use crate::authentication::AuthenticatedSession;
use crate::encryptor::Aes256GcmEncryptor;
use crate::target::{RestoreMetadata, RestoreTarget};
use backupsas_core::{
    BackupId, BackupManifest, BackupSasConfig, BackupSasError, CommitRecord, Result, hash_bytes,
    verify_hash,
};
use backupsas_protocol::Message;

/// Authorized restore view of a complete backup (trusted manifest + commit only).
pub struct BackupHandle<'a> {
    session: &'a mut AuthenticatedSession,
    pub backup_id: BackupId,
    pub manifest: BackupManifest,
    pub commit: CommitRecord,
}

impl AuthenticatedSession {
    pub async fn open_backup(&mut self, backup_id: BackupId) -> Result<BackupHandle<'_>> {
        if !self.info.is_active() {
            return Err(BackupSasError::Session("session expired".into()));
        }
        self.conn
            .send(&Message::OpenBackup {
                session_id: self.session_id.to_string(),
                backup_id: backup_id.to_string(),
            })
            .await?;
        match self.conn.recv().await? {
            Message::OpenBackupOk {
                backup_id: id,
                manifest_bytes,
                commit_bytes,
            } => {
                if id != backup_id.to_string() {
                    return Err(BackupSasError::Protocol(
                        "open_backup backup_id mismatch".into(),
                    ));
                }
                let manifest = BackupManifest::from_slice(&manifest_bytes)?;
                let commit = CommitRecord::from_slice(&commit_bytes)?;
                if manifest.backup_id != backup_id {
                    return Err(BackupSasError::InvalidManifest(
                        "manifest backup_id mismatch".into(),
                    ));
                }
                manifest.validate()?;
                commit.verify_against_manifest(&manifest)?;
                Ok(BackupHandle {
                    session: self,
                    backup_id,
                    manifest,
                    commit,
                })
            }
            Message::Error { reason } => Err(BackupSasError::Protocol(reason)),
            other => Err(BackupSasError::Protocol(format!(
                "unexpected {}",
                other.type_name()
            ))),
        }
    }
}

impl BackupHandle<'_> {
    pub async fn read_chunk(&mut self, sequence: u32) -> Result<Vec<u8>> {
        if !self.session.info.is_active() {
            return Err(BackupSasError::Session("session expired".into()));
        }
        self.session
            .conn
            .send(&Message::ReadChunk {
                session_id: self.session.session_id.to_string(),
                backup_id: self.backup_id.to_string(),
                sequence,
            })
            .await?;
        match self.session.conn.recv().await? {
            Message::ReadChunkOk {
                backup_id,
                sequence: seq,
                payload,
            } => {
                if backup_id != self.backup_id.to_string() || seq != sequence {
                    return Err(BackupSasError::Protocol(
                        "read_chunk response mismatch".into(),
                    ));
                }
                Ok(payload)
            }
            Message::Error { reason } => Err(BackupSasError::Protocol(reason)),
            other => Err(BackupSasError::Protocol(format!(
                "unexpected {}",
                other.type_name()
            ))),
        }
    }

    pub async fn restore_to(
        &mut self,
        config: &BackupSasConfig,
        target: &mut dyn RestoreTarget,
    ) -> Result<()> {
        self.manifest.validate()?;
        self.commit.verify_against_manifest(&self.manifest)?;

        target.metadata(&RestoreMetadata {
            backup_id: Some(self.backup_id),
            database_id: Some(self.manifest.database_id),
            total_size: self.manifest.total_size,
            chunk_count: self.manifest.chunk_count(),
            label: None,
        })?;

        let encryptor = Aes256GcmEncryptor::new(*config.backup_encryption_key.as_bytes());
        let mut plaintext_offset = 0u64;
        let mut verified_hashes = Vec::with_capacity(self.manifest.chunks.len());
        let chunks: Vec<_> = self.manifest.chunks.clone();

        for chunk in &chunks {
            let ciphertext = self.read_chunk(chunk.sequence).await?;
            verify_chunk_hash(chunk.sequence, &ciphertext, &chunk.hash)?;
            if ciphertext.len() as u64 != chunk.size {
                return Err(BackupSasError::ChunkHashMismatch {
                    seq: chunk.sequence,
                    expected: chunk.hash.clone(),
                    actual: hash_bytes(&ciphertext),
                });
            }
            let plaintext = encryptor.decrypt(&ciphertext)?;
            target.write_range(plaintext_offset, &plaintext)?;
            plaintext_offset += plaintext.len() as u64;
            verified_hashes.push(chunk.hash.clone());
        }

        self.manifest.verify_root_hash()?;
        if verified_hashes != self.manifest.chunk_hashes() {
            return Err(BackupSasError::InvalidManifest(
                "chunk hash list mismatch after restore".into(),
            ));
        }

        target.finalize()?;
        Ok(())
    }
}

fn verify_chunk_hash(sequence: u32, data: &[u8], expected: &str) -> Result<()> {
    match verify_hash(data, expected) {
        Ok(()) => Ok(()),
        Err(BackupSasError::ChunkHashMismatch {
            expected, actual, ..
        }) => Err(BackupSasError::ChunkHashMismatch {
            seq: sequence,
            expected,
            actual,
        }),
        Err(e) => Err(e),
    }
}
