//! Catalog, retention, relocation and node-transfer operations on an
//! authenticated session.

use crate::authentication::AuthenticatedSession;
use backupsas_core::{
    BackupManifest, BackupSasError, RelocationNotice, RemoteBackupInfo, Result, TransferMode,
};
use backupsas_protocol::Message;

/// Parameters for pushing an already-encrypted backup to another node.
#[derive(Debug, Clone)]
pub struct TransferOffer {
    pub transfer_id: String,
    pub mode: TransferMode,
    pub repository: String,
    pub owner_client_id: String,
    pub owner_public_key: Vec<u8>,
}

impl AuthenticatedSession {
    pub async fn list_backups(&mut self, repository: &str) -> Result<Vec<RemoteBackupInfo>> {
        self.conn
            .send(&Message::ListBackups {
                session_id: self.session_id.to_string(),
                repository: repository.to_string(),
            })
            .await?;
        match self.conn.recv().await? {
            Message::BackupList { items } => Ok(items),
            other => Err(unexpected(other)),
        }
    }

    pub async fn delete_backup(&mut self, backup_id: &str) -> Result<()> {
        self.conn
            .send(&Message::DeleteBackup {
                session_id: self.session_id.to_string(),
                backup_id: backup_id.to_string(),
            })
            .await?;
        match self.conn.recv().await? {
            Message::Deleted { .. } => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Fetch relocation notices addressed to this client. Notices are
    /// returned unverified; check each with the pinned source key.
    pub async fn pending_relocations(&mut self) -> Result<Vec<RelocationNotice>> {
        self.conn
            .send(&Message::PendingRelocations {
                session_id: self.session_id.to_string(),
            })
            .await?;
        match self.conn.recv().await? {
            Message::Relocations { notices } => Ok(notices),
            other => Err(unexpected(other)),
        }
    }

    pub async fn ack_relocation(&mut self, relocation_id: &str) -> Result<()> {
        self.conn
            .send(&Message::AckRelocation {
                session_id: self.session_id.to_string(),
                relocation_id: relocation_id.to_string(),
            })
            .await?;
        match self.conn.recv().await? {
            Message::RelocationAcked { .. } => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    /// Push ciphertext chunks of an existing backup (node-to-node transfer).
    ///
    /// `read_chunk(seq)` returns the stored ciphertext for that sequence.
    /// Resumes automatically if the target already holds a prefix.
    pub async fn push_encrypted<F>(
        &mut self,
        offer: &TransferOffer,
        manifest_bytes: &[u8],
        mut read_chunk: F,
    ) -> Result<()>
    where
        F: FnMut(u32) -> Result<Vec<u8>>,
    {
        let manifest = BackupManifest::from_slice(manifest_bytes)?;
        let backup_id = manifest.backup_id.to_string();
        let sid = self.session_id.to_string();
        self.conn
            .send(&Message::TransferOffer {
                session_id: sid.clone(),
                transfer_id: offer.transfer_id.clone(),
                mode: offer.mode.as_str().to_string(),
                repository: offer.repository.clone(),
                backup_id: backup_id.clone(),
                database_id: manifest.database_id.to_string(),
                owner_client_id: offer.owner_client_id.clone(),
                owner_public_key: offer.owner_public_key.clone(),
                total_size: manifest.total_size,
                chunk_size: manifest.chunk_size,
                chunk_count: manifest.chunk_count(),
                manifest_hash: manifest.manifest_hash.clone(),
            })
            .await?;
        let (resume_from, has_manifest) = match self.conn.recv().await? {
            Message::Created {
                resume_from,
                has_manifest,
                ..
            } => (resume_from, has_manifest),
            // Identical copy already committed on the target (retry after crash).
            Message::Committed { .. } => return Ok(()),
            other => return Err(unexpected(other)),
        };

        if !has_manifest {
            self.conn
                .send(&Message::Manifest {
                    session_id: sid.clone(),
                    backup_id: backup_id.clone(),
                    bytes: manifest_bytes.to_vec(),
                })
                .await?;
            match self.conn.recv().await? {
                Message::ManifestAck { .. } => {}
                other => return Err(unexpected(other)),
            }
        }

        for info in manifest.chunks.iter().filter(|c| c.sequence >= resume_from) {
            let payload = read_chunk(info.sequence)?;
            self.conn
                .send(&Message::Chunk {
                    session_id: sid.clone(),
                    backup_id: backup_id.clone(),
                    sequence: info.sequence,
                    hash: info.hash.clone(),
                    payload,
                })
                .await?;
            match self.conn.recv().await? {
                Message::ChunkAck { sequence } if sequence == info.sequence => {}
                other => return Err(unexpected(other)),
            }
        }

        self.conn
            .send(&Message::Verify {
                session_id: sid.clone(),
                backup_id: backup_id.clone(),
            })
            .await?;
        match self.conn.recv().await? {
            Message::VerifyOk { .. } => {}
            Message::VerifyFail { mismatches, .. } => {
                return Err(BackupSasError::InvalidManifest(format!(
                    "transfer verify failed: {mismatches:?}"
                )));
            }
            other => return Err(unexpected(other)),
        }
        self.conn
            .send(&Message::Commit {
                session_id: sid,
                backup_id,
            })
            .await?;
        match self.conn.recv().await? {
            Message::Committed { .. } => Ok(()),
            other => Err(unexpected(other)),
        }
    }

    pub async fn close(mut self) -> Result<()> {
        self.conn
            .send(&Message::SessionClose {
                session_id: self.session_id.to_string(),
            })
            .await
    }
}

fn unexpected(msg: Message) -> BackupSasError {
    match msg {
        Message::Error { reason } => BackupSasError::Protocol(reason),
        other => BackupSasError::Protocol(format!("unexpected {}", other.type_name())),
    }
}
