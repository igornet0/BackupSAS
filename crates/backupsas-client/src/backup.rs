use crate::authentication::AuthenticatedSession;
use crate::chunker::{Chunk, chunk_reader};
use crate::encryptor::{Aes256GcmEncryptor, EncryptedChunk};
use crate::source::BackupSource;
use backupsas_core::{
    BackupId, BackupManifest, BackupSasConfig, BackupSasError, ChunkInfo, DEFAULT_KEY_ID,
    DatabaseId, Result,
};
use backupsas_protocol::Message;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct UploadOutcome {
    pub backup_id: BackupId,
    pub path: String,
    pub chunks_sent: u32,
}

pub struct UploadHandle<'a> {
    session: &'a mut AuthenticatedSession,
    repository: String,
    pub manifest: BackupManifest,
    chunks: Vec<EncryptedChunk>,
    resume_from: u32,
    has_manifest: bool,
}

impl<'a> UploadHandle<'a> {
    pub async fn upload(&mut self) -> Result<u32> {
        self.upload_n(u32::MAX).await
    }

    pub async fn upload_partial(&mut self, stop_after: u32) -> Result<u32> {
        self.upload_n(stop_after).await
    }

    async fn upload_n(&mut self, stop_after: u32) -> Result<u32> {
        if !self.has_manifest {
            self.session
                .conn
                .send(&Message::Manifest {
                    session_id: self.session.session_id.to_string(),
                    backup_id: self.manifest.backup_id.to_string(),
                    bytes: self.manifest.to_vec()?,
                })
                .await?;
            expect(&mut self.session.conn, |m| {
                matches!(m, Message::ManifestAck { .. })
            })
            .await?;
            self.has_manifest = true;
        }

        let mut sent = 0u32;
        let start = self.resume_from;
        for i in 0..self.chunks.len() {
            let (sequence, hash, payload) = {
                let chunk = &self.chunks[i];
                if chunk.sequence < start {
                    continue;
                }
                (chunk.sequence, chunk.hash.clone(), chunk.payload.clone())
            };
            self.session
                .conn
                .send(&Message::Chunk {
                    session_id: self.session.session_id.to_string(),
                    backup_id: self.manifest.backup_id.to_string(),
                    sequence,
                    hash,
                    payload,
                })
                .await?;
            match self.session.conn.recv().await? {
                Message::ChunkAck { sequence: ack } if ack == sequence => {}
                Message::Error { reason } => return Err(BackupSasError::Protocol(reason)),
                other => {
                    return Err(BackupSasError::Protocol(format!(
                        "unexpected {}",
                        other.type_name()
                    )));
                }
            }
            self.resume_from = sequence + 1;
            sent += 1;
            if sent >= stop_after {
                return Ok(sent);
            }
        }
        Ok(sent)
    }

    pub async fn verify(&mut self) -> Result<()> {
        self.session
            .conn
            .send(&Message::Verify {
                session_id: self.session.session_id.to_string(),
                backup_id: self.manifest.backup_id.to_string(),
            })
            .await?;
        match self.session.conn.recv().await? {
            Message::VerifyOk { .. } => Ok(()),
            Message::VerifyFail { mismatches, .. } => Err(BackupSasError::InvalidManifest(
                format!("verify failed: {mismatches:?}"),
            )),
            Message::Error { reason } => Err(BackupSasError::Protocol(reason)),
            other => Err(BackupSasError::Protocol(format!(
                "unexpected {}",
                other.type_name()
            ))),
        }
    }

    pub async fn commit(&mut self) -> Result<UploadOutcome> {
        self.verify().await?;
        self.session
            .conn
            .send(&Message::Commit {
                session_id: self.session.session_id.to_string(),
                backup_id: self.manifest.backup_id.to_string(),
            })
            .await?;
        match self.session.conn.recv().await? {
            Message::Committed { path, .. } => Ok(UploadOutcome {
                backup_id: self.manifest.backup_id,
                path,
                chunks_sent: self.resume_from,
            }),
            Message::Error { reason } => Err(BackupSasError::Protocol(reason)),
            other => Err(BackupSasError::Protocol(format!(
                "unexpected {}",
                other.type_name()
            ))),
        }
    }
}

impl AuthenticatedSession {
    pub async fn create_backup<R: Read>(
        &mut self,
        config: &BackupSasConfig,
        database_id: DatabaseId,
        reader: R,
    ) -> Result<UploadHandle<'_>> {
        let chunks = chunk_reader(reader, config.chunk_size as usize)?;
        self.create_backup_from_chunks(config, database_id, chunks)
            .await
    }

    pub async fn create_backup_from_source(
        &mut self,
        config: &BackupSasConfig,
        database_id: DatabaseId,
        source: &mut dyn BackupSource,
    ) -> Result<UploadHandle<'_>> {
        let total = source.total_size();
        let chunk_size = config.chunk_size as usize;
        let mut chunks = Vec::new();
        let mut offset = 0u64;
        let mut sequence = 0u32;
        while offset < total {
            let remaining = (total - offset) as usize;
            let len = remaining.min(chunk_size);
            let plaintext = source.read_range(offset, len)?;
            chunks.push(Chunk {
                sequence,
                plaintext,
            });
            offset += len as u64;
            sequence += 1;
        }
        self.create_backup_from_chunks(config, database_id, chunks)
            .await
    }

    async fn create_backup_from_chunks(
        &mut self,
        config: &BackupSasConfig,
        database_id: DatabaseId,
        chunks: Vec<Chunk>,
    ) -> Result<UploadHandle<'_>> {
        let encryptor = Aes256GcmEncryptor::new(*config.backup_encryption_key.as_bytes());
        let encrypted = encryptor.encrypt_chunks(&chunks)?;
        let chunk_infos: Vec<ChunkInfo> = encrypted
            .iter()
            .map(|c| ChunkInfo {
                sequence: c.sequence,
                size: c.payload.len() as u64,
                hash: c.hash.clone(),
            })
            .collect();
        let total_size: u64 = chunks.iter().map(|c| c.plaintext.len() as u64).sum();
        let manifest = BackupManifest::new(
            BackupId::new(),
            database_id,
            config.chunk_size,
            total_size,
            chunk_infos,
            DEFAULT_KEY_ID,
        );
        self.open_upload(config, database_id, manifest, encrypted, false)
            .await
    }

    pub async fn resume_backup(
        &mut self,
        config: &BackupSasConfig,
        database_id: DatabaseId,
        manifest: BackupManifest,
        chunks: Vec<EncryptedChunk>,
    ) -> Result<UploadHandle<'_>> {
        self.open_upload(config, database_id, manifest, chunks, true)
            .await
    }

    async fn open_upload(
        &mut self,
        config: &BackupSasConfig,
        database_id: DatabaseId,
        manifest: BackupManifest,
        chunks: Vec<EncryptedChunk>,
        use_resume: bool,
    ) -> Result<UploadHandle<'_>> {
        let (resume_from, has_manifest) = if use_resume {
            self.conn
                .send(&Message::Resume {
                    session_id: self.session_id.to_string(),
                    backup_id: manifest.backup_id.to_string(),
                })
                .await?;
            match self.conn.recv().await? {
                Message::ResumeAck {
                    next_sequence,
                    has_manifest,
                    ..
                } => (next_sequence, has_manifest),
                Message::Error { reason } => return Err(BackupSasError::Protocol(reason)),
                other => {
                    return Err(BackupSasError::Protocol(format!(
                        "unexpected {}",
                        other.type_name()
                    )));
                }
            }
        } else {
            self.conn
                .send(&Message::Create {
                    session_id: self.session_id.to_string(),
                    backup_id: manifest.backup_id.to_string(),
                    database_id: database_id.to_string(),
                    repository: config.repository.clone(),
                    total_size: manifest.total_size,
                    chunk_size: manifest.chunk_size,
                    chunk_count: manifest.chunk_count(),
                })
                .await?;
            match self.conn.recv().await? {
                Message::Created {
                    resume_from,
                    has_manifest,
                    ..
                } => (resume_from, has_manifest),
                Message::Error { reason } => return Err(BackupSasError::Protocol(reason)),
                other => {
                    return Err(BackupSasError::Protocol(format!(
                        "unexpected {}",
                        other.type_name()
                    )));
                }
            }
        };

        Ok(UploadHandle {
            session: self,
            repository: config.repository.clone(),
            manifest,
            chunks,
            resume_from,
            has_manifest,
        })
    }
}

async fn expect<F>(conn: &mut crate::connection::Connection, pred: F) -> Result<Message>
where
    F: FnOnce(&Message) -> bool,
{
    let msg = conn.recv().await?;
    if let Message::Error { reason } = &msg {
        return Err(BackupSasError::Protocol(reason.clone()));
    }
    if pred(&msg) {
        Ok(msg)
    } else {
        Err(BackupSasError::Protocol(format!(
            "unexpected {}",
            msg.type_name()
        )))
    }
}

impl UploadHandle<'_> {
    pub fn chunks(&self) -> &[EncryptedChunk] {
        &self.chunks
    }

    pub fn repository(&self) -> &str {
        &self.repository
    }
}
