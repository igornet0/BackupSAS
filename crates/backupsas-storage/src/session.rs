use backupsas_core::{BackupId, BackupState, ClientId, DatabaseId, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSession {
    pub backup_id: BackupId,
    pub database_id: DatabaseId,
    pub client_id: ClientId,
    pub repository: String,
    pub state: BackupState,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub total_size: u64,
    pub chunk_size: u64,
    pub chunk_count: u32,
    pub next_sequence: u32,
    pub has_manifest: bool,
    pub verified: bool,
    /// Last time the session was written (manifest, chunk, verify…). Older
    /// session files lack it; `created_at` is used instead.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub last_activity: Option<OffsetDateTime>,
}

impl UploadSession {
    pub fn last_activity_or_created(&self) -> OffsetDateTime {
        self.last_activity.unwrap_or(self.created_at)
    }

    pub fn last_verified_chunk(&self) -> u32 {
        self.next_sequence.saturating_sub(1)
    }

    pub fn require_state(&self, expected: BackupState) -> Result<()> {
        if self.state != expected {
            return Err(backupsas_core::BackupSasError::InvalidState {
                id: self.backup_id.to_string(),
                actual: self.state,
                expected,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub backup_id: BackupId,
    pub database_id: DatabaseId,
    pub client_id: ClientId,
    pub repository: String,
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub committed_at: OffsetDateTime,
    pub state: BackupState,
    pub chunk_count: u32,
    pub total_size: u64,
}

#[derive(Debug, Clone)]
pub enum BackupRecord {
    Uploading(UploadSession),
    Complete {
        path: PathBuf,
        metadata: BackupMetadata,
    },
}
