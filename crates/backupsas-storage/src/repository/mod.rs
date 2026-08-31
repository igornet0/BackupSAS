mod filesystem;
mod legacy;

#[cfg(test)]
mod contract;
#[cfg(test)]
mod failure;

pub use filesystem::{CreateUpload, FilesystemBackupRepository, VerifyReport};
pub use legacy::FsRepository;

use backupsas_core::{
    BackupId, BackupManifest, ChunkInfo, CommitRecord, Result,
};
use async_trait::async_trait;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub backup_id: BackupId,
    pub state: backupsas_core::BackupState,
    pub manifest: Option<BackupManifest>,
    pub path: Option<PathBuf>,
    pub chunks_received: u32,
    pub chunk_count: u32,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub mismatches: Vec<(u32, String, String)>,
}

impl From<VerificationResult> for VerifyReport {
    fn from(v: VerificationResult) -> Self {
        Self {
            ok: v.valid,
            mismatches: v.mismatches,
        }
    }
}

/// Backup lifecycle, manifest, chunks, commit, and verification.
#[async_trait]
pub trait BackupRepository: Send + Sync {
    async fn create(&self, manifest: &BackupManifest) -> Result<BackupId>;
    async fn write_chunk(
        &self,
        backup_id: &BackupId,
        chunk: &ChunkInfo,
        data: &[u8],
    ) -> Result<()>;
    async fn finalize(&self, backup_id: &BackupId, commit: &CommitRecord) -> Result<()>;
    async fn inspect(&self, backup_id: &BackupId) -> Result<BackupInfo>;
    async fn verify(&self, backup_id: &BackupId) -> Result<VerificationResult>;
    async fn delete(&self, backup_id: &BackupId) -> Result<()>;
}

#[async_trait]
impl<T: BackupRepository + ?Sized> BackupRepository for std::sync::Arc<T> {
    async fn create(&self, manifest: &BackupManifest) -> Result<BackupId> {
        (**self).create(manifest).await
    }

    async fn write_chunk(
        &self,
        backup_id: &BackupId,
        chunk: &ChunkInfo,
        data: &[u8],
    ) -> Result<()> {
        (**self).write_chunk(backup_id, chunk, data).await
    }

    async fn finalize(&self, backup_id: &BackupId, commit: &CommitRecord) -> Result<()> {
        (**self).finalize(backup_id, commit).await
    }

    async fn inspect(&self, backup_id: &BackupId) -> Result<BackupInfo> {
        (**self).inspect(backup_id).await
    }

    async fn verify(&self, backup_id: &BackupId) -> Result<VerificationResult> {
        (**self).verify(backup_id).await
    }

    async fn delete(&self, backup_id: &BackupId) -> Result<()> {
        (**self).delete(backup_id).await
    }
}
