use super::BackupRepository;
use super::filesystem::{CreateUpload, FilesystemBackupRepository, VerifyReport};
use crate::session::{BackupMetadata, BackupRecord, UploadSession};
use async_trait::async_trait;
use backupsas_core::{BackupId, BackupManifest, ChunkInfo, CommitRecord, Result};
use std::path::{Path, PathBuf};

/// Protocol-facing repository facade. Delegates to `FilesystemBackupRepository`.
pub struct FsRepository {
    inner: FilesystemBackupRepository,
}

impl FsRepository {
    pub fn open(root: PathBuf, name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            inner: FilesystemBackupRepository::open(root, name)?,
        })
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn root(&self) -> &Path {
        self.inner.root()
    }

    pub fn inner(&self) -> &FilesystemBackupRepository {
        &self.inner
    }

    pub fn create_upload(&self, req: CreateUpload) -> Result<UploadSession> {
        self.inner.create_upload(req)
    }

    pub fn resume(&self, backup_id: &BackupId) -> Result<UploadSession> {
        self.inner.resume(backup_id)
    }

    pub fn store_manifest(&self, backup_id: &BackupId, bytes: &[u8]) -> Result<BackupManifest> {
        self.inner.store_manifest(backup_id, bytes)
    }

    pub fn write_chunk(
        &self,
        backup_id: &BackupId,
        sequence: u32,
        hash: &str,
        data: &[u8],
    ) -> Result<u32> {
        self.inner
            .write_chunk_protocol(backup_id, sequence, hash, data)
    }

    pub fn verify(&self, backup_id: &BackupId) -> Result<VerifyReport> {
        self.inner.verify_upload(backup_id)
    }

    pub fn commit(&self, backup_id: &BackupId) -> Result<PathBuf> {
        self.inner.commit(backup_id)
    }

    pub fn abort(&self, backup_id: &BackupId) -> Result<()> {
        self.inner.abort(backup_id)
    }

    pub fn status(&self, backup_id: &BackupId) -> Result<BackupRecord> {
        self.inner.status(backup_id)
    }

    pub fn list_sessions(&self) -> Result<Vec<UploadSession>> {
        self.inner.list_sessions()
    }

    pub fn list_complete(&self) -> Result<Vec<(PathBuf, BackupMetadata)>> {
        self.inner.list_complete()
    }

    pub fn read_complete_backup(
        &self,
        backup_id: &BackupId,
        client_id: backupsas_core::ClientId,
    ) -> Result<(BackupManifest, CommitRecord)> {
        self.inner.read_complete_backup(backup_id, client_id)
    }

    pub fn read_complete_chunk(
        &self,
        backup_id: &BackupId,
        client_id: backupsas_core::ClientId,
        sequence: u32,
    ) -> Result<Vec<u8>> {
        self.inner
            .read_complete_chunk(backup_id, client_id, sequence)
    }
}

#[async_trait]
impl BackupRepository for FsRepository {
    async fn create(&self, manifest: &BackupManifest) -> Result<BackupId> {
        BackupRepository::create(&self.inner, manifest).await
    }

    async fn write_chunk(
        &self,
        backup_id: &BackupId,
        chunk: &ChunkInfo,
        data: &[u8],
    ) -> Result<()> {
        BackupRepository::write_chunk(&self.inner, backup_id, chunk, data).await
    }

    async fn finalize(&self, backup_id: &BackupId, commit: &CommitRecord) -> Result<()> {
        BackupRepository::finalize(&self.inner, backup_id, commit).await
    }

    async fn inspect(&self, backup_id: &BackupId) -> Result<super::BackupInfo> {
        BackupRepository::inspect(&self.inner, backup_id).await
    }

    async fn verify(&self, backup_id: &BackupId) -> Result<super::VerificationResult> {
        BackupRepository::verify(&self.inner, backup_id).await
    }

    async fn delete(&self, backup_id: &BackupId) -> Result<()> {
        BackupRepository::delete(&self.inner, backup_id).await
    }
}
