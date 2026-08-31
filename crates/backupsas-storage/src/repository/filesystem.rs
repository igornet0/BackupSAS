use crate::keys;
use crate::paths;
use crate::repository::{BackupInfo, BackupRepository, VerificationResult};
use crate::session::{BackupMetadata, BackupRecord, UploadSession};
use crate::storage::FilesystemStorage;
use async_trait::async_trait;
use backupsas_core::{
    BackupId, BackupManifest, BackupSasError, BackupState, ChunkInfo, ClientId, CommitRecord,
    DatabaseId, Result, VerifyResult, hash_bytes, verify_backup_dir,
};
use fd_lock::RwLock;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;

pub struct CreateUpload {
    pub backup_id: BackupId,
    pub database_id: DatabaseId,
    pub client_id: ClientId,
    pub total_size: u64,
    pub chunk_size: u64,
    pub chunk_count: u32,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub ok: bool,
    pub mismatches: Vec<(u32, String, String)>,
}

/// Filesystem-backed backup repository. Owns backup semantics; delegates blobs to `BackupStorage`.
pub struct FilesystemBackupRepository {
    pub name: String,
    storage: Arc<FilesystemStorage>,
}

impl FilesystemBackupRepository {
    pub fn open(root: PathBuf, name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        fs::create_dir_all(paths::state_dir(&root))?;
        fs::create_dir_all(paths::index_dir(&root))?;
        fs::create_dir_all(root.join("backups"))?;
        Ok(Self {
            name,
            storage: Arc::new(FilesystemStorage::new(root)),
        })
    }

    pub fn root(&self) -> &Path {
        self.storage.root()
    }

    pub fn storage(&self) -> Arc<FilesystemStorage> {
        Arc::clone(&self.storage)
    }

    // --- Protocol-facing sync API (unchanged behavior) ---

    pub fn create_upload(&self, req: CreateUpload) -> Result<UploadSession> {
        let mut held = self.lock(&req.backup_id)?;
        let _guard = held.write()?;
        if let Some(session) = self.load_session(&req.backup_id)? {
            match session.state {
                BackupState::Creating | BackupState::Uploading | BackupState::Verifying => {
                    return Ok(session);
                }
                BackupState::Complete => {
                    return Err(BackupSasError::AlreadyComplete(req.backup_id.to_string()));
                }
                BackupState::Aborted => {
                    self.remove_staging(&req.backup_id)?;
                }
            }
        }
        if self.index_path(&req.backup_id).is_some() {
            return Err(BackupSasError::AlreadyComplete(req.backup_id.to_string()));
        }

        let session = UploadSession {
            backup_id: req.backup_id,
            database_id: req.database_id,
            client_id: req.client_id,
            repository: self.name.clone(),
            state: BackupState::Creating,
            created_at: OffsetDateTime::now_utc(),
            total_size: req.total_size,
            chunk_size: req.chunk_size,
            chunk_count: req.chunk_count,
            next_sequence: 0,
            has_manifest: false,
            verified: false,
        };
        fs::create_dir_all(paths::staging_chunks(self.root(), &session.backup_id))?;
        self.save_session(&session)?;
        Ok(session)
    }

    pub fn resume(&self, backup_id: &BackupId) -> Result<UploadSession> {
        let mut held = self.lock(backup_id)?;
        let _guard = held.write()?;
        let session = self
            .load_session(backup_id)?
            .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
        match session.state {
            BackupState::Creating | BackupState::Uploading | BackupState::Verifying => Ok(session),
            BackupState::Complete => Err(BackupSasError::AlreadyComplete(backup_id.to_string())),
            BackupState::Aborted => Err(BackupSasError::InvalidState {
                id: backup_id.to_string(),
                actual: BackupState::Aborted,
                expected: BackupState::Uploading,
            }),
        }
    }

    pub fn store_manifest(&self, backup_id: &BackupId, bytes: &[u8]) -> Result<BackupManifest> {
        let mut held = self.lock(backup_id)?;
        let _guard = held.write()?;
        let mut session = self.require_open(backup_id)?;
        let manifest = BackupManifest::from_slice(bytes)?;
        if manifest.backup_id != *backup_id {
            return Err(BackupSasError::InvalidManifest(
                "manifest backup_id does not match session".into(),
            ));
        }
        if manifest.chunk_count() != session.chunk_count {
            return Err(BackupSasError::InvalidManifest(format!(
                "manifest chunks {} != session {}",
                manifest.chunk_count(),
                session.chunk_count
            )));
        }
        self.storage_write_blocking(&keys::staging_manifest(backup_id), bytes)?;
        session.has_manifest = true;
        session.state = BackupState::Uploading;
        session.verified = false;
        self.save_session(&session)?;
        Ok(manifest)
    }

    pub fn write_chunk_protocol(
        &self,
        backup_id: &BackupId,
        sequence: u32,
        hash: &str,
        data: &[u8],
    ) -> Result<u32> {
        let mut held = self.lock(backup_id)?;
        let _guard = held.write()?;
        let mut session = self.require_uploading(backup_id)?;
        if sequence != session.next_sequence {
            return Err(BackupSasError::ChunkSequence {
                expected: session.next_sequence,
                got: sequence,
            });
        }
        let actual = hash_bytes(data);
        if actual != hash {
            return Err(BackupSasError::ChunkHashMismatch {
                seq: sequence,
                expected: hash.to_string(),
                actual,
            });
        }
        self.storage_write_blocking(&keys::staging_chunk(backup_id, sequence), data)?;
        session.next_sequence += 1;
        session.verified = false;
        self.save_session(&session)?;
        Ok(session.next_sequence)
    }

    pub fn verify_upload(&self, backup_id: &BackupId) -> Result<VerifyReport> {
        let report = self.verify_staging(backup_id)?;
        Ok(report.into())
    }

    pub fn commit(&self, backup_id: &BackupId) -> Result<PathBuf> {
        let (session, commit) = {
            let mut held = self.lock(backup_id)?;
            let _guard = held.write()?;
            let session = self
                .load_session(backup_id)?
                .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
            if !session.verified {
                return Err(BackupSasError::InvalidState {
                    id: backup_id.to_string(),
                    actual: session.state,
                    expected: BackupState::Verifying,
                });
            }

            let manifest_bytes = self.storage_read_blocking(&keys::staging_manifest(backup_id))?;
            let manifest = BackupManifest::from_slice(&manifest_bytes)?;
            let now = OffsetDateTime::now_utc();
            let commit = CommitRecord::new(
                session.backup_id,
                manifest.root_hash.clone(),
                manifest.manifest_hash.clone(),
                now,
            );
            (session, commit)
        };
        self.finalize_sync(backup_id, &commit, &session)
    }

    pub fn abort(&self, backup_id: &BackupId) -> Result<()> {
        let mut held = self.lock(backup_id)?;
        let _guard = held.write()?;
        if let Some(mut session) = self.load_session(backup_id)? {
            if session.state == BackupState::Complete {
                return Err(BackupSasError::AlreadyComplete(backup_id.to_string()));
            }
            session.state = BackupState::Aborted;
            self.save_session(&session)?;
        }
        self.remove_staging(backup_id)?;
        let _ = fs::remove_file(paths::session_json(self.root(), backup_id));
        Ok(())
    }

    pub fn status(&self, backup_id: &BackupId) -> Result<BackupRecord> {
        if let Some(session) = self.load_session(backup_id)? {
            return Ok(BackupRecord::Uploading(session));
        }
        if let Some(path) = self.index_path(backup_id) {
            let meta_path = path.join("metadata.json");
            let bytes = fs::read(&meta_path)?;
            let meta: BackupMetadata = serde_json::from_slice(&bytes)?;
            return Ok(BackupRecord::Complete {
                path,
                metadata: meta,
            });
        }
        Err(BackupSasError::BackupNotFound(backup_id.to_string()))
    }

    pub fn list_sessions(&self) -> Result<Vec<UploadSession>> {
        let dir = paths::state_dir(self.root());
        let mut out = Vec::new();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".json") {
                let bytes = fs::read(entry.path())?;
                if let Ok(session) = serde_json::from_slice::<UploadSession>(&bytes) {
                    out.push(session);
                }
            }
        }
        Ok(out)
    }

    pub fn list_complete(&self) -> Result<Vec<(PathBuf, BackupMetadata)>> {
        let index = paths::index_dir(self.root());
        let mut out = Vec::new();
        let entries = match fs::read_dir(&index) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let rel = fs::read_to_string(entry.path())?;
            let path = self.root().join(rel.trim());
            let meta_path = path.join("metadata.json");
            if let Ok(bytes) = fs::read(&meta_path)
                && let Ok(meta) = serde_json::from_slice::<BackupMetadata>(&bytes)
            {
                out.push((path, meta));
            }
        }
        Ok(out)
    }

    /// Load trusted manifest + commit for a complete backup. Checks client ownership via metadata.
    pub fn read_complete_backup(
        &self,
        backup_id: &BackupId,
        client_id: ClientId,
    ) -> Result<(BackupManifest, CommitRecord)> {
        let backup_dir = self
            .index_path(backup_id)
            .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
        let commit_path = paths::backup_commit(&backup_dir);
        if !commit_path.exists() {
            return Err(BackupSasError::InvalidState {
                id: backup_id.to_string(),
                actual: BackupState::Uploading,
                expected: BackupState::Complete,
            });
        }
        let meta_path = backup_dir.join("metadata.json");
        if meta_path.exists() {
            let meta: BackupMetadata = serde_json::from_slice(&fs::read(&meta_path)?)?;
            if meta.client_id != client_id {
                return Err(BackupSasError::Auth(
                    "client not authorized for this backup".into(),
                ));
            }
        }
        let manifest = BackupManifest::from_slice(&fs::read(backup_dir.join("manifest.json"))?)?;
        let commit = CommitRecord::from_slice(&fs::read(&commit_path)?)?;
        if manifest.backup_id != *backup_id {
            return Err(BackupSasError::InvalidManifest(
                "manifest backup_id mismatch".into(),
            ));
        }
        commit.verify_against_manifest(&manifest)?;
        Ok((manifest, commit))
    }

    /// Read one ciphertext chunk from a complete backup (authorized by client_id).
    pub fn read_complete_chunk(
        &self,
        backup_id: &BackupId,
        client_id: ClientId,
        sequence: u32,
    ) -> Result<Vec<u8>> {
        let backup_dir = self
            .index_path(backup_id)
            .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
        if !paths::backup_commit(&backup_dir).exists() {
            return Err(BackupSasError::InvalidState {
                id: backup_id.to_string(),
                actual: BackupState::Uploading,
                expected: BackupState::Complete,
            });
        }
        let meta_path = backup_dir.join("metadata.json");
        if meta_path.exists() {
            let meta: BackupMetadata = serde_json::from_slice(&fs::read(&meta_path)?)?;
            if meta.client_id != client_id {
                return Err(BackupSasError::Auth(
                    "client not authorized for this backup".into(),
                ));
            }
        }
        let manifest = BackupManifest::from_slice(&fs::read(backup_dir.join("manifest.json"))?)?;
        if sequence >= manifest.chunk_count() {
            return Err(BackupSasError::ChunkSequence {
                expected: sequence,
                got: manifest.chunk_count(),
            });
        }
        let chunk_path = backup_dir.join("chunks").join(paths::chunk_name(sequence));
        fs::read(&chunk_path).map_err(Into::into)
    }

    // --- BackupRepository implementation (sync core) ---

    fn create_sync(&self, manifest: &BackupManifest) -> Result<BackupId> {
        manifest.validate()?;
        let backup_id = manifest.backup_id;
        let mut held = self.lock(&backup_id)?;
        let _guard = held.write()?;
        if self.load_session(&backup_id)?.is_some() || self.index_path(&backup_id).is_some() {
            return Err(BackupSasError::AlreadyComplete(backup_id.to_string()));
        }

        let session = UploadSession {
            backup_id,
            database_id: manifest.database_id,
            client_id: ClientId::new(),
            repository: self.name.clone(),
            state: BackupState::Uploading,
            created_at: OffsetDateTime::now_utc(),
            total_size: manifest.total_size,
            chunk_size: manifest.chunk_size,
            chunk_count: manifest.chunk_count(),
            next_sequence: 0,
            has_manifest: true,
            verified: false,
        };
        fs::create_dir_all(paths::staging_chunks(self.root(), &backup_id))?;
        let manifest_bytes = manifest.to_vec()?;
        self.storage_write_blocking(&keys::staging_manifest(&backup_id), &manifest_bytes)?;
        self.save_session(&session)?;
        Ok(backup_id)
    }

    fn write_chunk_sync(&self, backup_id: &BackupId, chunk: &ChunkInfo, data: &[u8]) -> Result<()> {
        self.write_chunk_protocol(backup_id, chunk.sequence, &chunk.hash, data)?;
        Ok(())
    }

    fn verify_staging(&self, backup_id: &BackupId) -> Result<VerificationResult> {
        let mut held = self.lock(backup_id)?;
        let _guard = held.write()?;
        let mut session = self
            .load_session(backup_id)?
            .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
        if session.state == BackupState::Complete {
            return Err(BackupSasError::AlreadyComplete(backup_id.to_string()));
        }
        if session.state == BackupState::Aborted {
            return Err(BackupSasError::InvalidState {
                id: backup_id.to_string(),
                actual: session.state,
                expected: BackupState::Uploading,
            });
        }
        if !session.has_manifest {
            return Err(BackupSasError::InvalidManifest(
                "manifest not uploaded".into(),
            ));
        }

        session.state = BackupState::Verifying;
        self.save_session(&session)?;

        let manifest_bytes = self.storage_read_blocking(&keys::staging_manifest(backup_id))?;
        let manifest = BackupManifest::from_slice(&manifest_bytes)?;
        let mut mismatches = Vec::new();

        if session.next_sequence != manifest.chunk_count() {
            return Ok(VerificationResult {
                valid: false,
                mismatches: vec![(
                    session.next_sequence,
                    format!("expected {} chunks", manifest.chunk_count()),
                    format!("received {}", session.next_sequence),
                )],
            });
        }

        for chunk in &manifest.chunks {
            let data =
                self.storage_read_blocking(&keys::staging_chunk(backup_id, chunk.sequence))?;
            let actual = hash_bytes(&data);
            if actual != chunk.hash {
                mismatches.push((chunk.sequence, chunk.hash.clone(), actual));
            }
        }

        if mismatches.is_empty() {
            session.verified = true;
            session.state = BackupState::Verifying;
            self.save_session(&session)?;
            Ok(VerificationResult {
                valid: true,
                mismatches,
            })
        } else {
            session.verified = false;
            session.state = BackupState::Uploading;
            self.save_session(&session)?;
            Ok(VerificationResult {
                valid: false,
                mismatches,
            })
        }
    }

    fn finalize_sync(
        &self,
        backup_id: &BackupId,
        commit: &CommitRecord,
        session: &UploadSession,
    ) -> Result<PathBuf> {
        let report = self.verify_staging(backup_id)?;
        if !report.valid {
            return Err(BackupSasError::InvalidManifest(format!(
                "finalize refused: verify failed: {:?}",
                report.mismatches
            )));
        }

        let manifest_bytes = self.storage_read_blocking(&keys::staging_manifest(backup_id))?;
        let manifest = BackupManifest::from_slice(&manifest_bytes)?;
        if commit.backup_id != manifest.backup_id {
            return Err(BackupSasError::InvalidManifest(
                "commit backup_id mismatch".into(),
            ));
        }
        if commit.root_hash != manifest.root_hash {
            return Err(BackupSasError::InvalidManifest(
                "commit root_hash mismatch".into(),
            ));
        }
        if commit.manifest_hash != manifest.manifest_hash {
            return Err(BackupSasError::InvalidManifest(
                "commit manifest_hash mismatch".into(),
            ));
        }

        let dest = paths::dated_backup_dir(self.root(), session.created_at, backup_id);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let staging = paths::staging_dir(self.root(), backup_id);
        if dest.exists() {
            return Err(BackupSasError::AlreadyComplete(backup_id.to_string()));
        }
        fs::rename(&staging, &dest)?;

        let commit_bytes = commit.to_vec_pretty()?;
        paths::atomic_write(&paths::backup_commit(&dest), &commit_bytes)?;

        let metadata = BackupMetadata {
            backup_id: session.backup_id,
            database_id: session.database_id,
            client_id: session.client_id,
            repository: session.repository.clone(),
            received_at: session.created_at,
            committed_at: commit.committed_at,
            state: BackupState::Complete,
            chunk_count: session.chunk_count,
            total_size: session.total_size,
        };
        let meta_bytes = serde_json::to_vec_pretty(&metadata)?;
        paths::atomic_write(&dest.join("metadata.json"), &meta_bytes)?;

        let rel = dest
            .strip_prefix(self.root())
            .unwrap_or(&dest)
            .to_string_lossy()
            .into_owned();
        self.storage_write_blocking(&keys::index_entry(backup_id), rel.as_bytes())?;

        let session_path = paths::session_json(self.root(), backup_id);
        let _ = fs::remove_file(session_path);
        let _ = fs::remove_file(paths::session_lock(self.root(), backup_id));

        Ok(dest)
    }

    fn inspect_sync(&self, backup_id: &BackupId) -> Result<BackupInfo> {
        if let Some(session) = self.load_session(backup_id)? {
            let manifest = if session.has_manifest {
                let bytes = self.storage_read_blocking(&keys::staging_manifest(backup_id))?;
                Some(BackupManifest::from_slice(&bytes)?)
            } else {
                None
            };
            return Ok(BackupInfo {
                backup_id: session.backup_id,
                state: session.state,
                manifest,
                path: None,
                chunks_received: session.next_sequence,
                chunk_count: session.chunk_count,
            });
        }
        if let Some(path) = self.index_path(backup_id) {
            let manifest_bytes = fs::read(path.join("manifest.json"))?;
            let manifest = BackupManifest::from_slice(&manifest_bytes)?;
            return Ok(BackupInfo {
                backup_id: manifest.backup_id,
                state: BackupState::Complete,
                manifest: Some(manifest.clone()),
                path: Some(path),
                chunks_received: manifest.chunk_count(),
                chunk_count: manifest.chunk_count(),
            });
        }
        Err(BackupSasError::BackupNotFound(backup_id.to_string()))
    }

    fn verify_complete(&self, backup_dir: &Path) -> VerificationResult {
        let result: VerifyResult = verify_backup_dir(backup_dir);
        VerificationResult {
            valid: result.valid,
            mismatches: result
                .failures
                .iter()
                .map(|f| (0, f.to_string(), String::new()))
                .collect(),
        }
    }

    fn delete_sync(&self, backup_id: &BackupId) -> Result<()> {
        if self.load_session(backup_id)?.is_some() {
            self.remove_staging(backup_id)?;
            let _ = fs::remove_file(paths::session_json(self.root(), backup_id));
            let _ = fs::remove_file(paths::session_lock(self.root(), backup_id));
            return Ok(());
        }
        if let Some(path) = self.index_path(backup_id) {
            if path.exists() {
                fs::remove_dir_all(&path)?;
            }
            self.storage_delete_blocking(&keys::index_entry(backup_id))?;
            return Ok(());
        }
        Err(BackupSasError::BackupNotFound(backup_id.to_string()))
    }

    // --- helpers ---

    fn storage_write_blocking(&self, key: &str, data: &[u8]) -> Result<()> {
        self.storage.write_object_sync(key, data)
    }

    fn storage_read_blocking(&self, key: &str) -> Result<Vec<u8>> {
        self.storage.read_object_sync(key)
    }

    fn storage_delete_blocking(&self, key: &str) -> Result<()> {
        self.storage.delete_object_sync(key)
    }

    fn require_open(&self, backup_id: &BackupId) -> Result<UploadSession> {
        let session = self
            .load_session(backup_id)?
            .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
        match session.state {
            BackupState::Creating | BackupState::Uploading | BackupState::Verifying => Ok(session),
            BackupState::Complete => Err(BackupSasError::AlreadyComplete(backup_id.to_string())),
            BackupState::Aborted => Err(BackupSasError::InvalidState {
                id: backup_id.to_string(),
                actual: BackupState::Aborted,
                expected: BackupState::Uploading,
            }),
        }
    }

    fn require_uploading(&self, backup_id: &BackupId) -> Result<UploadSession> {
        let session = self.require_open(backup_id)?;
        let mut session = session;
        if session.state == BackupState::Creating {
            return Err(BackupSasError::InvalidState {
                id: backup_id.to_string(),
                actual: BackupState::Creating,
                expected: BackupState::Uploading,
            });
        }
        if session.state == BackupState::Verifying {
            session.state = BackupState::Uploading;
            session.verified = false;
        }
        Ok(session)
    }

    fn load_session(&self, backup_id: &BackupId) -> Result<Option<UploadSession>> {
        let path = paths::session_json(self.root(), backup_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        Ok(Some(serde_json::from_slice(&bytes)?))
    }

    fn save_session(&self, session: &UploadSession) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(session)?;
        paths::atomic_write(
            &paths::session_json(self.root(), &session.backup_id),
            &bytes,
        )?;
        Ok(())
    }

    fn remove_staging(&self, backup_id: &BackupId) -> Result<()> {
        let staging = paths::staging_dir(self.root(), backup_id);
        if staging.exists() {
            fs::remove_dir_all(&staging)?;
        }
        Ok(())
    }

    fn index_path(&self, backup_id: &BackupId) -> Option<PathBuf> {
        let index = paths::index_file(self.root(), backup_id);
        let rel = fs::read_to_string(index).ok()?;
        Some(self.root().join(rel.trim()))
    }

    fn lock(&self, backup_id: &BackupId) -> Result<HeldLock> {
        fs::create_dir_all(paths::state_dir(self.root()))?;
        let path = paths::session_lock(self.root(), backup_id);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        Ok(HeldLock {
            lock: RwLock::new(file),
        })
    }
}

struct HeldLock {
    lock: RwLock<File>,
}

impl HeldLock {
    fn write(&mut self) -> Result<fd_lock::RwLockWriteGuard<'_, File>> {
        self.lock
            .write()
            .map_err(|e| BackupSasError::Other(format!("failed to lock session: {e}")))
    }
}

#[async_trait]
impl BackupRepository for FilesystemBackupRepository {
    async fn create(&self, manifest: &BackupManifest) -> Result<BackupId> {
        self.create_sync(manifest)
    }

    async fn write_chunk(
        &self,
        backup_id: &BackupId,
        chunk: &ChunkInfo,
        data: &[u8],
    ) -> Result<()> {
        self.write_chunk_sync(backup_id, chunk, data)
    }

    async fn finalize(&self, backup_id: &BackupId, commit: &CommitRecord) -> Result<()> {
        let session = self
            .load_session(backup_id)?
            .ok_or_else(|| BackupSasError::BackupNotFound(backup_id.to_string()))?;
        self.finalize_sync(backup_id, commit, &session)?;
        Ok(())
    }

    async fn inspect(&self, backup_id: &BackupId) -> Result<BackupInfo> {
        self.inspect_sync(backup_id)
    }

    async fn verify(&self, backup_id: &BackupId) -> Result<VerificationResult> {
        if let Some(path) = self.index_path(backup_id) {
            return Ok(self.verify_complete(&path));
        }
        self.verify_staging(backup_id)
    }

    async fn delete(&self, backup_id: &BackupId) -> Result<()> {
        self.delete_sync(backup_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backupsas_core::DEFAULT_KEY_ID;

    fn temp_repo() -> (tempfile::TempDir, FilesystemBackupRepository) {
        let dir = tempfile::tempdir().unwrap();
        let repo =
            FilesystemBackupRepository::open(dir.path().to_path_buf(), "avrora-prod").unwrap();
        (dir, repo)
    }

    fn make_chunks(n: u32, size: usize) -> (Vec<Vec<u8>>, Vec<ChunkInfo>, u64) {
        let mut chunks = Vec::new();
        let mut infos = Vec::new();
        for i in 0..n {
            let data = vec![i as u8; size];
            let hash = hash_bytes(&data);
            infos.push(ChunkInfo {
                sequence: i,
                size: data.len() as u64,
                hash,
            });
            chunks.push(data);
        }
        let total = (n as u64) * (size as u64);
        (chunks, infos, total)
    }

    #[test]
    fn write_verify_commit() {
        let (_tmp, repo) = temp_repo();
        let backup_id = BackupId::new();
        let database_id = DatabaseId::new();
        let (chunks, chunk_infos, total) = make_chunks(3, 32);

        repo.create_upload(CreateUpload {
            backup_id,
            database_id,
            client_id: ClientId::new(),
            total_size: total,
            chunk_size: 32,
            chunk_count: 3,
        })
        .unwrap();

        let manifest = BackupManifest::new(
            backup_id,
            database_id,
            32,
            total,
            chunk_infos,
            DEFAULT_KEY_ID,
        );
        repo.store_manifest(&backup_id, &manifest.to_vec().unwrap())
            .unwrap();

        for (i, chunk) in chunks.iter().enumerate() {
            repo.write_chunk_protocol(&backup_id, i as u32, &hash_bytes(chunk), chunk)
                .unwrap();
        }

        let report = repo.verify_upload(&backup_id).unwrap();
        assert!(report.ok);

        let dest = repo.commit(&backup_id).unwrap();
        assert!(dest.join("manifest.json").exists());
        assert!(dest.join("commit.json").exists());
        assert!(dest.join("chunks").join("000000").exists());
        assert!(dest.join("chunks").join("000002").exists());

        match repo.status(&backup_id).unwrap() {
            BackupRecord::Complete { metadata, .. } => {
                assert_eq!(metadata.state, BackupState::Complete);
            }
            other => panic!("expected complete, got {other:?}"),
        }
    }

    #[test]
    fn resume_after_partial_write() {
        let (_tmp, repo) = temp_repo();
        let backup_id = BackupId::new();
        let (chunks, chunk_infos, total) = make_chunks(3, 16);
        repo.create_upload(CreateUpload {
            backup_id,
            database_id: DatabaseId::new(),
            client_id: ClientId::new(),
            total_size: total,
            chunk_size: 16,
            chunk_count: 3,
        })
        .unwrap();
        let hash0 = chunk_infos[0].hash.clone();
        let manifest = BackupManifest::new(
            backup_id,
            DatabaseId::new(),
            16,
            total,
            chunk_infos,
            DEFAULT_KEY_ID,
        );
        repo.store_manifest(&backup_id, &manifest.to_vec().unwrap())
            .unwrap();
        repo.write_chunk_protocol(&backup_id, 0, &hash0, &chunks[0])
            .unwrap();

        let session = repo.resume(&backup_id).unwrap();
        assert_eq!(session.next_sequence, 1);
        assert_eq!(session.last_verified_chunk(), 0);
    }

    #[test]
    fn reject_out_of_order_chunk() {
        let (_tmp, repo) = temp_repo();
        let backup_id = BackupId::new();
        repo.create_upload(CreateUpload {
            backup_id,
            database_id: DatabaseId::new(),
            client_id: ClientId::new(),
            total_size: 16,
            chunk_size: 16,
            chunk_count: 2,
        })
        .unwrap();
        let manifest = BackupManifest::new(
            backup_id,
            DatabaseId::new(),
            16,
            16,
            vec![
                ChunkInfo {
                    sequence: 0,
                    size: 16,
                    hash: hash_bytes(b"chunk0"),
                },
                ChunkInfo {
                    sequence: 1,
                    size: 16,
                    hash: hash_bytes(b"chunk1"),
                },
            ],
            DEFAULT_KEY_ID,
        );
        repo.store_manifest(&backup_id, &manifest.to_vec().unwrap())
            .unwrap();
        let err = repo
            .write_chunk_protocol(&backup_id, 1, "blake3:x", b"hello")
            .unwrap_err();
        assert!(matches!(
            err,
            BackupSasError::ChunkSequence {
                expected: 0,
                got: 1
            }
        ));
    }
}
