use backupsas_core::{BackupId, BackupSasError, DatabaseId, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Audit hints passed to a restore target before payload write.
///
/// Sourced from the trusted manifest during restore — not from untrusted `metadata.json`.
#[derive(Debug, Clone, Default)]
pub struct RestoreMetadata {
    pub backup_id: Option<BackupId>,
    pub database_id: Option<DatabaseId>,
    pub total_size: u64,
    pub chunk_count: u32,
    pub label: Option<String>,
}

/// Writable restore destination. Implementations must be `Send` for async client use.
pub trait RestoreTarget: Send {
    fn metadata(&mut self, metadata: &RestoreMetadata) -> Result<()>;
    fn write_range(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    /// Publish a fully verified restore (semantics depend on the target).
    fn finalize(&mut self) -> Result<()>;
    /// Discard partial restore state after failure; production targets must stay unchanged.
    fn abort(&mut self) -> Result<()> {
        Ok(())
    }
}

/// In-memory restore target for tests and SDK reference implementation.
#[derive(Debug, Clone)]
pub struct MemoryRestoreTarget {
    data: Vec<u8>,
    metadata: Option<RestoreMetadata>,
    finalized: bool,
}

impl MemoryRestoreTarget {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            metadata: None,
            finalized: false,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            metadata: None,
            finalized: false,
        }
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    pub fn restore_metadata(&self) -> Option<&RestoreMetadata> {
        self.metadata.as_ref()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl Default for MemoryRestoreTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl RestoreTarget for MemoryRestoreTarget {
    fn metadata(&mut self, metadata: &RestoreMetadata) -> Result<()> {
        self.metadata = Some(metadata.clone());
        if metadata.total_size > 0 {
            self.data.resize(metadata.total_size as usize, 0);
        }
        Ok(())
    }

    fn write_range(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let start = offset as usize;
        let end = start.saturating_add(data.len());
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        if let Some(meta) = &self.metadata
            && meta.total_size > 0
            && self.data.len() as u64 > meta.total_size
        {
            self.data.truncate(meta.total_size as usize);
        }
        self.finalized = true;
        Ok(())
    }
}

/// Atomic filesystem restore: writes to `{target}.restore-{backup_id}.tmp`, then renames on finalize.
pub struct FileRestoreTarget {
    target: PathBuf,
    temp: PathBuf,
    file: Option<File>,
    finalized: bool,
}

impl FileRestoreTarget {
    pub fn new(target: impl Into<PathBuf>, backup_id: BackupId) -> Result<Self> {
        let target = target.into();
        let temp = temp_path_for(&target, &backup_id);
        if temp.exists() {
            fs::remove_file(&temp).map_err(map_io)?;
        }
        Ok(Self {
            target,
            temp,
            file: None,
            finalized: false,
        })
    }

    pub fn target_path(&self) -> &Path {
        &self.target
    }

    pub fn temp_path(&self) -> &Path {
        &self.temp
    }

    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    fn cleanup_temp(&mut self) -> Result<()> {
        self.file.take();
        if self.temp.exists() {
            fs::remove_file(&self.temp).map_err(map_io)?;
        }
        Ok(())
    }
}

impl RestoreTarget for FileRestoreTarget {
    fn metadata(&mut self, metadata: &RestoreMetadata) -> Result<()> {
        if self.file.is_some() {
            return Err(BackupSasError::Other(
                "file restore target already initialized".into(),
            ));
        }
        if let Some(parent) = self.temp.parent() {
            fs::create_dir_all(parent).map_err(map_io)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.temp)
            .map_err(map_io)?;
        if metadata.total_size > 0 {
            file.set_len(metadata.total_size).map_err(map_io)?;
        }
        self.file = Some(file);
        Ok(())
    }

    fn write_range(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| BackupSasError::Other("restore temp file not open".into()))?;
        file.seek(SeekFrom::Start(offset)).map_err(map_io)?;
        file.write_all(data).map_err(map_io)?;
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        if self.finalized {
            return Err(BackupSasError::Other("restore already finalized".into()));
        }
        let file = self
            .file
            .take()
            .ok_or_else(|| BackupSasError::Other("restore temp file not open".into()))?;
        file.sync_all().map_err(map_io)?;
        drop(file);

        fs::rename(&self.temp, &self.target).map_err(map_io)?;
        sync_parent_dir(&self.target)?;
        self.finalized = true;
        Ok(())
    }

    fn abort(&mut self) -> Result<()> {
        if self.finalized {
            return Ok(());
        }
        self.cleanup_temp()
    }
}

impl Drop for FileRestoreTarget {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.cleanup_temp();
        }
    }
}

fn temp_path_for(target: &Path, backup_id: &BackupId) -> PathBuf {
    PathBuf::from(format!("{}.restore-{}.tmp", target.display(), backup_id))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if !parent.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let dir = File::open(parent).map_err(map_io)?;
        dir.sync_all().map_err(map_io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn map_io(err: std::io::Error) -> BackupSasError {
    BackupSasError::Io(err)
}

#[cfg(test)]
mod file_target_tests {
    use super::*;

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("backupsas-restore-{}", BackupId::new()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn temp_path_format() {
        let target = PathBuf::from("/data/database.db");
        let backup_id: BackupId = "bkp_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
        assert_eq!(
            temp_path_for(&target, &backup_id),
            PathBuf::from("/data/database.db.restore-bkp_01ARZ3NDEKTSV4RRFFQ69G5FAV.tmp")
        );
    }

    #[test]
    fn atomic_finalize_replaces_existing_target() {
        let dir = test_dir();
        let target = dir.join("database.db");
        fs::write(&target, b"old-production").unwrap();
        let backup_id = BackupId::new();

        let mut restore = FileRestoreTarget::new(&target, backup_id).unwrap();
        restore
            .metadata(&RestoreMetadata {
                total_size: 11,
                ..Default::default()
            })
            .unwrap();
        restore.write_range(0, b"hello-world").unwrap();
        restore.finalize().unwrap();

        assert!(restore.is_finalized());
        assert!(!restore.temp_path().exists());
        assert_eq!(fs::read(&target).unwrap(), b"hello-world");
    }

    #[test]
    fn abort_removes_temp_and_leaves_target_unchanged() {
        let dir = test_dir();
        let target = dir.join("database.db");
        fs::write(&target, b"original").unwrap();
        let backup_id = BackupId::new();

        let mut restore = FileRestoreTarget::new(&target, backup_id).unwrap();
        restore
            .metadata(&RestoreMetadata {
                total_size: 5,
                ..Default::default()
            })
            .unwrap();
        restore.write_range(0, b"parti").unwrap();
        restore.abort().unwrap();

        assert!(!restore.is_finalized());
        assert!(!restore.temp_path().exists());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn drop_before_finalize_cleans_up() {
        let dir = test_dir();
        let target = dir.join("database.db");
        fs::write(&target, b"original").unwrap();
        let backup_id = BackupId::new();
        let temp;

        {
            let mut restore = FileRestoreTarget::new(&target, backup_id).unwrap();
            temp = restore.temp_path().to_path_buf();
            restore
                .metadata(&RestoreMetadata {
                    total_size: 4,
                    ..Default::default()
                })
                .unwrap();
            restore.write_range(0, b"half").unwrap();
        }

        assert!(!temp.exists());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn partial_restore_abort_leaves_target_unchanged() {
        let dir = test_dir();
        let target = dir.join("database.db");
        fs::write(&target, b"original").unwrap();
        let backup_id = BackupId::new();

        let mut restore = FileRestoreTarget::new(&target, backup_id).unwrap();
        restore
            .metadata(&RestoreMetadata {
                total_size: 8,
                ..Default::default()
            })
            .unwrap();
        restore.write_range(0, b"1234").unwrap();
        restore.abort().unwrap();

        assert!(!restore.is_finalized());
        assert!(!restore.temp_path().exists());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }
}

#[cfg(test)]
mod memory_target_tests {
    use super::*;

    #[test]
    fn memory_target_writes_ranges() {
        let mut target = MemoryRestoreTarget::new();
        target
            .metadata(&RestoreMetadata {
                total_size: 11,
                ..Default::default()
            })
            .unwrap();
        target.write_range(0, b"hello").unwrap();
        target.write_range(5, b"-world").unwrap();
        target.finalize().unwrap();
        assert_eq!(target.bytes(), b"hello-world");
    }

    #[test]
    fn memory_target_extends_on_out_of_order_write() {
        let mut target = MemoryRestoreTarget::new();
        target.write_range(5, b"tail").unwrap();
        assert_eq!(target.bytes(), b"\0\0\0\0\0tail");
    }
}
