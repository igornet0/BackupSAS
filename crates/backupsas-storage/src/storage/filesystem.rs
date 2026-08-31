use super::BackupStorage;
use crate::paths;
use async_trait::async_trait;
use backupsas_core::{BackupSasError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FilesystemStorage {
    root: PathBuf,
}

impl FilesystemStorage {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn object_path(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }

    pub fn write_object_sync(&self, key: &str, data: &[u8]) -> Result<()> {
        paths::atomic_write(&self.object_path(key), data)?;
        Ok(())
    }

    pub fn read_object_sync(&self, key: &str) -> Result<Vec<u8>> {
        std::fs::read(self.object_path(key)).map_err(Into::into)
    }

    pub fn delete_object_sync(&self, key: &str) -> Result<()> {
        let path = self.object_path(key);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_prefix_sync(&self, prefix: &str) -> Result<Vec<String>> {
        let base = self.object_path(prefix);
        if !base.exists() {
            return Ok(Vec::new());
        }
        let root = self.root.clone();
        let mut keys = Vec::new();
        collect_keys(&base, &root, &mut keys)?;
        keys.sort();
        Ok(keys)
    }
}

#[async_trait]
impl BackupStorage for FilesystemStorage {
    async fn write_object(&self, key: &str, data: &[u8]) -> Result<()> {
        self.write_object_sync(key, data)
    }

    async fn read_object(&self, key: &str) -> Result<Vec<u8>> {
        self.read_object_sync(key)
    }

    async fn delete_object(&self, key: &str) -> Result<()> {
        self.delete_object_sync(key)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_prefix_sync(prefix)
    }
}

fn collect_keys(current: &Path, root: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = std::fs::read_dir(current)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_keys(&path, root, out)?;
        } else if path.is_file() {
            let rel = path.strip_prefix(root).map_err(|e| BackupSasError::Path {
                path: path.clone(),
                message: e.to_string(),
            })?;
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn write_read_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = FilesystemStorage::new(dir.path().to_path_buf());
        storage
            .write_object("nested/obj.txt", b"hello")
            .await
            .unwrap();
        let data = storage.read_object("nested/obj.txt").await.unwrap();
        assert_eq!(data, b"hello");
        let keys = storage.list_prefix("nested/").await.unwrap();
        assert_eq!(keys, vec!["nested/obj.txt"]);
        storage.delete_object("nested/obj.txt").await.unwrap();
        assert!(storage.read_object("nested/obj.txt").await.is_err());
    }
}
