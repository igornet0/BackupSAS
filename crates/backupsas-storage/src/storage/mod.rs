mod filesystem;

pub use filesystem::FilesystemStorage;

use backupsas_core::Result;
use async_trait::async_trait;

/// Low-level object storage. No backup semantics.
#[async_trait]
pub trait BackupStorage: Send + Sync {
    async fn write_object(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn read_object(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete_object(&self, key: &str) -> Result<()>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>>;
}
