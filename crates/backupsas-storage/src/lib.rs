//! Filesystem-backed immutable backup repository.

mod keys;
pub mod paths;
mod repository;
mod root;
mod session;
mod storage;

pub use repository::{
    BackupInfo, BackupRepository, CreateUpload, FilesystemBackupRepository, FsRepository,
    VerificationResult, VerifyReport,
};
pub use root::StorageRoot;
pub use session::{BackupMetadata, BackupRecord, UploadSession};
pub use storage::{BackupStorage, FilesystemStorage};

/// Repository root path helper for operators and tests.
pub fn repo_root(data_dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    paths::repo_root(data_dir, name)
}
