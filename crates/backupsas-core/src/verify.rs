use crate::error::BackupSasError;
use crate::format::CommitRecord;
use crate::hash::{hash_bytes, verify_hash};
use crate::manifest::BackupManifest;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyFailure {
    MissingManifest,
    MissingCommit,
    InvalidManifest(String),
    ChunkHashMismatch {
        sequence: u32,
        expected: String,
        actual: String,
    },
    RootMismatch {
        expected: String,
        actual: String,
    },
    ManifestHashMismatch {
        expected: String,
        actual: String,
    },
    CommitBackupIdMismatch,
    CommitRootMismatch {
        expected: String,
        actual: String,
    },
    CommitManifestHashMismatch {
        expected: String,
        actual: String,
    },
    IncompleteChunks {
        expected: u32,
        received: u32,
    },
}

impl fmt::Display for VerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingManifest => f.write_str("missing manifest.json"),
            Self::MissingCommit => f.write_str("missing commit.json"),
            Self::InvalidManifest(msg) => write!(f, "invalid manifest: {msg}"),
            Self::ChunkHashMismatch { sequence, .. } => {
                write!(f, "chunk hash mismatch at sequence {sequence}")
            }
            Self::RootMismatch { .. } => f.write_str("root_hash mismatch"),
            Self::ManifestHashMismatch { .. } => f.write_str("manifest_hash mismatch"),
            Self::CommitBackupIdMismatch => f.write_str("commit backup_id mismatch"),
            Self::CommitRootMismatch { .. } => f.write_str("commit root mismatch"),
            Self::CommitManifestHashMismatch { .. } => f.write_str("commit manifest_hash mismatch"),
            Self::IncompleteChunks { expected, received } => {
                write!(
                    f,
                    "incomplete chunks: expected {expected}, received {received}"
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid: bool,
    pub failures: Vec<VerifyFailure>,
}

impl VerifyResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            failures: Vec::new(),
        }
    }

    pub fn fail(failure: VerifyFailure) -> Self {
        Self {
            valid: false,
            failures: vec![failure],
        }
    }

    pub fn push(&mut self, failure: VerifyFailure) {
        self.valid = false;
        self.failures.push(failure);
    }
}

pub fn verify_backup_dir(backup_dir: &Path) -> VerifyResult {
    let manifest_path = backup_dir.join("manifest.json");
    let commit_path = backup_dir.join("commit.json");
    let chunks_dir = backup_dir.join("chunks");

    if !manifest_path.exists() {
        return VerifyResult::fail(VerifyFailure::MissingManifest);
    }

    let manifest_bytes = match std::fs::read(&manifest_path) {
        Ok(b) => b,
        Err(e) => {
            return VerifyResult::fail(VerifyFailure::InvalidManifest(e.to_string()));
        }
    };

    let manifest = match BackupManifest::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            return VerifyResult::fail(VerifyFailure::InvalidManifest(e.to_string()));
        }
    };

    let mut result = VerifyResult::ok();

    if let Err(e) = manifest.verify_manifest_hash() {
        result.push(VerifyFailure::ManifestHashMismatch {
            expected: manifest.compute_manifest_hash(),
            actual: manifest.manifest_hash.clone(),
        });
        let _ = e;
    }

    let recomputed_root = crate::merkle::merkle_root(&manifest.chunk_hashes());
    match recomputed_root {
        Ok(actual) if actual != manifest.root_hash => {
            result.push(VerifyFailure::RootMismatch {
                expected: manifest.root_hash.clone(),
                actual,
            });
        }
        Err(e) => result.push(VerifyFailure::InvalidManifest(e.to_string())),
        _ => {}
    }

    let chunk_count = manifest.chunk_count();
    for chunk in &manifest.chunks {
        let path = chunks_dir.join(format!("{:06}", chunk.sequence));
        if !path.exists() {
            result.push(VerifyFailure::IncompleteChunks {
                expected: chunk_count,
                received: chunk.sequence,
            });
            continue;
        }
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                result.push(VerifyFailure::InvalidManifest(e.to_string()));
                continue;
            }
        };
        if let Err(BackupSasError::ChunkHashMismatch {
            expected, actual, ..
        }) = verify_hash(&data, &chunk.hash)
        {
            result.push(VerifyFailure::ChunkHashMismatch {
                sequence: chunk.sequence,
                expected,
                actual,
            });
        }
        if data.len() as u64 != chunk.size {
            let actual = hash_bytes(&data);
            result.push(VerifyFailure::ChunkHashMismatch {
                sequence: chunk.sequence,
                expected: chunk.hash.clone(),
                actual,
            });
        }
    }

    if !commit_path.exists() {
        result.push(VerifyFailure::MissingCommit);
        return result;
    }

    let commit_bytes = match std::fs::read(&commit_path) {
        Ok(b) => b,
        Err(e) => {
            result.push(VerifyFailure::InvalidManifest(e.to_string()));
            return result;
        }
    };

    let commit = match CommitRecord::from_slice(&commit_bytes) {
        Ok(c) => c,
        Err(e) => {
            result.push(VerifyFailure::InvalidManifest(e.to_string()));
            return result;
        }
    };

    if commit.backup_id != manifest.backup_id {
        result.push(VerifyFailure::CommitBackupIdMismatch);
    }
    if commit.root_hash != manifest.root_hash {
        result.push(VerifyFailure::CommitRootMismatch {
            expected: manifest.root_hash.clone(),
            actual: commit.root_hash.clone(),
        });
    }
    if commit.manifest_hash != manifest.manifest_hash {
        result.push(VerifyFailure::CommitManifestHashMismatch {
            expected: manifest.manifest_hash.clone(),
            actual: commit.manifest_hash.clone(),
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{ChunkInfo, CommitRecord, DEFAULT_KEY_ID};
    use crate::hash::hash_bytes;
    use crate::id::{BackupId, DatabaseId};
    use crate::manifest::BackupManifest;
    use time::OffsetDateTime;

    fn write_complete_backup(dir: &Path) -> (BackupId, Vec<u8>, Vec<u8>) {
        let backup_id = BackupId::new();
        let mut chunks = Vec::new();
        let mut infos = Vec::new();
        for i in 0..2u32 {
            let data = vec![i as u8; 16];
            infos.push(ChunkInfo {
                sequence: i,
                size: data.len() as u64,
                hash: hash_bytes(&data),
            });
            chunks.push(data);
        }
        let manifest =
            BackupManifest::new(backup_id, DatabaseId::new(), 16, 32, infos, DEFAULT_KEY_ID);
        let manifest_bytes = manifest.to_vec().unwrap();
        std::fs::create_dir_all(dir.join("chunks")).unwrap();
        std::fs::write(dir.join("manifest.json"), &manifest_bytes).unwrap();
        for (i, chunk) in chunks.iter().enumerate() {
            std::fs::write(dir.join("chunks").join(format!("{i:06}")), chunk).unwrap();
        }
        let commit = CommitRecord::new(
            backup_id,
            manifest.root_hash.clone(),
            manifest.manifest_hash.clone(),
            OffsetDateTime::now_utc(),
        );
        std::fs::write(dir.join("commit.json"), commit.to_vec_pretty().unwrap()).unwrap();
        (backup_id, manifest_bytes, chunks[1].clone())
    }

    #[test]
    fn valid_complete_backup() {
        let dir = tempfile::tempdir().unwrap();
        write_complete_backup(dir.path());
        let result = verify_backup_dir(dir.path());
        assert!(result.valid, "failures: {:?}", result.failures);
    }

    #[test]
    fn corrupt_chunk_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        write_complete_backup(dir.path());
        std::fs::write(dir.path().join("chunks").join("000001"), b"bad").unwrap();
        let result = verify_backup_dir(dir.path());
        assert!(!result.valid);
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, VerifyFailure::ChunkHashMismatch { sequence: 1, .. }))
        );
    }

    #[test]
    fn bad_commit_root_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let (backup_id, _, _) = write_complete_backup(dir.path());
        let commit_path = dir.path().join("commit.json");
        let mut commit: CommitRecord =
            serde_json::from_slice(&std::fs::read(&commit_path).unwrap()).unwrap();
        commit.root_hash = "blake3:deadbeef".into();
        std::fs::write(&commit_path, commit.to_vec_pretty().unwrap()).unwrap();
        let _ = backup_id;
        let result = verify_backup_dir(dir.path());
        assert!(!result.valid);
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, VerifyFailure::CommitRootMismatch { .. }))
        );
    }

    #[test]
    fn missing_commit_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        write_complete_backup(dir.path());
        std::fs::remove_file(dir.path().join("commit.json")).unwrap();
        let result = verify_backup_dir(dir.path());
        assert!(!result.valid);
        assert!(
            result
                .failures
                .iter()
                .any(|f| matches!(f, VerifyFailure::MissingCommit))
        );
    }
}
