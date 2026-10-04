use crate::paths;
use crate::repository::FsRepository;
use crate::session::BackupRecord;
use backupsas_core::{BackupId, BackupSasError, RepositoryConfig, Result, ServerConfig};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct StorageRoot {
    data_dir: PathBuf,
    repos: HashMap<String, FsRepository>,
}

impl StorageRoot {
    pub fn open(config: &ServerConfig) -> Result<Self> {
        Self::open_at(&config.data_dir, &config.repositories)
    }

    pub fn open_at(data_dir: &Path, repos: &[RepositoryConfig]) -> Result<Self> {
        let mut map = HashMap::new();
        for repo in repos {
            let root = paths::repo_root(data_dir, &repo.name);
            map.insert(
                repo.name.clone(),
                FsRepository::open(root, repo.name.clone())?,
            );
        }
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            repos: map,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn repo(&self, name: &str) -> Result<&FsRepository> {
        self.repos
            .get(name)
            .ok_or_else(|| BackupSasError::RepositoryNotFound(name.to_string()))
    }

    pub fn find_backup(&self, id: &BackupId) -> Result<(&FsRepository, BackupRecord)> {
        for repo in self.repos.values() {
            if let Ok(record) = repo.status(id) {
                return Ok((repo, record));
            }
        }
        Err(BackupSasError::BackupNotFound(id.to_string()))
    }

    /// Remove incomplete uploads idle longer than `max_idle` in every repository.
    pub fn cleanup_stale_uploads(
        &self,
        max_idle: std::time::Duration,
    ) -> Result<Vec<(String, BackupId)>> {
        let mut out = Vec::new();
        for (name, repo) in &self.repos {
            for id in repo.cleanup_stale_uploads(max_idle)? {
                out.push((name.clone(), id));
            }
        }
        Ok(out)
    }

    pub fn list_all(&self) -> Result<Vec<(String, BackupRecord)>> {
        let mut out = Vec::new();
        for (name, repo) in &self.repos {
            for session in repo.list_sessions()? {
                out.push((name.clone(), BackupRecord::Uploading(session)));
            }
            for (path, metadata) in repo.list_complete()? {
                out.push((name.clone(), BackupRecord::Complete { path, metadata }));
            }
        }
        Ok(out)
    }
}
