//! Signed relocation notices produced by outgoing transfers.
//!
//! Stored as one JSON file per notice under `relocations/`. Always read from
//! disk so the CLI (`backupsas transfer`) and the running daemon share state.
//!
//! State machine per notice: `pending` → (owner ack) `acked` → (local copies
//! of a `move` deleted) `cleaned`. Every step is persisted before the next one
//! starts; [`RelocationStore::finish_cleanups`] completes `acked` notices after
//! a crash/restart.

use backupsas_core::{BackupId, BackupSasError, ClientId, RelocationNotice, Result, TransferMode};
use backupsas_storage::StorageRoot;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelocationRecord {
    pub notice: RelocationNotice,
    #[serde(default)]
    pub acked: bool,
    #[serde(default)]
    pub acked_at: Option<u64>,
    /// Local copies handled after the ack (deleted for `move`).
    #[serde(default)]
    pub cleaned: bool,
}

#[derive(Debug, Clone)]
pub struct RelocationStore {
    dir: PathBuf,
}

impl RelocationStore {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join("relocations");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(BackupSasError::InvalidId(id.to_string()));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    pub fn insert(&self, notice: RelocationNotice) -> Result<()> {
        let path = self.path(&notice.relocation_id)?;
        let record = RelocationRecord {
            notice,
            acked: false,
            acked_at: None,
            cleaned: false,
        };
        backupsas_storage::paths::atomic_write(&path, &serde_json::to_vec_pretty(&record)?)?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<RelocationRecord>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let record: RelocationRecord = serde_json::from_slice(&fs::read(&path)?)?;
            out.push(record);
        }
        out.sort_by_key(|r| r.notice.created_at);
        Ok(out)
    }

    pub fn pending_for(&self, client: &ClientId) -> Result<Vec<RelocationNotice>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|r| !r.acked && r.notice.owner_client_id == *client)
            .map(|r| r.notice)
            .collect())
    }

    fn write(&self, record: &RelocationRecord) -> Result<()> {
        let path = self.path(&record.notice.relocation_id)?;
        backupsas_storage::paths::atomic_write(&path, &serde_json::to_vec_pretty(record)?)?;
        Ok(())
    }

    /// Ack by the owner, then delete moved copies. Idempotent: acking an
    /// already acked/cleaned notice succeeds and resumes unfinished cleanup.
    pub fn ack_and_clean(
        &self,
        id: &str,
        client: &ClientId,
        storage: &StorageRoot,
    ) -> Result<RelocationRecord> {
        let mut record = self.ack(id, client)?;
        if !record.cleaned {
            crate::transfer::finalize_move(storage, &record.notice)?;
            record.cleaned = true;
            self.write(&record)?;
        }
        Ok(record)
    }

    /// Complete cleanup of notices acked before a crash. Returns their ids.
    pub fn finish_cleanups(&self, storage: &StorageRoot) -> Result<Vec<String>> {
        let mut done = Vec::new();
        for mut record in self.list()? {
            if record.acked && !record.cleaned {
                crate::transfer::finalize_move(storage, &record.notice)?;
                record.cleaned = true;
                self.write(&record)?;
                done.push(record.notice.relocation_id);
            }
        }
        Ok(done)
    }

    /// Mark a notice as acknowledged by its owner and return it.
    pub fn ack(&self, id: &str, client: &ClientId) -> Result<RelocationRecord> {
        let path = self.path(id)?;
        let mut record: RelocationRecord = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|_| BackupSasError::Other(format!("unknown relocation {id}")))?,
        )?;
        if record.notice.owner_client_id != *client {
            return Err(BackupSasError::Auth(
                "relocation belongs to another client".into(),
            ));
        }
        if !record.acked {
            record.acked = true;
            record.acked_at = Some(backupsas_core::crypto::timestamp_now());
            backupsas_storage::paths::atomic_write(&path, &serde_json::to_vec_pretty(&record)?)?;
        }
        Ok(record)
    }

    /// `true` when a backup was moved away and its local copy only awaits the
    /// owner's ack (or post-ack cleanup).
    pub fn is_moved_away(&self, backup_id: &BackupId) -> Result<bool> {
        Ok(self.list()?.iter().any(|r| {
            !r.cleaned
                && r.notice.mode == TransferMode::Move
                && r.notice.backup_ids.contains(backup_id)
        }))
    }
}
