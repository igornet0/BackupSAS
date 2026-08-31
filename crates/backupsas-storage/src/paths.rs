use backupsas_core::BackupId;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub fn repo_root(data_dir: &Path, name: &str) -> PathBuf {
    data_dir.join("repositories").join(name)
}

pub fn state_dir(repo: &Path) -> PathBuf {
    repo.join(".state")
}

pub fn index_dir(repo: &Path) -> PathBuf {
    repo.join(".index")
}

pub fn session_json(repo: &Path, id: &BackupId) -> PathBuf {
    state_dir(repo).join(format!("{id}.json"))
}

pub fn session_lock(repo: &Path, id: &BackupId) -> PathBuf {
    state_dir(repo).join(format!("{id}.lock"))
}

pub fn staging_dir(repo: &Path, id: &BackupId) -> PathBuf {
    state_dir(repo).join(id.to_string())
}

pub fn staging_chunks(repo: &Path, id: &BackupId) -> PathBuf {
    staging_dir(repo, id).join("chunks")
}

pub fn staging_manifest(repo: &Path, id: &BackupId) -> PathBuf {
    staging_dir(repo, id).join("manifest.json")
}

pub fn staging_commit(repo: &Path, id: &BackupId) -> PathBuf {
    staging_dir(repo, id).join("commit.json")
}

pub fn backup_commit(backup_dir: &Path) -> PathBuf {
    backup_dir.join("commit.json")
}

pub fn chunk_name(seq: u32) -> String {
    format!("{seq:06}")
}

pub fn chunk_path(dir: &Path, seq: u32) -> PathBuf {
    dir.join(chunk_name(seq))
}

pub fn dated_backup_dir(repo: &Path, created_at: OffsetDateTime, id: &BackupId) -> PathBuf {
    repo.join("backups")
        .join(format!("{:04}", created_at.year()))
        .join(format!("{:02}", created_at.month() as u8))
        .join(format!("{:02}", created_at.day()))
        .join(format!("backup-{id}"))
}

pub fn index_file(repo: &Path, id: &BackupId) -> PathBuf {
    index_dir(repo).join(id.to_string())
}

pub fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
