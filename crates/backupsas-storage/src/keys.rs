//! Object keys relative to repository root (forward-slash paths).
#![allow(dead_code)]

use backupsas_core::BackupId;
pub fn session_json(backup_id: &BackupId) -> String {
    format!(".state/{backup_id}.json")
}

pub fn session_lock(backup_id: &BackupId) -> String {
    format!(".state/{backup_id}.lock")
}

pub fn staging_prefix(backup_id: &BackupId) -> String {
    format!(".state/{backup_id}/")
}

pub fn staging_manifest(backup_id: &BackupId) -> String {
    format!(".state/{backup_id}/manifest.json")
}

pub fn staging_chunk(backup_id: &BackupId, sequence: u32) -> String {
    format!(".state/{backup_id}/chunks/{sequence:06}")
}

pub fn index_entry(backup_id: &BackupId) -> String {
    format!(".index/{backup_id}")
}

pub fn backup_manifest(rel_backup_dir: &str) -> String {
    format!("{rel_backup_dir}/manifest.json")
}

pub fn backup_commit(rel_backup_dir: &str) -> String {
    format!("{rel_backup_dir}/commit.json")
}

pub fn backup_metadata(rel_backup_dir: &str) -> String {
    format!("{rel_backup_dir}/metadata.json")
}

pub fn backup_chunk(rel_backup_dir: &str, sequence: u32) -> String {
    format!("{rel_backup_dir}/chunks/{sequence:06}")
}
