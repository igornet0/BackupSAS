use super::filesystem::{CreateUpload, FilesystemBackupRepository};
use super::BackupRepository;
use backupsas_core::{
    hash_bytes, BackupId, BackupManifest, BackupSasError, BackupState, ChunkInfo, ClientId,
    CommitRecord, DatabaseId, DEFAULT_KEY_ID,
};
use time::OffsetDateTime;

fn temp_repo() -> (tempfile::TempDir, FilesystemBackupRepository) {
    let dir = tempfile::tempdir().unwrap();
    let repo = FilesystemBackupRepository::open(dir.path().to_path_buf(), "failure").unwrap();
    (dir, repo)
}

fn sample_manifest(backup_id: BackupId) -> (BackupManifest, Vec<Vec<u8>>, Vec<ChunkInfo>) {
    let mut chunks = Vec::new();
    let mut infos = Vec::new();
    for i in 0..3u32 {
        let data = vec![i as u8; 32];
        infos.push(ChunkInfo {
            sequence: i,
            size: data.len() as u64,
            hash: hash_bytes(&data),
        });
        chunks.push(data);
    }
    let manifest = BackupManifest::new(
        backup_id,
        DatabaseId::new(),
        32,
        96,
        infos.clone(),
        DEFAULT_KEY_ID,
    );
    (manifest, chunks, infos)
}

#[tokio::test]
async fn corrupt_chunk_fails_verify() {
    let (_dir, repo) = temp_repo();
    let backup_id = BackupId::new();
    let (manifest, chunks, infos) = sample_manifest(backup_id);
    repo.create(&manifest).await.unwrap();
    for (info, data) in infos.iter().zip(chunks.iter()) {
        repo.write_chunk(&backup_id, info, data).await.unwrap();
    }

    let corrupt_key = crate::keys::staging_chunk(&backup_id, 1);
    repo.storage()
        .write_object_sync(&corrupt_key, b"corrupted-bytes")
        .unwrap();

    let report = repo.verify(&backup_id).await.unwrap();
    assert!(!report.valid);
    assert!(report.mismatches.iter().any(|(seq, _, _)| *seq == 1));

    let info = repo.inspect(&backup_id).await.unwrap();
    assert_ne!(info.state, BackupState::Complete);
    assert!(!repo.root().join(".state").join(backup_id.to_string()).join("commit.json").exists());
}

#[tokio::test]
async fn finalize_refuses_without_all_chunks() {
    let (_dir, repo) = temp_repo();
    let backup_id = BackupId::new();
    let (manifest, chunks, infos) = sample_manifest(backup_id);
    repo.create(&manifest).await.unwrap();
    repo.write_chunk(&backup_id, &infos[0], &chunks[0])
        .await
        .unwrap();

    let commit = CommitRecord::new(
        backup_id,
        manifest.root_hash.clone(),
        manifest.manifest_hash.clone(),
        OffsetDateTime::now_utc(),
    );
    assert!(repo.finalize(&backup_id, &commit).await.is_err());
    let info = repo.inspect(&backup_id).await.unwrap();
    assert_ne!(info.state, BackupState::Complete);
    assert!(!repo.root().join(".state").join(backup_id.to_string()).join("commit.json").exists());
}

#[tokio::test]
async fn commit_without_verify_fails_protocol_path() {
    let (_dir, repo) = temp_repo();
    let backup_id = BackupId::new();
    let database_id = DatabaseId::new();
    let (manifest, chunks, _infos) = sample_manifest(backup_id);
    repo.create_upload(CreateUpload {
        backup_id,
        database_id,
        client_id: ClientId::new(),
        total_size: 96,
        chunk_size: 32,
        chunk_count: 3,
    })
    .unwrap();
    repo.store_manifest(&backup_id, &manifest.to_vec().unwrap())
        .unwrap();
    for (i, chunk) in chunks.iter().enumerate() {
        repo.write_chunk_protocol(&backup_id, i as u32, &hash_bytes(chunk), chunk)
            .unwrap();
    }

    let err = repo.commit(&backup_id).unwrap_err();
    assert!(matches!(
        err,
        BackupSasError::InvalidState {
            expected: BackupState::Verifying,
            ..
        }
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn disk_full_leaves_upload_incomplete() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, repo) = temp_repo();
    let backup_id = BackupId::new();
    let (manifest, chunks, infos) = sample_manifest(backup_id);
    repo.create(&manifest).await.unwrap();
    repo.write_chunk(&backup_id, &infos[0], &chunks[0])
        .await
        .unwrap();

    let chunks_dir = dir
        .path()
        .join(".state")
        .join(backup_id.to_string())
        .join("chunks");
    let mut perms = std::fs::metadata(&chunks_dir).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&chunks_dir, perms).unwrap();

    let err = repo
        .write_chunk(&backup_id, &infos[1], &chunks[1])
        .await
        .unwrap_err();
    assert!(matches!(err, BackupSasError::Io(_)));

    let info = repo.inspect(&backup_id).await.unwrap();
    assert_eq!(info.state, BackupState::Uploading);
    assert_eq!(info.chunks_received, 1);
    assert!(!dir
        .path()
        .join(".state")
        .join(backup_id.to_string())
        .join("commit.json")
        .exists());
}

#[tokio::test]
async fn delete_removes_incomplete_backup() {
    let (_dir, repo) = temp_repo();
    let backup_id = BackupId::new();
    let (manifest, chunks, infos) = sample_manifest(backup_id);
    repo.create(&manifest).await.unwrap();
    repo.write_chunk(&backup_id, &infos[0], &chunks[0])
        .await
        .unwrap();
    repo.delete(&backup_id).await.unwrap();
    assert!(repo.inspect(&backup_id).await.is_err());
}
