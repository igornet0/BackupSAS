use super::filesystem::FilesystemBackupRepository;
use super::{BackupRepository};
use backupsas_core::{
    hash_bytes, BackupId, BackupManifest, BackupState, ChunkInfo, CommitRecord, DatabaseId,
    DEFAULT_KEY_ID,
};
use time::OffsetDateTime;

pub async fn repository_contract<R: BackupRepository>(repo: &R) {
    test_create(repo).await;
    test_write_chunks(repo).await;
    test_verify_before_finalize(repo).await;
    test_finalize(repo).await;
    test_inspect_complete(repo).await;
    test_verify_complete(repo).await;
    test_delete(repo).await;
}

struct ContractFixture {
    backup_id: BackupId,
    manifest: BackupManifest,
    chunks: Vec<Vec<u8>>,
    chunk_infos: Vec<ChunkInfo>,
}

fn build_fixture() -> ContractFixture {
    let backup_id = BackupId::new();
    let database_id = DatabaseId::new();
    let mut chunks = Vec::new();
    let mut chunk_infos = Vec::new();
    for i in 0..3u32 {
        let data = vec![i as u8; 32];
        let hash = hash_bytes(&data);
        chunk_infos.push(ChunkInfo {
            sequence: i,
            size: data.len() as u64,
            hash,
        });
        chunks.push(data);
    }
    let total = 96u64;
    let manifest = BackupManifest::new(backup_id, database_id, 32, total, chunk_infos.clone(), DEFAULT_KEY_ID);
    ContractFixture {
        backup_id,
        manifest,
        chunks,
        chunk_infos,
    }
}

async fn test_create<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    let id = repo.create(&fixture.manifest).await.unwrap();
    assert_eq!(id, fixture.backup_id);
    let info = repo.inspect(&id).await.unwrap();
    assert_eq!(info.state, BackupState::Uploading);
    assert!(info.manifest.is_some());
    assert_eq!(info.chunks_received, 0);
    assert_eq!(info.chunk_count, 3);
}

async fn test_write_chunks<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    for (chunk, data) in fixture.chunk_infos.iter().zip(fixture.chunks.iter()) {
        repo.write_chunk(&fixture.backup_id, chunk, data).await.unwrap();
    }
    let info = repo.inspect(&fixture.backup_id).await.unwrap();
    assert_eq!(info.chunks_received, 3);
}

async fn test_verify_before_finalize<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    for (chunk, data) in fixture.chunk_infos.iter().zip(fixture.chunks.iter()) {
        repo.write_chunk(&fixture.backup_id, chunk, data).await.unwrap();
    }
    let report = repo.verify(&fixture.backup_id).await.unwrap();
    assert!(report.valid, "expected valid verify before finalize");
}

async fn test_finalize<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    for (chunk, data) in fixture.chunk_infos.iter().zip(fixture.chunks.iter()) {
        repo.write_chunk(&fixture.backup_id, chunk, data).await.unwrap();
    }
    let commit = CommitRecord::new(
        fixture.backup_id,
        fixture.manifest.root_hash.clone(),
        fixture.manifest.manifest_hash.clone(),
        OffsetDateTime::now_utc(),
    );
    repo.finalize(&fixture.backup_id, &commit).await.unwrap();
    let info = repo.inspect(&fixture.backup_id).await.unwrap();
    assert_eq!(info.state, BackupState::Complete);
    assert!(info.path.is_some());
}

async fn test_inspect_complete<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    for (chunk, data) in fixture.chunk_infos.iter().zip(fixture.chunks.iter()) {
        repo.write_chunk(&fixture.backup_id, chunk, data).await.unwrap();
    }
    let commit = CommitRecord::new(
        fixture.backup_id,
        fixture.manifest.root_hash.clone(),
        fixture.manifest.manifest_hash.clone(),
        OffsetDateTime::now_utc(),
    );
    repo.finalize(&fixture.backup_id, &commit).await.unwrap();
    let info = repo.inspect(&fixture.backup_id).await.unwrap();
    assert_eq!(info.backup_id, fixture.backup_id);
    assert_eq!(info.state, BackupState::Complete);
}

async fn test_verify_complete<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    for (chunk, data) in fixture.chunk_infos.iter().zip(fixture.chunks.iter()) {
        repo.write_chunk(&fixture.backup_id, chunk, data).await.unwrap();
    }
    let commit = CommitRecord::new(
        fixture.backup_id,
        fixture.manifest.root_hash.clone(),
        fixture.manifest.manifest_hash.clone(),
        OffsetDateTime::now_utc(),
    );
    repo.finalize(&fixture.backup_id, &commit).await.unwrap();
    let report = repo.verify(&fixture.backup_id).await.unwrap();
    assert!(report.valid);
}

async fn test_delete<R: BackupRepository>(repo: &R) {
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    repo.write_chunk(&fixture.backup_id, &fixture.chunk_infos[0], &fixture.chunks[0])
        .await
        .unwrap();
    repo.delete(&fixture.backup_id).await.unwrap();
    assert!(repo.inspect(&fixture.backup_id).await.is_err());

    let fixture2 = build_fixture();
    repo.create(&fixture2.manifest).await.unwrap();
    for (chunk, data) in fixture2.chunk_infos.iter().zip(fixture2.chunks.iter()) {
        repo.write_chunk(&fixture2.backup_id, chunk, data).await.unwrap();
    }
    let commit = CommitRecord::new(
        fixture2.backup_id,
        fixture2.manifest.root_hash.clone(),
        fixture2.manifest.manifest_hash.clone(),
        OffsetDateTime::now_utc(),
    );
    repo.finalize(&fixture2.backup_id, &commit).await.unwrap();
    repo.delete(&fixture2.backup_id).await.unwrap();
    assert!(repo.inspect(&fixture2.backup_id).await.is_err());
}

#[tokio::test]
async fn filesystem_repository_passes_contract() {
    let dir = tempfile::tempdir().unwrap();
    let repo = FilesystemBackupRepository::open(dir.path().to_path_buf(), "contract").unwrap();
    repository_contract(&repo).await;
}

#[tokio::test]
async fn fs_repository_facade_passes_contract() {
    let dir = tempfile::tempdir().unwrap();
    let repo = super::legacy::FsRepository::open(dir.path().to_path_buf(), "contract").unwrap();
    repository_contract(&repo).await;
}

#[tokio::test]
async fn incomplete_backup_has_no_commit() {
    let dir = tempfile::tempdir().unwrap();
    let repo = FilesystemBackupRepository::open(dir.path().to_path_buf(), "contract").unwrap();
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    repo.write_chunk(&fixture.backup_id, &fixture.chunk_infos[0], &fixture.chunks[0])
        .await
        .unwrap();
    let info = repo.inspect(&fixture.backup_id).await.unwrap();
    assert_eq!(info.state, BackupState::Uploading);
    let staging = dir.path().join(".state").join(fixture.backup_id.to_string());
    assert!(staging.join("manifest.json").exists());
    assert!(!staging.join("commit.json").exists());
}

#[tokio::test]
async fn finalize_rejects_bad_commit_root() {
    let dir = tempfile::tempdir().unwrap();
    let repo = FilesystemBackupRepository::open(dir.path().to_path_buf(), "contract").unwrap();
    let fixture = build_fixture();
    repo.create(&fixture.manifest).await.unwrap();
    for (chunk, data) in fixture.chunk_infos.iter().zip(fixture.chunks.iter()) {
        repo.write_chunk(&fixture.backup_id, chunk, data).await.unwrap();
    }
    let bad_commit = CommitRecord::new(
        fixture.backup_id,
        "blake3:deadbeef".into(),
        fixture.manifest.manifest_hash.clone(),
        OffsetDateTime::now_utc(),
    );
    assert!(repo.finalize(&fixture.backup_id, &bad_commit).await.is_err());
    let info = repo.inspect(&fixture.backup_id).await.unwrap();
    assert_ne!(info.state, BackupState::Complete);
}
