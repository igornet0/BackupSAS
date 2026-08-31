use backupsas_client::{BackupSasClient, MemoryBackupSource, MemoryRestoreTarget};
use backupsas_core::{BackupEncryptionKey, BackupId, CommitRecord, DatabaseId, Identity};
use backupsas_integration::harness::{boot_fresh_server, client_config, repo_root};
use backupsas_server::load_config;
use backupsas_storage::{BackupRecord, StorageRoot};
use std::io::Cursor;

async fn upload_memory_source(
    data_dir: &std::path::Path,
    source_data: Vec<u8>,
) -> (backupsas_core::BackupId, std::path::PathBuf) {
    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let client_dir = data_dir.join("client-identity");
    identity.save(&client_dir).unwrap();
    let config = client_config(
        server.addr,
        data_dir,
        server.server_id,
        server.public_key,
        server.enrollment_secret,
        identity,
    );
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut source = MemoryBackupSource::new(source_data);
    let mut backup = session
        .create_backup_from_source(client.config(), DatabaseId::new(), &mut source)
        .await
        .unwrap();
    backup.upload().await.unwrap();
    let outcome = backup.commit().await.unwrap();

    let storage = StorageRoot::open(&load_config(data_dir).unwrap()).unwrap();
    let (_, record) = storage.find_backup(&outcome.backup_id).unwrap();
    let path = match record {
        BackupRecord::Complete { path, .. } => path,
        _ => panic!("expected complete backup"),
    };
    (outcome.backup_id, path)
}

fn restore_client_config(
    addr: std::net::SocketAddr,
    data_dir: &std::path::Path,
    server: &backupsas_integration::harness::ServerHandle,
) -> backupsas_core::BackupSasConfig {
    let identity = Identity::load(&data_dir.join("client-identity")).unwrap();
    client_config(
        addr,
        data_dir,
        server.server_id,
        server.public_key,
        None,
        identity,
    )
}

fn random_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn restore_memory_e2e_byte_equality() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(1024 * 1024);
    let (backup_id, _) = upload_memory_source(data_dir, source_data.clone()).await;

    let server = boot_fresh_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = MemoryRestoreTarget::new();
    backup
        .restore_to(client.config(), &mut target)
        .await
        .unwrap();

    assert_eq!(source_data, target.into_bytes());
}

#[tokio::test]
async fn restore_rejects_corrupt_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(256 * 1024);
    let (backup_id, path) = upload_memory_source(data_dir, source_data).await;

    std::fs::write(path.join("chunks").join("000001"), b"corrupted").unwrap();

    let server = boot_fresh_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = MemoryRestoreTarget::new();
    let err = backup
        .restore_to(client.config(), &mut target)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("hash mismatch"),
        "unexpected error: {err}"
    );
    assert!(!target.is_finalized());
}

#[tokio::test]
async fn restore_rejects_bad_commit_on_open() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(128 * 1024);
    let (backup_id, path) = upload_memory_source(data_dir, source_data).await;

    let commit_path = path.join("commit.json");
    let mut commit: CommitRecord =
        serde_json::from_slice(&std::fs::read(&commit_path).unwrap()).unwrap();
    commit.root_hash = "blake3:deadbeef".into();
    std::fs::write(&commit_path, commit.to_vec_pretty().unwrap()).unwrap();

    let server = boot_fresh_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let result = session.open_backup(backup_id).await;
    let err = result.err().expect("open should fail");
    assert!(
        err.to_string().contains("root_hash mismatch") || err.to_string().contains("commit"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn restore_rejects_bad_merkle_root_on_open() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(128 * 1024);
    let (backup_id, path) = upload_memory_source(data_dir, source_data).await;

    let manifest_path = path.join("manifest.json");
    let mut manifest: backupsas_core::BackupManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest.root_hash = "blake3:deadbeef".into();
    std::fs::write(&manifest_path, manifest.to_vec().unwrap()).unwrap();

    let server = boot_fresh_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let err = session
        .open_backup(backup_id)
        .await
        .err()
        .expect("open should fail");
    assert!(
        err.to_string().contains("root_hash") || err.to_string().contains("manifest"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn restore_rejects_missing_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let _ = upload_memory_source(data_dir, random_bytes(64 * 1024)).await;

    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let config = client_config(
        server.addr,
        data_dir,
        server.server_id,
        server.public_key,
        server.enrollment_secret,
        identity,
    );
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let missing = BackupId::new();
    let err = session
        .open_backup(missing)
        .await
        .err()
        .expect("open should fail");
    assert!(
        err.to_string().contains("not found"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn restore_rejects_expired_session() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(64 * 1024);
    let (backup_id, _) = upload_memory_source(data_dir, source_data).await;

    let server = boot_fresh_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    session.info.expires_at = time::OffsetDateTime::now_utc() - time::Duration::seconds(1);
    let err = session
        .open_backup(backup_id)
        .await
        .err()
        .expect("open should fail");
    assert!(
        err.to_string().contains("expired"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn restore_rejects_wrong_encryption_key() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(128 * 1024);
    let (backup_id, _) = upload_memory_source(data_dir, source_data).await;

    let server = boot_fresh_server(data_dir).await;
    let mut config = restore_client_config(server.addr, data_dir, &server);
    config.backup_encryption_key = BackupEncryptionKey::new([1u8; 32]);

    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = MemoryRestoreTarget::new();
    let err = backup
        .restore_to(client.config(), &mut target)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("decrypt"),
        "unexpected error: {err}"
    );
    assert!(!target.is_finalized());
}

#[tokio::test]
async fn restore_failure_leaves_target_unfinalized() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(256 * 1024);
    let (backup_id, path) = upload_memory_source(data_dir, source_data).await;

    std::fs::write(path.join("chunks").join("000002"), b"tampered").unwrap();

    let server = boot_fresh_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = MemoryRestoreTarget::new();
    assert!(
        backup
            .restore_to(client.config(), &mut target)
            .await
            .is_err()
    );
    assert!(!target.is_finalized());
    let _ = repo_root(data_dir);
}

#[tokio::test]
async fn restore_via_reader_upload_path() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(192 * 1024);

    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    identity.save(&data_dir.join("client-identity")).unwrap();
    let config = client_config(
        server.addr,
        data_dir,
        server.server_id,
        server.public_key,
        server.enrollment_secret,
        identity,
    );
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(
            client.config(),
            DatabaseId::new(),
            Cursor::new(source_data.clone()),
        )
        .await
        .unwrap();
    backup.upload().await.unwrap();
    let outcome = backup.commit().await.unwrap();

    let server2 = boot_fresh_server(data_dir).await;
    let config2 = restore_client_config(server2.addr, data_dir, &server2);
    let client2 = BackupSasClient::connect(config2).await.unwrap();
    let mut session2 = client2.authenticate().await.unwrap();
    let mut restore = session2.open_backup(outcome.backup_id).await.unwrap();
    let mut target = MemoryRestoreTarget::new();
    restore
        .restore_to(client2.config(), &mut target)
        .await
        .unwrap();
    assert_eq!(source_data, target.into_bytes());
}
