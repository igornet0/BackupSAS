use backupsas_client::{BackupSasClient, MemoryBackupSource};
use backupsas_core::{BackupSasError, BackupState, DatabaseId, Identity};
use backupsas_integration::harness::{
    boot_existing_server, boot_fresh_server, client_config, plaintext_three_chunks, repo_root,
};
use backupsas_storage::{BackupRecord, StorageRoot, paths};
use std::io::Cursor;

async fn enrolled_client(
    data_dir: &std::path::Path,
    server: &backupsas_integration::harness::ServerHandle,
    identity: Identity,
) -> BackupSasClient {
    let config = client_config(
        server.addr,
        data_dir,
        server.server_id,
        server.public_key,
        server.enrollment_secret.clone(),
        identity,
    );
    BackupSasClient::connect(config).await.unwrap()
}

#[tokio::test]
async fn disconnect_mid_upload_then_resume() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let client = enrolled_client(data_dir, &server, identity).await;
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(
            client.config(),
            DatabaseId::new(),
            Cursor::new(plaintext_three_chunks()),
        )
        .await
        .unwrap();
    backup.upload_partial(1).await.unwrap();
    let manifest = backup.manifest.clone();
    let chunks = backup.chunks().to_vec();
    drop(backup);
    drop(session);

    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .resume_backup(client.config(), manifest.database_id, manifest, chunks)
        .await
        .unwrap();
    assert_eq!(backup.upload().await.unwrap(), 2);
    backup.commit().await.unwrap();
}

#[tokio::test]
async fn server_restart_mid_upload_then_resume() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let client_dir = data_dir.join("client-identity");
    identity.save(&client_dir).unwrap();
    let client = enrolled_client(data_dir, &server, identity).await;
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(
            client.config(),
            DatabaseId::new(),
            Cursor::new(plaintext_three_chunks()),
        )
        .await
        .unwrap();
    backup.upload_partial(2).await.unwrap();
    let manifest = backup.manifest.clone();
    let chunks = backup.chunks().to_vec();
    let backup_id = manifest.backup_id;
    drop(backup);
    drop(session);
    server.shutdown().await;

    let server = boot_existing_server(data_dir).await;
    let identity = Identity::load(&client_dir).unwrap();
    let client = enrolled_client(data_dir, &server, identity).await;
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .resume_backup(client.config(), manifest.database_id, manifest, chunks)
        .await
        .unwrap();
    backup.upload().await.unwrap();
    backup.commit().await.unwrap();

    let storage = StorageRoot::open(&backupsas_server::load_config(data_dir).unwrap()).unwrap();
    match storage.find_backup(&backup_id).unwrap() {
        (_, BackupRecord::Complete { metadata, .. }) => {
            assert_eq!(metadata.state, BackupState::Complete);
            assert_eq!(metadata.chunk_count, 3);
        }
        _ => panic!("expected complete backup record"),
    }
}

#[tokio::test]
async fn corrupt_staging_chunk_verify_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let client = enrolled_client(data_dir, &server, identity).await;
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(
            client.config(),
            DatabaseId::new(),
            Cursor::new(plaintext_three_chunks()),
        )
        .await
        .unwrap();
    backup.upload().await.unwrap();

    let chunk_path = paths::chunk_path(
        &paths::staging_chunks(&repo_root(data_dir), &backup.manifest.backup_id),
        1,
    );
    std::fs::write(&chunk_path, b"corrupted").unwrap();

    let err = backup.verify().await.unwrap_err();
    assert!(matches!(err, BackupSasError::InvalidManifest(_)));

    let config = backupsas_server::load_config(data_dir).unwrap();
    let storage = StorageRoot::open(&config).unwrap();
    match storage.find_backup(&backup.manifest.backup_id) {
        Ok((_, BackupRecord::Uploading(upload))) => {
            assert_ne!(upload.state, BackupState::Complete);
        }
        Ok(_) => panic!("expected uploading backup record"),
        Err(_) => panic!("backup not found after corrupt verify"),
    }
}

#[tokio::test]
async fn commit_without_verify_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let client = enrolled_client(data_dir, &server, identity).await;
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(
            client.config(),
            DatabaseId::new(),
            Cursor::new(plaintext_three_chunks()),
        )
        .await
        .unwrap();
    backup.upload().await.unwrap();
    let backup_id = backup.manifest.backup_id;
    drop(backup);
    drop(session);

    let storage = StorageRoot::open(&backupsas_server::load_config(data_dir).unwrap()).unwrap();
    let repo = storage.repo("avrora-prod").unwrap();
    let err = repo.commit(&backup_id).unwrap_err();
    assert!(matches!(
        err,
        backupsas_core::BackupSasError::InvalidState {
            expected: BackupState::Verifying,
            ..
        }
    ));
}

#[tokio::test]
async fn memory_source_upload_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let server = boot_fresh_server(data_dir).await;
    let identity = Identity::generate_client();
    let client = enrolled_client(data_dir, &server, identity).await;
    let mut session = client.authenticate().await.unwrap();
    let mut source = MemoryBackupSource::new(plaintext_three_chunks()).with_label("integration");
    let mut backup = session
        .create_backup_from_source(client.config(), DatabaseId::new(), &mut source)
        .await
        .unwrap();
    backup.upload().await.unwrap();
    let outcome = backup.commit().await.unwrap();

    let storage = StorageRoot::open(&backupsas_server::load_config(data_dir).unwrap()).unwrap();
    match storage.find_backup(&outcome.backup_id).unwrap() {
        (_, BackupRecord::Complete { path, .. }) => {
            assert!(path.join("commit.json").exists());
            assert!(path.join("manifest.json").exists());
        }
        _ => panic!("expected complete backup with commit.json"),
    }
}

#[tokio::test]
async fn expired_session_info_is_inactive() {
    use backupsas_core::{SessionId, SessionInfo};
    use time::OffsetDateTime;

    let info = SessionInfo {
        session_id: SessionId::new(),
        created_at: OffsetDateTime::now_utc() - time::Duration::hours(2),
        expires_at: OffsetDateTime::now_utc() - time::Duration::seconds(1),
    };
    assert!(!info.is_active());
    assert_eq!(info.state(), backupsas_core::SessionState::Expired);
}
