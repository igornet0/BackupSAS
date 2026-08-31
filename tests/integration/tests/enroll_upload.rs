use backupsas_client::BackupSasClient;
use backupsas_core::{
    BackupEncryptionKey, BackupSasConfig, BackupState, DEFAULT_REPO_NAME, DatabaseId, Identity,
};
use backupsas_server::{ServerState, bind, init_data_dir, load_config, serve};
use backupsas_storage::{BackupRecord, StorageRoot};
use std::io::Cursor;
use std::time::Duration;

fn plaintext() -> Vec<u8> {
    let mut data = Vec::new();
    for i in 0..3u8 {
        data.extend(std::iter::repeat_n(i + 1, 64 * 1024));
    }
    data
}

async fn start_server(
    data_dir: &std::path::Path,
) -> (
    std::net::SocketAddr,
    backupsas_core::ServerId,
    backupsas_core::PublicKey,
    backupsas_core::EnrollmentSecret,
) {
    let init = init_data_dir(data_dir, "127.0.0.1:0").unwrap();
    let secret = init.enrollment_secret;
    let server_id = init.config.server_id;
    let public_key = init.public_key;
    let state = ServerState::from_config(init.config).unwrap();
    let (listener, addr) = bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, server_id, public_key, secret)
}

fn client_config(
    addr: std::net::SocketAddr,
    data_dir: &std::path::Path,
    server_id: backupsas_core::ServerId,
    server_pk: backupsas_core::PublicKey,
    secret: Option<backupsas_core::EnrollmentSecret>,
    identity: Identity,
) -> BackupSasConfig {
    let mut cfg = BackupSasConfig::new(
        addr.to_string(),
        server_id,
        server_pk,
        identity,
        DEFAULT_REPO_NAME,
        BackupEncryptionKey::new([9u8; 32]),
    )
    .with_ca_cert(data_dir.join("tls").join("ca.crt"))
    .with_chunk_size(64 * 1024);
    if let Some(secret) = secret {
        cfg = cfg.with_bootstrap_secret(secret);
    }
    cfg
}

#[tokio::test]
async fn enroll_authenticate_upload_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let (addr, server_id, server_pk, secret) = start_server(data_dir).await;
    let identity = Identity::generate_client();
    let config = client_config(addr, data_dir, server_id, server_pk, Some(secret), identity);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(client.config(), DatabaseId::new(), Cursor::new(plaintext()))
        .await
        .unwrap();
    let sent = backup.upload().await.unwrap();
    assert_eq!(sent, 3);
    let outcome = backup.commit().await.unwrap();

    let storage = StorageRoot::open(&load_config(data_dir).unwrap()).unwrap();
    match storage.find_backup(&outcome.backup_id).unwrap() {
        (_, BackupRecord::Complete { metadata, path }) => {
            assert_eq!(metadata.state, BackupState::Complete);
            assert!(path.join("chunks").join("000002").exists());
        }
        other => panic!("expected complete: {:?}", other.1),
    }
}

#[tokio::test]
async fn resume_after_partial_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let (addr, server_id, server_pk, secret) = start_server(data_dir).await;
    let identity = Identity::generate_client();
    let config = client_config(addr, data_dir, server_id, server_pk, Some(secret), identity);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .create_backup(client.config(), DatabaseId::new(), Cursor::new(plaintext()))
        .await
        .unwrap();
    let sent = backup.upload_partial(1).await.unwrap();
    assert_eq!(sent, 1);
    let manifest = backup.manifest.clone();
    let chunks = backup.chunks().to_vec();
    drop(backup);
    drop(session);

    let mut session = client.authenticate().await.unwrap();
    let mut backup = session
        .resume_backup(client.config(), manifest.database_id, manifest, chunks)
        .await
        .unwrap();
    let sent = backup.upload().await.unwrap();
    assert_eq!(sent, 2);
    let outcome = backup.commit().await.unwrap();

    let storage = StorageRoot::open(&load_config(data_dir).unwrap()).unwrap();
    match storage.find_backup(&outcome.backup_id).unwrap() {
        (_, BackupRecord::Complete { metadata, .. }) => {
            assert_eq!(metadata.chunk_count, 3);
        }
        other => panic!("expected complete: {:?}", other.1),
    }
}
