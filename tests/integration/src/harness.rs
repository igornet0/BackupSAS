//! Shared harness for integration tests.

use backupsas_core::{
    BackupEncryptionKey, BackupId, BackupSasConfig, DEFAULT_REPO_NAME, DatabaseId,
    EnrollmentSecret, Identity, PublicKey, ServerId,
};
use backupsas_server::{ServerState, bind, init_data_dir, load_config, serve};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn random_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

pub fn plaintext_three_chunks() -> Vec<u8> {
    let mut data = Vec::new();
    for i in 0..3u8 {
        data.extend(std::iter::repeat_n(i + 1, 64 * 1024));
    }
    data
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    pub server_id: ServerId,
    pub public_key: PublicKey,
    pub enrollment_secret: Option<EnrollmentSecret>,
    _task: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    pub async fn shutdown(self) {
        self._task.abort();
        let _ = self._task.await;
    }
}

pub async fn boot_fresh_server(data_dir: &Path) -> ServerHandle {
    let init = init_data_dir(data_dir, "127.0.0.1:0").unwrap();
    let secret = init.enrollment_secret;
    let server_id = init.config.server_id;
    let public_key = init.public_key;
    let state = ServerState::from_config(init.config).unwrap();
    let (listener, addr) = bind("127.0.0.1:0").await.unwrap();
    let task = tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    ServerHandle {
        addr,
        server_id,
        public_key,
        enrollment_secret: Some(secret),
        _task: task,
    }
}

pub async fn boot_existing_server(data_dir: &Path) -> ServerHandle {
    let config = load_config(data_dir).unwrap();
    let server_id = config.server_id;
    let identity = backupsas_core::Identity::load(&data_dir.join("identity")).unwrap();
    let public_key = identity.public_key;
    let state = ServerState::from_config(config).unwrap();
    let (listener, addr) = bind("127.0.0.1:0").await.unwrap();
    let task = tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    ServerHandle {
        addr,
        server_id,
        public_key,
        enrollment_secret: None,
        _task: task,
    }
}

pub fn client_config(
    addr: SocketAddr,
    data_dir: &Path,
    server_id: ServerId,
    server_pk: PublicKey,
    secret: Option<EnrollmentSecret>,
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

pub fn repo_root(data_dir: &Path) -> PathBuf {
    backupsas_storage::repo_root(data_dir, DEFAULT_REPO_NAME)
}

pub fn restore_client_config(
    addr: SocketAddr,
    data_dir: &Path,
    server: &ServerHandle,
) -> BackupSasConfig {
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

pub async fn upload_memory_source(data_dir: &Path, source_data: Vec<u8>) -> (BackupId, PathBuf) {
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
    let client = backupsas_client::BackupSasClient::connect(config)
        .await
        .unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut source = backupsas_client::MemoryBackupSource::new(source_data);
    let mut backup = session
        .create_backup_from_source(client.config(), DatabaseId::new(), &mut source)
        .await
        .unwrap();
    backup.upload().await.unwrap();
    let outcome = backup.commit().await.unwrap();

    let storage = backupsas_storage::StorageRoot::open(&load_config(data_dir).unwrap()).unwrap();
    let (_, record) = storage.find_backup(&outcome.backup_id).unwrap();
    let path = match record {
        backupsas_storage::BackupRecord::Complete { path, .. } => path,
        _ => panic!("expected complete backup"),
    };
    (outcome.backup_id, path)
}
