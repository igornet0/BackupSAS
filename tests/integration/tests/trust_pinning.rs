use backupsas_client::BackupSasClient;
use backupsas_core::{
    BackupEncryptionKey, BackupSasConfig, BackupSasError, Identity, PublicKey, SecretKey,
    DEFAULT_REPO_NAME,
};
use backupsas_server::{bind, init_data_dir, serve, ServerState};
use std::time::Duration;

#[tokio::test]
async fn reject_changed_server_public_key() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let init = init_data_dir(data_dir, "127.0.0.1:0").unwrap();
    let server_id = init.config.server_id;
    let state = ServerState::from_config(init.config).unwrap();
    let (listener, addr) = bind("127.0.0.1:0").await.unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let wrong_pk: PublicKey = SecretKey::generate().public_key();
    let config = BackupSasConfig::new(
        addr.to_string(),
        server_id,
        wrong_pk,
        Identity::generate_client(),
        DEFAULT_REPO_NAME,
        BackupEncryptionKey::new([1u8; 32]),
    )
    .with_ca_cert(data_dir.join("tls").join("ca.crt"));

    let client = BackupSasClient::connect(config).await.unwrap();
    match client.authenticate().await {
        Err(err) => assert!(
            matches!(err, BackupSasError::TrustPinMismatch { .. }),
            "expected pin mismatch, got {err:?}"
        ),
        Ok(_) => panic!("authentication must fail when the pinned public key is wrong"),
    }
}
