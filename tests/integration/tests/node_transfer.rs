//! Connect descriptor, catalog listing, and node-to-node transfer (copy/move)
//! with delegated trust and owner-acknowledged relocation.

use backupsas_client::{BackupSasClient, MemoryBackupSource, MemoryRestoreTarget, TransferOffer};
use backupsas_core::{
    BackupEncryptionKey, BackupId, BackupSasConfig, ConnectDescriptor, DEFAULT_REPO_NAME,
    DatabaseId, EnrollmentSecret, Identity, PeerKind, ServerConfig, TransferMode,
};
use backupsas_server::peers::add_peer;
use backupsas_server::transfer::{TransferRequest, run_transfer};
use backupsas_server::{
    ServerState, bind, init_data_dir, issue_enrollment_secret, refresh_descriptor, save_config,
    serve,
};
use std::path::Path;
use std::time::Duration;

const KEY: [u8; 32] = [7u8; 32];

struct Node {
    config: ServerConfig,
    descriptor: ConnectDescriptor,
    secret: EnrollmentSecret,
    task: tokio::task::JoinHandle<()>,
}

/// Boot a node and publish its real listening address in `connect.json`.
async fn boot_node(data_dir: &Path) -> Node {
    let init = init_data_dir(data_dir, "127.0.0.1:0").unwrap();
    let (listener, addr) = bind("127.0.0.1:0").await.unwrap();
    let mut config = init.config;
    config.public_endpoints = vec![addr.to_string()];
    save_config(&config).unwrap();
    let descriptor = refresh_descriptor(&config).unwrap();
    let state = ServerState::from_config(config.clone()).unwrap();
    let task = tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Node {
        config,
        descriptor,
        secret: init.enrollment_secret,
        task,
    }
}

fn db_config(descriptor: &ConnectDescriptor, identity: Identity) -> BackupSasConfig {
    BackupSasConfig::from_descriptor(
        descriptor,
        identity,
        DEFAULT_REPO_NAME,
        BackupEncryptionKey::new(KEY),
    )
    .unwrap()
    .with_chunk_size(64 * 1024)
}

fn data(n: usize, salt: u8) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8 ^ salt).collect()
}

async fn upload(cfg: BackupSasConfig, bytes: Vec<u8>) -> BackupId {
    let client = BackupSasClient::new(cfg);
    let mut session = client.authenticate().await.unwrap();
    let mut source = MemoryBackupSource::new(bytes);
    let mut backup = session
        .create_backup_from_source(client.config(), DatabaseId::new(), &mut source)
        .await
        .unwrap();
    backup.upload().await.unwrap();
    backup.commit().await.unwrap().backup_id
}

async fn restore(cfg: BackupSasConfig, id: BackupId) -> Vec<u8> {
    let client = BackupSasClient::new(cfg);
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(id).await.unwrap();
    let mut target = MemoryRestoreTarget::new();
    backup
        .restore_to(client.config(), &mut target)
        .await
        .unwrap();
    target.into_bytes()
}

#[tokio::test]
async fn descriptor_is_signed_and_usable() {
    let tmp = tempfile::tempdir().unwrap();
    let node = boot_node(tmp.path()).await;
    let on_disk = ConnectDescriptor::load(&tmp.path().join("connect.json")).unwrap();
    on_disk.verify().unwrap();
    assert_eq!(on_disk, node.descriptor);
    assert!(on_disk.has_feature("transfer"));

    let identity = Identity::generate_client();
    let cfg = db_config(&node.descriptor, identity).with_bootstrap_secret(node.secret.clone());
    let id = upload(cfg, data(100_000, 1)).await;

    let identity = Identity::generate_client();
    // A different identity without enrollment cannot authenticate.
    let err = BackupSasClient::new(db_config(&node.descriptor, identity))
        .authenticate()
        .await;
    assert!(err.is_err());
    let _ = id;
    node.task.abort();
}

#[tokio::test]
async fn copy_and_move_between_nodes() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let a = boot_node(tmp_a.path()).await;
    let b = boot_node(tmp_b.path()).await;

    // Database enrolls on node A and uploads two backups.
    let db_dir = tempfile::tempdir().unwrap();
    Identity::generate_client().save(db_dir.path()).unwrap();
    let ident = || Identity::load(db_dir.path()).unwrap();
    let first = data(200_000, 3);
    let second = data(150_000, 9);
    let id1 = upload(
        db_config(&a.descriptor, ident()).with_bootstrap_secret(a.secret.clone()),
        first.clone(),
    )
    .await;
    let id2 = upload(db_config(&a.descriptor, ident()), second.clone()).await;

    {
        let mut s = BackupSasClient::new(db_config(&a.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        let items = s.list_backups(DEFAULT_REPO_NAME).await.unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| i.state == "COMPLETE" && !i.relocated));
        assert!(s.pending_relocations().await.unwrap().is_empty());
    }

    // Database identity must not be able to push transfers (not a node).
    {
        let mut s = BackupSasClient::new(db_config(&a.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        let offer = TransferOffer {
            transfer_id: "trf_x".into(),
            mode: TransferMode::Copy,
            repository: DEFAULT_REPO_NAME.into(),
            owner_client_id: ident().id.to_string(),
            owner_public_key: ident().public_key.to_bytes().to_vec(),
        };
        let storage = backupsas_storage::StorageRoot::open(&a.config).unwrap();
        let manifest = storage
            .repo(DEFAULT_REPO_NAME)
            .unwrap()
            .read_manifest_bytes(&id1)
            .unwrap();
        let err = s
            .push_encrypted(&offer, &manifest, |_| Ok(vec![]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("only enrolled nodes"), "{err}");
    }

    // Pair A -> B using a node secret issued on B.
    let node_secret = issue_enrollment_secret(tmp_b.path(), PeerKind::Node).unwrap();
    add_peer(
        tmp_a.path(),
        "b",
        b.descriptor.clone(),
        DEFAULT_REPO_NAME,
        node_secret,
    )
    .await
    .unwrap();

    // COPY id1.
    let report = run_transfer(
        &a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: Some(vec![id1]),
            mode: TransferMode::Copy,
        },
    )
    .await
    .unwrap();
    assert_eq!(report.notices.len(), 1);

    let notice = {
        let mut s = BackupSasClient::new(db_config(&a.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        let notices = s.pending_relocations().await.unwrap();
        assert_eq!(notices.len(), 1);
        notices[0].clone()
    };
    notice.verify(&a.descriptor.public_key).unwrap();
    assert!(notice.verify(&b.descriptor.public_key).is_err());
    assert_eq!(notice.target.server_id, b.descriptor.server_id);
    assert_eq!(notice.backup_ids, vec![id1]);

    // The database reaches B with its existing identity (delegated trust).
    assert_eq!(
        restore(db_config(&notice.target, ident()), id1).await,
        first
    );

    {
        let mut s = BackupSasClient::new(db_config(&a.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        s.ack_relocation(&notice.relocation_id).await.unwrap();
        assert!(s.pending_relocations().await.unwrap().is_empty());
    }
    // Copy keeps the source.
    assert_eq!(restore(db_config(&a.descriptor, ident()), id1).await, first);

    // MOVE id2.
    run_transfer(
        &a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: Some(vec![id2]),
            mode: TransferMode::Move,
        },
    )
    .await
    .unwrap();
    let notice = {
        let mut s = BackupSasClient::new(db_config(&a.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        let items = s.list_backups(DEFAULT_REPO_NAME).await.unwrap();
        let moved = items
            .iter()
            .find(|i| i.backup_id == id2.to_string())
            .unwrap();
        assert!(moved.relocated);
        s.pending_relocations().await.unwrap().remove(0)
    };
    assert_eq!(notice.mode, TransferMode::Move);
    notice.verify(&a.descriptor.public_key).unwrap();
    // Still readable on A until acknowledged.
    assert_eq!(
        restore(db_config(&a.descriptor, ident()), id2).await,
        second
    );
    assert_eq!(
        restore(db_config(&b.descriptor, ident()), id2).await,
        second
    );

    {
        let mut s = BackupSasClient::new(db_config(&a.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        s.ack_relocation(&notice.relocation_id).await.unwrap();
        let items = s.list_backups(DEFAULT_REPO_NAME).await.unwrap();
        assert_eq!(items.len(), 1, "moved backup is deleted on A after ack");
        assert_eq!(items[0].backup_id, id1.to_string());
    }

    // B lists both; owner can delete (retention).
    {
        let mut s = BackupSasClient::new(db_config(&b.descriptor, ident()))
            .authenticate()
            .await
            .unwrap();
        assert_eq!(s.list_backups(DEFAULT_REPO_NAME).await.unwrap().len(), 2);
        s.delete_backup(&id1.to_string()).await.unwrap();
        assert_eq!(s.list_backups(DEFAULT_REPO_NAME).await.unwrap().len(), 1);
    }

    a.task.abort();
    b.task.abort();
}
