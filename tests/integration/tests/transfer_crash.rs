//! Crash / retry / authorization tests for node-to-node transfer, relocation
//! acknowledgement and enrollment.

use backupsas_client::{BackupSasClient, MemoryBackupSource, MemoryRestoreTarget, TransferOffer};
use backupsas_core::{
    BackupId, BackupSasConfig, BackupSasError, DEFAULT_REPO_NAME, DatabaseId, Identity,
    ParticipantId, PeerKind, SecretKey, TransferMode,
};
use backupsas_integration::harness::{PublishedNode, boot_published_node, descriptor_config};
use backupsas_server::issue_enrollment_secret;
use backupsas_server::peers::{PeerStore, add_peer, peer_client_config};
use backupsas_server::relocations::RelocationStore;
use backupsas_server::transfer::{TransferRequest, run_transfer};
use backupsas_storage::StorageRoot;
use std::path::Path;

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

struct Fixture {
    _tmp: tempfile::TempDir,
    a: PublishedNode,
    b: PublishedNode,
    db: std::path::PathBuf,
    id: BackupId,
    payload: Vec<u8>,
}

impl Fixture {
    fn db(&self) -> Identity {
        Identity::load(&self.db).unwrap()
    }

    fn a_dir(&self) -> &Path {
        &self.a.config.data_dir
    }
}

/// Two nodes, a database enrolled on A with one 4-chunk backup, A paired to B.
async fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let a = boot_published_node(&tmp.path().join("a"), None).await;
    let b = boot_published_node(&tmp.path().join("b"), None).await;
    let db = tmp.path().join("db-identity");
    Identity::generate_client().save(&db).unwrap();
    let payload = data(250_000, 5);
    let id = upload(
        descriptor_config(&a.descriptor, Identity::load(&db).unwrap())
            .with_bootstrap_secret(a.secret.clone().unwrap()),
        payload.clone(),
    )
    .await;
    let node_secret = issue_enrollment_secret(&b.config.data_dir, PeerKind::Node).unwrap();
    add_peer(
        &a.config.data_dir,
        "b",
        b.descriptor.clone(),
        DEFAULT_REPO_NAME,
        node_secret,
    )
    .await
    .unwrap();
    Fixture {
        _tmp: tmp,
        a,
        b,
        db,
        id,
        payload,
    }
}

fn manifest_hash(info: &[backupsas_core::RemoteBackupInfo], id: BackupId) -> String {
    info.iter()
        .find(|i| i.backup_id == id.to_string())
        .map(|i| i.manifest_hash.clone())
        .unwrap_or_default()
}

/// Push `id` from A to B as the node, failing after `fail_at` chunks.
async fn interrupted_push(f: &Fixture, fail_at: u32) -> BackupSasError {
    let peer = PeerStore::open(f.a_dir()).unwrap().get("b").unwrap();
    let cfg = peer_client_config(f.a_dir(), &peer, None).unwrap();
    let mut session = BackupSasClient::new(cfg).authenticate().await.unwrap();
    let storage = StorageRoot::open(&f.a.config).unwrap();
    let repo = storage.repo(DEFAULT_REPO_NAME).unwrap();
    let manifest = repo.read_manifest_bytes(&f.id).unwrap();
    let owner = f.db();
    let offer = TransferOffer {
        transfer_id: "trf_crash".into(),
        mode: TransferMode::Move,
        repository: DEFAULT_REPO_NAME.into(),
        owner_client_id: owner.id.to_string(),
        owner_public_key: owner.public_key.to_bytes().to_vec(),
    };
    let ParticipantId::Client(owner_id) = owner.id else {
        unreachable!()
    };
    session
        .push_encrypted(&offer, &manifest, |seq| {
            if seq >= fail_at {
                return Err(BackupSasError::Other("simulated crash".into()));
            }
            repo.read_complete_chunk(&f.id, owner_id, seq)
        })
        .await
        .unwrap_err()
}

#[tokio::test]
async fn partial_transfer_is_never_committed_and_resumes_after_restart() {
    let f = fixture().await;
    let err = interrupted_push(&f, 2).await;
    assert!(err.to_string().contains("simulated crash"), "{err}");

    // On B the owner sees only an incomplete upload and cannot open it.
    {
        let mut s = BackupSasClient::new(descriptor_config(&f.b.descriptor, f.db()))
            .authenticate()
            .await
            .unwrap();
        let items = s.list_backups(DEFAULT_REPO_NAME).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_ne!(items[0].state, "COMPLETE");
        assert!(items[0].manifest_hash.is_empty());
        assert!(s.open_backup(f.id).await.is_err());
    }

    // Crash + restart B on the same address; the transfer resumes and commits.
    let b_dir = f.b.config.data_dir.clone();
    let Fixture {
        _tmp,
        a,
        b,
        db,
        id,
        payload,
    } = f;
    let (_, b_addr) = b.kill().await;
    let b = boot_published_node(&b_dir, Some(b_addr)).await;
    let f = Fixture {
        _tmp,
        a,
        b,
        db,
        id,
        payload,
    };

    let report = run_transfer(
        &f.a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: Some(vec![f.id]),
            mode: TransferMode::Copy,
        },
    )
    .await
    .unwrap();
    assert_eq!(report.transferred, vec![f.id]);

    let list = |desc: backupsas_core::ConnectDescriptor| {
        let ident = f.db();
        async move {
            let mut s = BackupSasClient::new(descriptor_config(&desc, ident))
                .authenticate()
                .await
                .unwrap();
            s.list_backups(DEFAULT_REPO_NAME).await.unwrap()
        }
    };
    let on_a = list(f.a.descriptor.clone()).await;
    let on_b = list(f.b.descriptor.clone()).await;
    let ha = manifest_hash(&on_a, f.id);
    assert!(!ha.is_empty());
    assert_eq!(
        ha,
        manifest_hash(&on_b, f.id),
        "copies must share manifest_hash"
    );
    assert_eq!(
        restore(descriptor_config(&f.b.descriptor, f.db()), f.id).await,
        f.payload
    );
}

#[tokio::test]
async fn transfer_retry_after_commit_is_idempotent() {
    let f = fixture().await;
    let req = TransferRequest {
        peer: "b".into(),
        repository: DEFAULT_REPO_NAME.into(),
        backup_ids: Some(vec![f.id]),
        mode: TransferMode::Copy,
    };
    run_transfer(&f.a.config, &req).await.unwrap();
    // A crash before the notice was recorded would make the operator retry:
    // the target answers `Committed` for the identical copy.
    let again = run_transfer(&f.a.config, &req).await.unwrap();
    assert_eq!(again.transferred, vec![f.id]);
    assert_eq!(
        restore(descriptor_config(&f.b.descriptor, f.db()), f.id).await,
        f.payload
    );
}

#[tokio::test]
async fn move_cleanup_survives_crash_between_ack_and_delete() {
    let f = fixture().await;
    run_transfer(
        &f.a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: None,
            mode: TransferMode::Move,
        },
    )
    .await
    .unwrap();
    let store = RelocationStore::open(f.a_dir()).unwrap();
    let rid = store.list().unwrap()[0].notice.relocation_id.clone();
    let ParticipantId::Client(owner) = f.db().id else {
        unreachable!()
    };
    // A second move of the same backup is refused while the first is open.
    assert!(
        run_transfer(
            &f.a.config,
            &TransferRequest {
                peer: "b".into(),
                repository: DEFAULT_REPO_NAME.into(),
                backup_ids: Some(vec![f.id]),
                mode: TransferMode::Move,
            },
        )
        .await
        .is_err()
    );

    // Ack recorded, then the process dies before deleting the local copy.
    store.ack(&rid, &owner).unwrap();
    let storage = StorageRoot::open(&f.a.config).unwrap();
    assert!(storage.find_backup(&f.id).is_ok(), "not deleted yet");

    let a_dir = f.a_dir().to_path_buf();
    let Fixture {
        _tmp,
        a,
        b,
        db,
        id,
        payload,
    } = f;
    let (_, a_addr) = a.kill().await;
    let a = boot_published_node(&a_dir, Some(a_addr)).await; // recovery on startup
    let f = Fixture {
        _tmp,
        a,
        b,
        db,
        id,
        payload,
    };

    let storage = StorageRoot::open(&f.a.config).unwrap();
    assert!(
        storage.find_backup(&f.id).is_err(),
        "cleanup completed on restart"
    );
    assert!(store.list().unwrap()[0].cleaned);

    // A late (duplicate) ack from the database is still accepted.
    let mut s = BackupSasClient::new(descriptor_config(&f.a.descriptor, f.db()))
        .authenticate()
        .await
        .unwrap();
    s.ack_relocation(&rid).await.unwrap();
    s.ack_relocation(&rid).await.unwrap();
    assert!(s.pending_relocations().await.unwrap().is_empty());
    assert_eq!(
        restore(descriptor_config(&f.b.descriptor, f.db()), f.id).await,
        f.payload
    );
}

#[tokio::test]
async fn move_source_kept_until_owner_ack() {
    let f = fixture().await;
    let err = interrupted_push(&f, 1).await;
    assert!(err.to_string().contains("simulated crash"));
    // Nothing committed on B, so no notice and the source is intact.
    assert!(
        RelocationStore::open(f.a_dir())
            .unwrap()
            .list()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        restore(descriptor_config(&f.a.descriptor, f.db()), f.id).await,
        f.payload
    );
}

#[tokio::test]
async fn foreign_clients_cannot_touch_backups_or_hijack_identities() {
    let f = fixture().await;
    let owner = f.db();

    // A second database enrolls with its own secret.
    let secret = issue_enrollment_secret(f.a_dir(), PeerKind::Database).unwrap();
    let other = Identity::generate_client();
    let other_dir = f.a_dir().join("other-db");
    other.save(&other_dir).unwrap();
    let mut s = BackupSasClient::new(
        descriptor_config(&f.a.descriptor, other).with_bootstrap_secret(secret),
    )
    .authenticate()
    .await
    .unwrap();
    assert!(s.list_backups(DEFAULT_REPO_NAME).await.unwrap().is_empty());
    assert!(s.open_backup(f.id).await.is_err());
    assert!(s.delete_backup(&f.id.to_string()).await.is_err());
    // Abort of a foreign backup is a no-op.
    s.conn
        .send(&backupsas_protocol::Message::Abort {
            session_id: s.session_id.to_string(),
            backup_id: f.id.to_string(),
        })
        .await
        .unwrap();
    let _ = s.conn.recv().await.unwrap();
    s.conn
        .send(&backupsas_protocol::Message::Status {
            session_id: s.session_id.to_string(),
            backup_id: Some(f.id.to_string()),
        })
        .await
        .unwrap();
    assert!(matches!(
        s.conn.recv().await.unwrap(),
        backupsas_protocol::Message::Error { .. }
    ));
    assert_eq!(
        restore(descriptor_config(&f.a.descriptor, f.db()), f.id).await,
        f.payload
    );

    // Re-enrolling the owner's client id with another key is refused, and the
    // secret is not consumed by the failed attempt.
    let secret = issue_enrollment_secret(f.a_dir(), PeerKind::Database).unwrap();
    let impostor = Identity::from_parts(owner.id, SecretKey::generate());
    let res = BackupSasClient::new(
        descriptor_config(&f.a.descriptor, impostor).with_bootstrap_secret(secret.clone()),
    )
    .authenticate()
    .await;
    assert!(res.is_err());
    BackupSasClient::new(
        descriptor_config(&f.a.descriptor, Identity::generate_client())
            .with_bootstrap_secret(secret),
    )
    .authenticate()
    .await
    .expect("secret still usable after rejected hijack");

    // A node cannot re-key a delegated owner on the target.
    run_transfer(
        &f.a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: None,
            mode: TransferMode::Copy,
        },
    )
    .await
    .unwrap();
    let peer = PeerStore::open(f.a_dir()).unwrap().get("b").unwrap();
    let mut node = BackupSasClient::new(peer_client_config(f.a_dir(), &peer, None).unwrap())
        .authenticate()
        .await
        .unwrap();
    let manifest = StorageRoot::open(&f.a.config)
        .unwrap()
        .repo(DEFAULT_REPO_NAME)
        .unwrap()
        .read_manifest_bytes(&f.id)
        .unwrap();
    let forged = TransferOffer {
        transfer_id: "trf_forged".into(),
        mode: TransferMode::Copy,
        repository: DEFAULT_REPO_NAME.into(),
        owner_client_id: owner.id.to_string(),
        owner_public_key: SecretKey::generate().public_key().to_bytes().to_vec(),
    };
    let err = node
        .push_encrypted(&forged, &manifest, |_| Ok(vec![]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("trust pin"), "{err}");
}

#[tokio::test]
async fn concurrent_enrollment_consumes_secret_once() {
    let tmp = tempfile::tempdir().unwrap();
    let node = boot_published_node(tmp.path(), None).await;
    let secret = node.secret.clone().unwrap();
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let cfg = descriptor_config(&node.descriptor, Identity::generate_client())
            .with_bootstrap_secret(secret.clone());
        tasks.push(tokio::spawn(async move {
            BackupSasClient::new(cfg).authenticate().await.is_ok()
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1, "exactly one enrollment may use a one-time secret");
}

#[tokio::test]
async fn stale_partial_transfer_is_garbage_collected_on_restart() {
    let f = fixture().await;
    interrupted_push(&f, 1).await;
    let b_dir = f.b.config.data_dir.clone();
    let Fixture {
        _tmp,
        a,
        b,
        db,
        id,
        payload,
    } = f;
    let (mut cfg, b_addr) = b.kill().await;
    // Restart with the default TTL: the resumable upload is kept.
    let b = boot_published_node(&b_dir, Some(b_addr)).await;
    let storage = StorageRoot::open(&b.config).unwrap();
    assert!(
        storage.find_backup(&id).is_ok(),
        "fresh upload must survive"
    );
    let (_, b_addr) = b.kill().await;

    // Idle longer than a 1s TTL: removed at startup.
    cfg.stale_upload_ttl_secs = Some(1);
    backupsas_server::save_config(&cfg).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let b = boot_published_node(&b_dir, Some(b_addr)).await;
    let storage = StorageRoot::open(&b.config).unwrap();
    assert!(storage.find_backup(&id).is_err(), "stale upload removed");
    let f = Fixture {
        _tmp,
        a,
        b,
        db,
        id,
        payload,
    };
    // The source still holds the backup, so the transfer can simply be redone.
    run_transfer(
        &f.a.config,
        &TransferRequest {
            peer: "b".into(),
            repository: DEFAULT_REPO_NAME.into(),
            backup_ids: Some(vec![f.id]),
            mode: TransferMode::Copy,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        restore(descriptor_config(&f.b.descriptor, f.db()), f.id).await,
        f.payload
    );
}
