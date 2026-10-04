//! Files written by the previous release must still load after the
//! Avrora-integration changes (new fields are all `serde(default)`).

use backupsas_core::{
    ClientId, EnrollmentRecord, EnrollmentSecret, Identity, PeerKind, RemoteBackupInfo, ServerId,
};
use backupsas_server::relocations::RelocationRecord;
use backupsas_server::trust::TrustStore;
use backupsas_storage::UploadSession;
use std::fs;

#[test]
fn old_trusted_peer_toml_defaults_to_database_without_delegation() {
    let dir = tempfile::tempdir().unwrap();
    let identity = Identity::generate_client();
    let backupsas_core::ParticipantId::Client(id) = identity.id else {
        unreachable!()
    };
    let old = format!(
        "id = \"{id}\"\npublic_key = \"{}\"\nfingerprint = \"{}\"\nrepositories = [\"avrora-prod\"]\nenrolled_at = \"2026-01-01T00:00:00Z\"\n",
        identity.public_key,
        identity.fingerprint()
    );
    fs::write(dir.path().join(format!("{id}.toml")), old).unwrap();
    let store = TrustStore::load(dir.path()).unwrap();
    let peer = store.get(&id).unwrap();
    assert_eq!(peer.kind, PeerKind::Database);
    assert!(peer.delegated_by.is_none());
}

#[test]
fn old_enrollment_secret_file_is_database_kind() {
    let dir = tempfile::tempdir().unwrap();
    let secret = EnrollmentSecret::generate();
    let path = dir.path().join("enrollment.secret");
    fs::write(&path, format!("secret_hash = \"{}\"\n", secret.hash())).unwrap();
    let rec = EnrollmentRecord::load(&path).unwrap();
    assert!(rec.matches(&secret));
    assert_eq!(rec.kind, PeerKind::Database);
}

#[test]
fn old_server_toml_loads_with_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let old = format!(
        "server_id = \"{}\"\nlisten = \"127.0.0.1:7420\"\ndata_dir = \"/x\"\n\n[[repositories]]\nid = \"repo_01ARZ3NDEKTSV4RRFFQ69G5FAV\"\nname = \"avrora-prod\"\n",
        ServerId::new()
    );
    fs::write(dir.path().join("server.toml"), old).unwrap();
    let cfg = backupsas_server::load_config(dir.path()).unwrap();
    assert!(cfg.public_endpoints.is_empty());
    assert_eq!(
        cfg.stale_upload_ttl(),
        Some(std::time::Duration::from_secs(
            backupsas_core::DEFAULT_STALE_UPLOAD_TTL_SECS
        ))
    );
}

#[test]
fn old_json_records_load() {
    let info: RemoteBackupInfo = serde_json::from_str(
        r#"{"backup_id":"bkp_1","database_id":"db_1","repository":"r","state":"COMPLETE","total_size":1,"chunk_count":1}"#,
    )
    .unwrap();
    assert!(info.manifest_hash.is_empty() && !info.relocated);

    let session: UploadSession = serde_json::from_str(&format!(
        r#"{{"backup_id":"bkp_01ARZ3NDEKTSV4RRFFQ69G5FAV","database_id":"db_01ARZ3NDEKTSV4RRFFQ69G5FAV","client_id":"{}","repository":"r","state":"UPLOADING","created_at":"2026-01-01T00:00:00Z","total_size":1,"chunk_size":1,"chunk_count":1,"next_sequence":0,"has_manifest":true,"verified":false}}"#,
        ClientId::new()
    ))
    .unwrap();
    assert_eq!(session.last_activity_or_created(), session.created_at);
}

#[test]
fn relocation_record_without_cleaned_flag_loads() {
    let a = Identity::generate_server();
    let b = Identity::generate_server();
    let (backupsas_core::ParticipantId::Server(a_id), backupsas_core::ParticipantId::Server(b_id)) =
        (a.id, b.id)
    else {
        unreachable!()
    };
    let target = backupsas_core::ConnectDescriptor::new(
        b_id,
        b.public_key,
        vec!["b:1".into()],
        "localhost",
        "pem",
        vec!["r".into()],
        vec![],
    )
    .sign(&b)
    .unwrap();
    let notice = backupsas_core::RelocationNotice {
        relocation_id: "rel_1".into(),
        mode: backupsas_core::TransferMode::Move,
        source_server_id: a_id,
        owner_client_id: ClientId::new(),
        repository: "r".into(),
        backup_ids: vec![],
        target,
        target_repository: "r".into(),
        created_at: 1,
        signature: String::new(),
    }
    .sign(&a)
    .unwrap();
    let mut v = serde_json::json!({ "notice": notice, "acked": true, "acked_at": 5 });
    v.as_object_mut().unwrap().remove("cleaned");
    let rec: RelocationRecord = serde_json::from_value(v).unwrap();
    assert!(
        rec.acked && !rec.cleaned,
        "pre-upgrade acked records get cleaned on startup"
    );
}
