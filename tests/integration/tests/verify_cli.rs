use backupsas_cli::verify::{VerifyOptions, any_invalid, format_all, run_verify};
use backupsas_client::BackupSasClient;
use backupsas_core::{CommitRecord, DatabaseId, Identity};
use backupsas_integration::harness::{
    boot_fresh_server, client_config, plaintext_three_chunks, repo_root,
};
use backupsas_server::load_config;
use backupsas_storage::{BackupRecord, StorageRoot, paths};
use std::io::Cursor;

async fn complete_backup(
    data_dir: &std::path::Path,
) -> (backupsas_core::BackupId, std::path::PathBuf) {
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
    let mut backup = session
        .create_backup(
            client.config(),
            DatabaseId::new(),
            Cursor::new(plaintext_three_chunks()),
        )
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

#[tokio::test]
async fn verify_cli_reports_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let (backup_id, _) = complete_backup(data_dir).await;

    let lines = run_verify(VerifyOptions {
        data_dir: data_dir.to_path_buf(),
        backup_id: Some(backup_id.to_string()),
        all: false,
        repository: None,
    })
    .unwrap();
    let out = format_all(&lines);
    assert!(out.contains("VALID"), "output:\n{out}");
    assert!(!out.contains("INVALID"));
    assert!(!any_invalid(&lines));
}

#[tokio::test]
async fn verify_cli_corrupt_chunk_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let (backup_id, path) = complete_backup(data_dir).await;

    std::fs::write(path.join("chunks").join("000001"), b"corrupted").unwrap();

    let lines = run_verify(VerifyOptions {
        data_dir: data_dir.to_path_buf(),
        backup_id: Some(backup_id.to_string()),
        all: false,
        repository: None,
    })
    .unwrap();
    let out = format_all(&lines);
    assert!(out.contains("INVALID"), "output:\n{out}");
    assert!(
        out.contains("chunk hash mismatch at sequence 1"),
        "output:\n{out}"
    );
    assert!(any_invalid(&lines));
}

#[tokio::test]
async fn verify_cli_bad_commit_root_is_invalid() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let (backup_id, path) = complete_backup(data_dir).await;

    let commit_path = path.join("commit.json");
    let mut commit: CommitRecord =
        serde_json::from_slice(&std::fs::read(&commit_path).unwrap()).unwrap();
    commit.root_hash = "blake3:deadbeef".into();
    std::fs::write(&commit_path, commit.to_vec_pretty().unwrap()).unwrap();

    let lines = run_verify(VerifyOptions {
        data_dir: data_dir.to_path_buf(),
        backup_id: Some(backup_id.to_string()),
        all: false,
        repository: None,
    })
    .unwrap();
    let out = format_all(&lines);
    assert!(out.contains("INVALID"), "output:\n{out}");
    assert!(out.contains("commit root mismatch"), "output:\n{out}");
    assert!(any_invalid(&lines));
}

#[tokio::test]
async fn verify_cli_all_flag_checks_repository() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let (backup_id, _) = complete_backup(data_dir).await;

    let lines = run_verify(VerifyOptions {
        data_dir: data_dir.to_path_buf(),
        backup_id: None,
        all: true,
        repository: Some("avrora-prod".into()),
    })
    .unwrap();
    let out = format_all(&lines);
    assert!(out.contains(&backup_id.to_string()), "output:\n{out}");
    assert!(out.contains("VALID"), "output:\n{out}");
}

#[tokio::test]
async fn full_pipeline_memory_source_then_verify_valid() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
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
    let mut source =
        backupsas_client::MemoryBackupSource::new(plaintext_three_chunks()).with_label("e2e");
    let mut backup = session
        .create_backup_from_source(client.config(), DatabaseId::new(), &mut source)
        .await
        .unwrap();
    backup.upload().await.unwrap();
    let outcome = backup.commit().await.unwrap();

    let lines = run_verify(VerifyOptions {
        data_dir: data_dir.to_path_buf(),
        backup_id: Some(outcome.backup_id.to_string()),
        all: false,
        repository: None,
    })
    .unwrap();
    let out = format_all(&lines);
    assert!(out.contains("VALID"), "output:\n{out}");

    let storage = StorageRoot::open(&load_config(data_dir).unwrap()).unwrap();
    match storage.find_backup(&outcome.backup_id).unwrap() {
        (_, BackupRecord::Complete { path, .. }) => {
            assert!(path.join("commit.json").exists());
            assert!(!paths::staging_dir(&repo_root(data_dir), &outcome.backup_id).exists());
        }
        _ => panic!("expected complete backup on disk"),
    }
}
