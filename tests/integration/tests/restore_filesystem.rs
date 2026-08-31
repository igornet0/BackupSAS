use backupsas_client::{BackupSasClient, FileRestoreTarget, RestoreTarget};
use backupsas_core::BackupId;
use backupsas_integration::harness::{
    boot_existing_server, random_bytes, restore_client_config, upload_memory_source,
};
use std::fs;
use std::time::Duration;

#[tokio::test]
async fn filesystem_restore_e2e_byte_equality() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(512 * 1024);
    let (backup_id, _) = upload_memory_source(data_dir, source_data.clone()).await;

    let server = boot_existing_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();

    let target_path = tmp.path().join("restored.db");
    let mut target = FileRestoreTarget::new(&target_path, backup_id).unwrap();
    backup
        .restore_to(client.config(), &mut target)
        .await
        .unwrap();

    assert!(target.is_finalized());
    assert!(!target.temp_path().exists());
    assert_eq!(fs::read(&target_path).unwrap(), source_data);
}

#[tokio::test]
async fn filesystem_restore_replaces_existing_target_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(256 * 1024);
    let (backup_id, _) = upload_memory_source(data_dir, source_data.clone()).await;

    let target_path = tmp.path().join("production.db");
    fs::write(&target_path, b"old-production-bytes").unwrap();
    let original = fs::read(&target_path).unwrap();

    let server = boot_existing_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = FileRestoreTarget::new(&target_path, backup_id).unwrap();
    backup
        .restore_to(client.config(), &mut target)
        .await
        .unwrap();

    assert!(target.is_finalized());
    assert_eq!(fs::read(&target_path).unwrap(), source_data);
    assert_ne!(fs::read(&target_path).unwrap(), original);
}

#[tokio::test]
async fn filesystem_restore_connection_loss_leaves_target_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(4 * 1024 * 1024);
    let (backup_id, backup_path) = upload_memory_source(data_dir, source_data).await;

    let target_path = tmp.path().join("production.db");
    fs::write(&target_path, b"unchanged").unwrap();

    let server = boot_existing_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = FileRestoreTarget::new(&target_path, backup_id).unwrap();
    let temp_path = target.temp_path().to_path_buf();

    let restore = backup.restore_to(client.config(), &mut target);
    let sabotage = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = fs::remove_dir_all(backup_path.join("chunks"));
    };
    let (restore_result, _) = tokio::join!(restore, sabotage);
    assert!(restore_result.is_err());
    assert!(!target.is_finalized());
    assert!(!temp_path.exists());
    assert_eq!(fs::read(&target_path).unwrap(), b"unchanged");
}

#[tokio::test]
async fn filesystem_restore_interrupted_before_finalize() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(256 * 1024);
    let (backup_id, backup_path) = upload_memory_source(data_dir, source_data).await;

    fs::write(backup_path.join("chunks").join("000002"), b"corrupted").unwrap();

    let target_path = tmp.path().join("production.db");
    fs::write(&target_path, b"original").unwrap();
    let temp_path = format!("{}.restore-{}.tmp", target_path.display(), backup_id);

    let server = boot_existing_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = FileRestoreTarget::new(&target_path, backup_id).unwrap();
    assert!(
        backup
            .restore_to(client.config(), &mut target)
            .await
            .is_err()
    );

    assert!(!target.is_finalized());
    assert!(!std::path::Path::new(&temp_path).exists());
    assert_eq!(fs::read(&target_path).unwrap(), b"original");
}

#[cfg(unix)]
#[tokio::test]
async fn filesystem_restore_target_write_failure() {
    use backupsas_core::{BackupSasError, Result};

    struct FailingTarget {
        inner: FileRestoreTarget,
        fail_on_next: bool,
    }

    impl RestoreTarget for FailingTarget {
        fn metadata(&mut self, metadata: &backupsas_client::RestoreMetadata) -> Result<()> {
            self.inner.metadata(metadata)
        }

        fn write_range(&mut self, offset: u64, data: &[u8]) -> Result<()> {
            if self.fail_on_next {
                return Err(BackupSasError::Io(std::io::Error::other(
                    "simulated target write failure",
                )));
            }
            self.fail_on_next = true;
            self.inner.write_range(offset, data)
        }

        fn finalize(&mut self) -> Result<()> {
            self.inner.finalize()
        }

        fn abort(&mut self) -> Result<()> {
            self.inner.abort()
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();
    let source_data = random_bytes(128 * 1024);
    let (backup_id, _) = upload_memory_source(data_dir, source_data).await;

    let target_path = tmp.path().join("production.db");
    fs::write(&target_path, b"original").unwrap();

    let server = boot_existing_server(data_dir).await;
    let config = restore_client_config(server.addr, data_dir, &server);
    let client = BackupSasClient::connect(config).await.unwrap();
    let mut session = client.authenticate().await.unwrap();
    let mut backup = session.open_backup(backup_id).await.unwrap();
    let mut target = FailingTarget {
        inner: FileRestoreTarget::new(&target_path, backup_id).unwrap(),
        fail_on_next: false,
    };
    assert!(
        backup
            .restore_to(client.config(), &mut target)
            .await
            .is_err()
    );

    assert!(!target.inner.is_finalized());
    assert!(!target.inner.temp_path().exists());
    assert_eq!(fs::read(&target_path).unwrap(), b"original");
}

#[cfg(unix)]
#[tokio::test]
async fn filesystem_restore_disk_full_on_write() {
    let tmp = tempfile::tempdir().unwrap();
    let restore_dir = tmp.path().join("restore-dir");
    fs::create_dir_all(&restore_dir).unwrap();
    let target_path = restore_dir.join("production.db");
    fs::write(&target_path, b"original").unwrap();

    let backup_id = BackupId::new();
    let mut perms = fs::metadata(&restore_dir).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&restore_dir, perms).unwrap();

    let mut target = FileRestoreTarget::new(&target_path, backup_id).unwrap();
    let err = target
        .metadata(&backupsas_client::RestoreMetadata {
            backup_id: Some(backup_id),
            total_size: 256 * 1024,
            ..Default::default()
        })
        .unwrap_err();
    assert!(err.to_string().contains("Permission denied") || err.to_string().contains("Read-only"));
    target.abort().unwrap();

    assert!(!target.is_finalized());
    assert!(!target.temp_path().exists());
    assert_eq!(fs::read(&target_path).unwrap(), b"original");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&restore_dir).unwrap().permissions();
        perms.set_mode(0o755);
        let _ = fs::set_permissions(&restore_dir, perms);
    }
}
