use crate::authentication::{AuthenticatedSession, authenticate};
use backupsas_core::{BackupSasConfig, Result};

/// High-level BackupSAS SDK entry point.
///
/// Avrora (or any DBMS) connects, authenticates, and uploads backups
/// without implementing TLS, handshake, or chunking itself.
pub struct BackupSasClient {
    config: BackupSasConfig,
}

impl BackupSasClient {
    pub fn new(config: BackupSasConfig) -> Self {
        Self { config }
    }

    pub async fn connect(config: BackupSasConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub fn config(&self) -> &BackupSasConfig {
        &self.config
    }

    pub async fn authenticate(&self) -> Result<AuthenticatedSession> {
        authenticate(&self.config).await
    }
}
