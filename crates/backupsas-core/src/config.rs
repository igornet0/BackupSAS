use crate::enrollment::EnrollmentSecret;
use crate::id::{RepositoryId, ServerId};
use crate::identity::Identity;
use crate::keys::{BackupEncryptionKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7420";
pub const DEFAULT_REPO_NAME: &str = "avrora-prod";
pub const DEFAULT_CHUNK_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server_id: ServerId,
    pub listen: String,
    pub data_dir: PathBuf,
    pub repositories: Vec<RepositoryConfig>,
}

impl ServerConfig {
    pub fn new(data_dir: PathBuf, listen: impl Into<String>, server_id: ServerId) -> Self {
        Self {
            server_id,
            listen: listen.into(),
            data_dir,
            repositories: vec![RepositoryConfig {
                id: RepositoryId::new(),
                name: DEFAULT_REPO_NAME.to_string(),
            }],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryConfig {
    pub id: RepositoryId,
    pub name: String,
}

/// Runtime client configuration. Private keys are not serializable.
pub struct BackupSasConfig {
    pub endpoint: String,
    pub server_id: ServerId,
    pub server_public_key: PublicKey,
    pub client_identity: Identity,
    pub repository: String,
    pub backup_encryption_key: BackupEncryptionKey,
    pub bootstrap_secret: Option<EnrollmentSecret>,
    pub ca_cert_path: Option<PathBuf>,
    pub server_name: String,
    pub chunk_size: u64,
}

impl BackupSasConfig {
    pub fn new(
        endpoint: impl Into<String>,
        server_id: ServerId,
        server_public_key: PublicKey,
        client_identity: Identity,
        repository: impl Into<String>,
        backup_encryption_key: BackupEncryptionKey,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            server_id,
            server_public_key,
            client_identity,
            repository: repository.into(),
            backup_encryption_key,
            bootstrap_secret: None,
            ca_cert_path: None,
            server_name: "localhost".into(),
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    pub fn with_bootstrap_secret(mut self, secret: EnrollmentSecret) -> Self {
        self.bootstrap_secret = Some(secret);
        self
    }

    pub fn with_ca_cert(mut self, path: PathBuf) -> Self {
        self.ca_cert_path = Some(path);
        self
    }

    pub fn with_chunk_size(mut self, size: u64) -> Self {
        self.chunk_size = size;
        self
    }
}

impl std::fmt::Debug for BackupSasConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupSasConfig")
            .field("endpoint", &self.endpoint)
            .field("server_id", &self.server_id)
            .field("server_public_key", &self.server_public_key)
            .field("client_identity", &self.client_identity.id)
            .field("repository", &self.repository)
            .finish_non_exhaustive()
    }
}
