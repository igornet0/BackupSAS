use crate::descriptor::ConnectDescriptor;
use crate::enrollment::EnrollmentSecret;
use crate::id::{RepositoryId, ServerId};
use crate::identity::Identity;
use crate::keys::{BackupEncryptionKey, PublicKey};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:7420";
pub const DEFAULT_REPO_NAME: &str = "avrora-prod";
pub const DEFAULT_CHUNK_SIZE: u64 = 64 * 1024 * 1024;
/// Default idle time before an incomplete upload is garbage-collected (7 days),
/// long enough for interrupted uploads/transfers to be resumed.
pub const DEFAULT_STALE_UPLOAD_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server_id: ServerId,
    pub listen: String,
    pub data_dir: PathBuf,
    pub repositories: Vec<RepositoryConfig>,
    /// Externally reachable `host:port` addresses published in the connect
    /// descriptor. Falls back to `listen` when empty.
    #[serde(default)]
    pub public_endpoints: Vec<String>,
    /// Incomplete uploads idle longer than this are removed (startup + hourly).
    /// `None` = [`DEFAULT_STALE_UPLOAD_TTL_SECS`], `Some(0)` disables cleanup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_upload_ttl_secs: Option<u64>,
}

impl ServerConfig {
    pub fn stale_upload_ttl(&self) -> Option<std::time::Duration> {
        match self.stale_upload_ttl_secs {
            Some(0) => None,
            Some(s) => Some(std::time::Duration::from_secs(s)),
            None => Some(std::time::Duration::from_secs(
                DEFAULT_STALE_UPLOAD_TTL_SECS,
            )),
        }
    }
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
            public_endpoints: Vec::new(),
            stale_upload_ttl_secs: None,
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
    /// In-memory CA certificate (e.g. from a connect descriptor). Takes
    /// precedence over `ca_cert_path`.
    pub ca_cert_pem: Option<String>,
    pub server_name: String,
    pub chunk_size: u64,
    /// Recorded in manifests so the owner can pick the right key on restore.
    pub key_id: String,
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
            ca_cert_pem: None,
            server_name: "localhost".into(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            key_id: crate::format::DEFAULT_KEY_ID.to_string(),
        }
    }

    /// Build a client config from a verified connect descriptor.
    pub fn from_descriptor(
        descriptor: &ConnectDescriptor,
        client_identity: Identity,
        repository: impl Into<String>,
        backup_encryption_key: BackupEncryptionKey,
    ) -> crate::error::Result<Self> {
        descriptor.verify()?;
        let endpoint = descriptor.endpoints.first().cloned().ok_or_else(|| {
            crate::error::BackupSasError::Protocol("descriptor has no endpoints".into())
        })?;
        let mut cfg = Self::new(
            endpoint,
            descriptor.server_id,
            descriptor.public_key,
            client_identity,
            repository,
            backup_encryption_key,
        );
        cfg.server_name = descriptor.server_name.clone();
        cfg.ca_cert_pem = Some(descriptor.ca_cert_pem.clone());
        Ok(cfg)
    }

    pub fn with_ca_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = key_id.into();
        self
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
