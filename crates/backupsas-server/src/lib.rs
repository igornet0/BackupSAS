//! BackupSAS TLS server: identity auth, enrollment, and storage.

pub mod peers;
pub mod relocations;
pub mod session;
pub mod tls;
pub mod transfer;
pub mod trust;

use backupsas_core::{
    ConnectDescriptor, EnrollmentRecord, EnrollmentSecret, Identity, PeerKind, Result, ServerConfig,
};
use backupsas_storage::StorageRoot;
use relocations::RelocationStore;
use rustls::ServerConfig as TlsServerConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use trust::TrustStore;

#[derive(Clone)]
pub struct ServerState {
    pub config: Arc<ServerConfig>,
    pub storage: Arc<StorageRoot>,
    pub tls: Arc<TlsServerConfig>,
    pub identity: Arc<Identity>,
    pub trust: Arc<Mutex<TrustStore>>,
    pub relocations: Arc<RelocationStore>,
}

impl ServerState {
    pub fn from_config(config: ServerConfig) -> Result<Self> {
        tls::install_crypto_provider();
        let tls = tls::load_server_config(&config.data_dir)?;
        let storage = StorageRoot::open(&config)?;
        let identity = Identity::load(&config.data_dir.join("identity"))?;
        let trust = TrustStore::load(&config.data_dir.join("trusted"))?;
        let relocations = RelocationStore::open(&config.data_dir)?;
        cleanup_stale_uploads(&config, &storage);
        // Crash recovery: finish deleting moved copies whose ack was recorded.
        for id in relocations.finish_cleanups(&storage)? {
            info!(relocation_id = %id, "completed relocation cleanup after restart");
        }
        Ok(Self {
            relocations: Arc::new(relocations),
            config: Arc::new(config),
            storage: Arc::new(storage),
            tls: Arc::new(tls),
            identity: Arc::new(identity),
            trust: Arc::new(Mutex::new(trust)),
        })
    }
}

pub struct InitResult {
    pub config: ServerConfig,
    pub enrollment_secret: EnrollmentSecret,
    pub public_key: backupsas_core::PublicKey,
    pub fingerprint: backupsas_core::Fingerprint,
    pub descriptor: ConnectDescriptor,
}

pub const CONNECT_FILE: &str = "connect.json";

pub async fn bind(listen: &str) -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

/// Remove incomplete uploads idle longer than the configured TTL.
fn cleanup_stale_uploads(config: &ServerConfig, storage: &StorageRoot) {
    let Some(ttl) = config.stale_upload_ttl() else {
        return;
    };
    match storage.cleanup_stale_uploads(ttl) {
        Ok(removed) => {
            for (repo, id) in removed {
                info!(%repo, backup_id = %id, "removed stale incomplete upload");
            }
        }
        Err(e) => warn!(error = %e, "stale upload cleanup failed"),
    }
}

const MAINTENANCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

pub async fn serve(listener: TcpListener, state: ServerState) -> Result<()> {
    let maintenance = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(MAINTENANCE_INTERVAL);
        tick.tick().await; // startup cleanup already ran in `from_config`
        loop {
            tick.tick().await;
            let s = maintenance.clone();
            let _ =
                tokio::task::spawn_blocking(move || cleanup_stale_uploads(&s.config, &s.storage))
                    .await;
        }
    });
    let acceptor = TlsAcceptor::from(state.tls.clone());
    info!(addr = %listener.local_addr()?, "BackupSAS listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, peer, acceptor, state).await {
                warn!(%peer, error = %err, "connection closed with error");
            }
        });
    }
}

pub async fn run(config: ServerConfig) -> Result<()> {
    let state = ServerState::from_config(config.clone())?;
    let (listener, addr) = bind(&config.listen).await?;
    info!(
        server_id = %config.server_id,
        %addr,
        "BackupSAS server started"
    );
    serve(listener, state).await
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    state: ServerState,
) -> Result<()> {
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|e| backupsas_core::BackupSasError::Tls(format!("handshake with {peer}: {e}")))?;
    session::run_session(tls, state).await
}

pub fn init_data_dir(data_dir: &Path, listen: &str) -> Result<InitResult> {
    tls::install_crypto_provider();
    std::fs::create_dir_all(data_dir)?;
    std::fs::create_dir_all(data_dir.join("trusted"))?;
    std::fs::create_dir_all(data_dir.join("tls"))?;
    std::fs::create_dir_all(data_dir.join("repositories"))?;
    std::fs::create_dir_all(data_dir.join("identity"))?;

    tls::generate_dev_certs(data_dir)?;
    let identity = Identity::generate_server();
    identity.save(&data_dir.join("identity"))?;

    let enrollment_secret = EnrollmentSecret::generate();
    EnrollmentRecord::from_secret(&enrollment_secret).save(&data_dir.join("enrollment.secret"))?;

    let backupsas_core::ParticipantId::Server(server_id) = identity.id else {
        return Err(backupsas_core::BackupSasError::Other(
            "generated identity is not a server".into(),
        ));
    };
    let config = ServerConfig::new(data_dir.to_path_buf(), listen, server_id);
    let toml = toml::to_string_pretty(&config)
        .map_err(|e| backupsas_core::BackupSasError::Serde(e.to_string()))?;
    std::fs::write(data_dir.join("server.toml"), toml)?;
    StorageRoot::open(&config)?;
    let descriptor = build_descriptor(&config, &identity)?;
    descriptor.save(&data_dir.join(CONNECT_FILE))?;

    Ok(InitResult {
        public_key: identity.public_key,
        fingerprint: identity.fingerprint(),
        enrollment_secret,
        config,
        descriptor,
    })
}

pub fn save_config(config: &ServerConfig) -> Result<()> {
    let toml = toml::to_string_pretty(config)
        .map_err(|e| backupsas_core::BackupSasError::Serde(e.to_string()))?;
    std::fs::write(config.data_dir.join("server.toml"), toml)?;
    Ok(())
}

/// Build and sign the public connect descriptor for this node.
pub fn build_descriptor(config: &ServerConfig, identity: &Identity) -> Result<ConnectDescriptor> {
    let ca_cert_pem = std::fs::read_to_string(config.data_dir.join("tls").join("ca.crt"))?;
    let endpoints = if config.public_endpoints.is_empty() {
        vec![config.listen.clone()]
    } else {
        config.public_endpoints.clone()
    };
    ConnectDescriptor::new(
        config.server_id,
        identity.public_key,
        endpoints,
        tls::SERVER_NAME,
        ca_cert_pem,
        config.repositories.iter().map(|r| r.name.clone()).collect(),
        backupsas_protocol::feature_names(backupsas_protocol::FEATURES_V2),
    )
    .sign(identity)
}

/// Load identity from `data_dir` and write a fresh `connect.json`.
pub fn refresh_descriptor(config: &ServerConfig) -> Result<ConnectDescriptor> {
    let identity = Identity::load(&config.data_dir.join("identity"))?;
    let descriptor = build_descriptor(config, &identity)?;
    descriptor.save(&config.data_dir.join(CONNECT_FILE))?;
    Ok(descriptor)
}

/// Issue a new one-time enrollment secret, replacing any unused one.
pub fn issue_enrollment_secret(data_dir: &Path, kind: PeerKind) -> Result<EnrollmentSecret> {
    let secret = EnrollmentSecret::generate();
    EnrollmentRecord::from_secret(&secret)
        .with_kind(kind)
        .save(&enrollment_path(data_dir))?;
    Ok(secret)
}

pub fn load_config(data_dir: &Path) -> Result<ServerConfig> {
    let path = data_dir.join("server.toml");
    let text = std::fs::read_to_string(&path)?;
    let mut config: ServerConfig =
        toml::from_str(&text).map_err(|e| backupsas_core::BackupSasError::Serde(e.to_string()))?;
    config.data_dir = data_dir.to_path_buf();
    Ok(config)
}

pub fn enrollment_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("enrollment.secret")
}
