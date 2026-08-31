//! BackupSAS TLS server: identity auth, enrollment, and storage.

pub mod session;
pub mod tls;
pub mod trust;

use backupsas_core::{EnrollmentRecord, EnrollmentSecret, Identity, Result, ServerConfig};
use backupsas_storage::StorageRoot;
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
}

impl ServerState {
    pub fn from_config(config: ServerConfig) -> Result<Self> {
        tls::install_crypto_provider();
        let tls = tls::load_server_config(&config.data_dir)?;
        let storage = StorageRoot::open(&config)?;
        let identity = Identity::load(&config.data_dir.join("identity"))?;
        let trust = TrustStore::load(&config.data_dir.join("trusted"))?;
        Ok(Self {
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
}

pub async fn bind(listen: &str) -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    Ok((listener, addr))
}

pub async fn serve(listener: TcpListener, state: ServerState) -> Result<()> {
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

    Ok(InitResult {
        public_key: identity.public_key,
        fingerprint: identity.fingerprint(),
        enrollment_secret,
        config,
    })
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
