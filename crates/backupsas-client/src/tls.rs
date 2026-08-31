use backupsas_core::{BackupSasError, Result};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| BackupSasError::Path {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| BackupSasError::Tls(format!("certs {}: {e}", path.display())))
}

pub fn load_client_tls(ca_cert: &Path) -> Result<ClientConfig> {
    install_crypto_provider();
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_cert)? {
        roots
            .add(cert)
            .map_err(|e| BackupSasError::Tls(format!("add CA: {e}")))?;
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub async fn connect(
    addr: &str,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>> {
    let stream = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(config);
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| BackupSasError::Tls(format!("server name: {e}")))?;
    connector
        .connect(name, stream)
        .await
        .map_err(|e| BackupSasError::Tls(format!("connect: {e}")))
}
