use crate::tls;
use backupsas_core::{BackupSasConfig, Result};
use backupsas_protocol::{read_frame, write_frame, Message};
use rustls::ClientConfig;
use std::sync::Arc;
use tokio::io::{split, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

pub struct Connection {
    pub reader: ReadHalf<TlsStream<TcpStream>>,
    pub writer: WriteHalf<TlsStream<TcpStream>>,
}

impl Connection {
    pub async fn connect(config: &BackupSasConfig) -> Result<Self> {
        let ca = config.ca_cert_path.as_ref().ok_or_else(|| {
            backupsas_core::BackupSasError::Tls("ca_cert_path is required for TLS transport".into())
        })?;
        let tls_cfg = Arc::new(tls::load_client_tls(ca)?);
        Self::connect_with_tls(config, tls_cfg).await
    }

    pub async fn connect_with_tls(
        config: &BackupSasConfig,
        tls_cfg: Arc<ClientConfig>,
    ) -> Result<Self> {
        let stream = tls::connect(&config.endpoint, &config.server_name, tls_cfg).await?;
        let (reader, writer) = split(stream);
        Ok(Self { reader, writer })
    }

    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        write_frame(&mut self.writer, msg).await
    }

    pub async fn recv(&mut self) -> Result<Message> {
        read_frame(&mut self.reader).await
    }
}
