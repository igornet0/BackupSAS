use backupsas_core::{BackupSasError, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

pub const SERVER_NAME: &str = "localhost";

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct CertBundle {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

pub fn generate_dev_certs(data_dir: &Path) -> Result<CertBundle> {
    let tls_dir = data_dir.join("tls");
    fs::create_dir_all(&tls_dir)?;

    let ca_key = KeyPair::generate().map_err(rcgen_err)?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "BackupSAS Transport CA");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key).map_err(rcgen_err)?;
    let ca_key_pem = ca_key.serialize_pem();

    let server_key = KeyPair::generate().map_err(rcgen_err)?;
    let mut server_params = CertificateParams::new(vec![
        "localhost".to_string(),
        "backupsas.local".to_string(),
    ])
    .map_err(rcgen_err)?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, "BackupSAS Transport");
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().map_err(rcgen_err)?),
        SanType::DnsName("backupsas.local".try_into().map_err(rcgen_err)?),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(rcgen_err)?;

    let bundle = CertBundle {
        ca_cert_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
    };

    fs::write(tls_dir.join("ca.crt"), &bundle.ca_cert_pem)?;
    fs::write(tls_dir.join("ca.key"), ca_key_pem)?;
    fs::write(tls_dir.join("server.crt"), &bundle.server_cert_pem)?;
    fs::write(tls_dir.join("server.key"), &bundle.server_key_pem)?;
    Ok(bundle)
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = fs::File::open(path).map_err(|e| BackupSasError::Path {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| BackupSasError::Tls(format!("read certs {}: {e}", path.display())))
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = fs::File::open(path).map_err(|e| BackupSasError::Path {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| BackupSasError::Tls(format!("read key {}: {e}", path.display())))?
        .ok_or_else(|| BackupSasError::Tls(format!("no private key in {}", path.display())))
}

pub fn load_server_config(data_dir: &Path) -> Result<ServerConfig> {
    let tls_dir = data_dir.join("tls");
    let server_certs = load_certs(&tls_dir.join("server.crt"))?;
    let server_key = load_key(&tls_dir.join("server.key"))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(server_certs, server_key)
        .map_err(|e| BackupSasError::Tls(format!("server cert: {e}")))?;
    Ok(config)
}

fn rcgen_err(err: impl std::fmt::Display) -> BackupSasError {
    BackupSasError::Tls(err.to_string())
}
