use anyhow::{Context, Result};
use backupsas_cli::verify::{VerifyOptions, any_invalid, format_all, run_verify};
use backupsas_core::{
    BackupId, ClientId, ConnectDescriptor, DEFAULT_LISTEN, EnrollmentSecret, Identity, PeerKind,
    TransferMode,
};
use backupsas_server::peers::{PeerStore, add_peer};
use backupsas_server::relocations::RelocationStore;
use backupsas_server::tls;
use backupsas_server::transfer::{TransferRequest, run_transfer};
use backupsas_server::trust::TrustStore;
use backupsas_server::{ServerState, init_data_dir, load_config, run};
use backupsas_storage::{BackupRecord, StorageRoot};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "backupsas",
    about = "BackupSAS storage daemon and identity SDK"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create identity, enrollment secret, and TLS transport material
    Init {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        #[arg(long, default_value = DEFAULT_LISTEN)]
        listen: String,
    },
    /// Run the BackupSAS server
    Start {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
    },
    /// Show identity, trusted clients, and backup states
    Status {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        #[arg(long)]
        backup_id: Option<String>,
    },
    /// Manage trusted client identities
    Trust {
        #[command(subcommand)]
        command: TrustCmd,
    },
    /// Verify backup cryptographic integrity (manifest, chunks, commit)
    Verify {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        #[arg(long)]
        backup_id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        repository: Option<String>,
    },
    /// Print (and refresh) the public connect descriptor JSON for Avrora / peers
    ConnectInfo {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        /// Externally reachable host:port (repeatable); persisted to server.toml
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
        /// Also write the descriptor to this file
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Issue a new one-time enrollment secret
    EnrollSecret {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        /// `database` for Avrora, `node` for another BackupSAS node
        #[arg(long, default_value = "database")]
        kind: String,
    },
    /// Manage outgoing links to other BackupSAS nodes
    Peer {
        #[command(subcommand)]
        command: PeerCmd,
    },
    /// Move or copy encrypted backups to a peer node
    Transfer {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        /// Peer name (see `backupsas peer list`)
        #[arg(long)]
        to: String,
        #[arg(long, default_value = backupsas_core::DEFAULT_REPO_NAME)]
        repository: String,
        /// Backup ids (repeatable); omit to transfer every complete backup
        #[arg(long = "backup-id")]
        backup_ids: Vec<String>,
        /// `move` or `copy`
        #[arg(long, default_value = "copy")]
        mode: String,
    },
    /// List relocation notices produced by transfers
    Relocations {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
    },
    /// Development helpers
    Dev {
        #[command(subcommand)]
        command: DevCmd,
    },
}

#[derive(Subcommand)]
enum PeerCmd {
    /// Enroll this node on a peer using its connect JSON and a `node` secret
    Add {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        #[arg(long)]
        name: String,
        /// Peer connect descriptor (from `backupsas connect-info` on the peer)
        #[arg(long)]
        connect: PathBuf,
        /// One-time secret from `backupsas enroll-secret --kind node` on the peer
        /// (`-` reads it from stdin)
        #[arg(long)]
        secret: String,
        #[arg(long, default_value = backupsas_core::DEFAULT_REPO_NAME)]
        repository: String,
    },
    List {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
    },
    Remove {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        name: String,
    },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// List enrolled Ed25519 clients
    Show {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
    },
    /// Revoke a trusted client
    Revoke {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
        id: String,
    },
}

#[derive(Subcommand)]
enum DevCmd {
    /// Generate TLS transport certificates (not BackupSAS identity)
    GenCerts {
        #[arg(long, default_value = "/var/lib/backupsas")]
        data_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("backupsas=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    let code = match cli.command {
        Commands::Init { data_dir, listen } => run_cmd(cmd_init(data_dir, listen)),
        Commands::Start { data_dir } => run_cmd(cmd_start(data_dir).await),
        Commands::Status {
            data_dir,
            backup_id,
        } => run_cmd(cmd_status(data_dir, backup_id)),
        Commands::Verify {
            data_dir,
            backup_id,
            all,
            repository,
        } => run_cmd(cmd_verify(data_dir, backup_id, all, repository)),
        Commands::Trust {
            command: TrustCmd::Show { data_dir },
        } => run_cmd(cmd_trust_show(data_dir)),
        Commands::Trust {
            command: TrustCmd::Revoke { data_dir, id },
        } => run_cmd(cmd_trust_revoke(data_dir, id)),
        Commands::ConnectInfo {
            data_dir,
            endpoints,
            out,
        } => run_cmd(cmd_connect_info(data_dir, endpoints, out)),
        Commands::EnrollSecret { data_dir, kind } => run_cmd(cmd_enroll_secret(data_dir, kind)),
        Commands::Peer { command } => run_cmd(cmd_peer(command).await),
        Commands::Transfer {
            data_dir,
            to,
            repository,
            backup_ids,
            mode,
        } => run_cmd(cmd_transfer(data_dir, to, repository, backup_ids, mode).await),
        Commands::Relocations { data_dir } => run_cmd(cmd_relocations(data_dir)),
        Commands::Dev {
            command: DevCmd::GenCerts { data_dir },
        } => run_cmd(cmd_gen_certs(data_dir)),
    };
    ExitCode::from(code)
}

fn run_cmd(result: Result<()>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e:#}");
            1
        }
    }
}

fn cmd_init(data_dir: PathBuf, listen: String) -> Result<()> {
    let result = init_data_dir(&data_dir, &listen)?;
    println!("BackupSAS Server");
    println!("    Server ID:     {}", result.config.server_id);
    println!("    Public Key:    {}", result.public_key);
    println!("    Fingerprint:   {}", result.fingerprint);
    println!("    Listen:        {}", result.config.listen);
    println!("    Data dir:      {}", data_dir.display());
    println!();
    println!("Enrollment secret (one-time, store it now):");
    println!("    {}", result.enrollment_secret.as_str());
    println!();
    println!(
        "Connect JSON written to {}/{}",
        data_dir.display(),
        backupsas_server::CONNECT_FILE
    );
    println!(
        "Import it in Avrora:  avrora backup target add --connect connect.json --secret <secret>"
    );
    println!("Publish an external address with `backupsas connect-info --endpoint host:port`.");
    println!("The enrollment secret is consumed after the first successful enroll.");
    Ok(())
}

fn cmd_connect_info(data_dir: PathBuf, endpoints: Vec<String>, out: Option<PathBuf>) -> Result<()> {
    let mut config = load_config(&data_dir)?;
    if !endpoints.is_empty() {
        config.public_endpoints = endpoints;
        backupsas_server::save_config(&config)?;
    }
    let descriptor = backupsas_server::refresh_descriptor(&config)?;
    let json = descriptor.to_json_pretty()?;
    if let Some(path) = out {
        std::fs::write(&path, &json)?;
        eprintln!("wrote {}", path.display());
    }
    println!("{json}");
    Ok(())
}

fn cmd_enroll_secret(data_dir: PathBuf, kind: String) -> Result<()> {
    let kind = PeerKind::parse(&kind)?;
    let secret = backupsas_server::issue_enrollment_secret(&data_dir, kind)?;
    println!("Enrollment secret ({}, one-time):", kind.as_str());
    println!("    {}", secret.as_str());
    Ok(())
}

async fn cmd_peer(command: PeerCmd) -> Result<()> {
    match command {
        PeerCmd::Add {
            data_dir,
            name,
            connect,
            secret,
            repository,
        } => {
            let descriptor = ConnectDescriptor::load(&connect)?;
            // `-` reads the secret from stdin so it stays out of argv/history.
            let secret = if secret == "-" {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line.trim().to_string()
            } else {
                secret
            };
            let secret = EnrollmentSecret::parse(secret)?;
            let record = add_peer(&data_dir, &name, descriptor, &repository, secret).await?;
            println!(
                "Peer `{}` added: {} {} repo={}",
                record.name,
                record.descriptor.server_id,
                record.descriptor.fingerprint,
                record.repository
            );
        }
        PeerCmd::List { data_dir } => {
            let peers = PeerStore::open(&data_dir)?.list()?;
            if peers.is_empty() {
                println!("No peers.");
            }
            for p in peers {
                println!(
                    "{}  {}  {}  repo={}  endpoints={}",
                    p.name,
                    p.descriptor.server_id,
                    p.descriptor.fingerprint,
                    p.repository,
                    p.descriptor.endpoints.join(",")
                );
            }
        }
        PeerCmd::Remove { data_dir, name } => {
            if PeerStore::open(&data_dir)?.remove(&name)? {
                println!("Removed peer {name}");
            } else {
                println!("Peer {name} not found");
            }
        }
    }
    Ok(())
}

async fn cmd_transfer(
    data_dir: PathBuf,
    to: String,
    repository: String,
    backup_ids: Vec<String>,
    mode: String,
) -> Result<()> {
    let config = load_config(&data_dir)?;
    let ids = if backup_ids.is_empty() {
        None
    } else {
        Some(
            backup_ids
                .iter()
                .map(|s| s.parse::<BackupId>())
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )
    };
    let report = run_transfer(
        &config,
        &TransferRequest {
            peer: to.clone(),
            repository,
            backup_ids: ids,
            mode: mode.parse::<TransferMode>()?,
        },
    )
    .await?;
    println!(
        "Transferred {} backup(s) to `{to}` ({mode})",
        report.transferred.len()
    );
    for n in &report.notices {
        println!(
            "    relocation {}  owner={}  backups={}",
            n.relocation_id,
            n.owner_client_id,
            n.backup_ids.len()
        );
    }
    if mode == "move" {
        println!("Local copies are deleted after the owning database acknowledges the move.");
    }
    Ok(())
}

fn cmd_relocations(data_dir: PathBuf) -> Result<()> {
    let records = RelocationStore::open(&data_dir)?.list()?;
    if records.is_empty() {
        println!("No relocations.");
    }
    for r in records {
        println!(
            "{}  {}  owner={}  -> {} ({})  backups={}  {}",
            r.notice.relocation_id,
            r.notice.mode,
            r.notice.owner_client_id,
            r.notice.target.server_id,
            r.notice.target_repository,
            r.notice.backup_ids.len(),
            if r.acked { "acked" } else { "pending" }
        );
    }
    Ok(())
}

async fn cmd_start(data_dir: PathBuf) -> Result<()> {
    let config = load_config(&data_dir).with_context(|| {
        format!(
            "failed to load {}/server.toml (run `backupsas init` first)",
            data_dir.display()
        )
    })?;
    let _ = ServerState::from_config(config.clone())?;
    run(config).await?;
    Ok(())
}

fn cmd_status(data_dir: PathBuf, backup_id: Option<String>) -> Result<()> {
    let config = load_config(&data_dir)?;
    let identity = Identity::load(&data_dir.join("identity"))?;
    println!("BackupSAS Server");
    println!("    ID:            {}", config.server_id);
    println!("    Public Key:    {}", identity.public_key);
    println!("    Fingerprint:   {}", identity.fingerprint());
    println!("    Listen:        {}", config.listen);
    println!("    Data dir:      {}", data_dir.display());

    let trust = TrustStore::load(&data_dir.join("trusted"))?;
    let peers = trust.list();
    println!("    Trusted clients: {}", peers.len());
    for peer in &peers {
        println!(
            "      {}  {}  repos={}",
            peer.id,
            peer.fingerprint,
            peer.repositories.join(",")
        );
    }

    let storage = StorageRoot::open(&config)?;
    if let Some(id) = backup_id {
        let id: BackupId = id.parse()?;
        let (repo, record) = storage.find_backup(&id)?;
        print_record(repo.name(), &record);
        return Ok(());
    }

    let records = storage.list_all()?;
    if records.is_empty() {
        println!("    No backups.");
        return Ok(());
    }
    println!("    Backups:");
    for (repo, record) in records {
        print_record(&repo, &record);
    }
    Ok(())
}

fn print_record(repo: &str, record: &BackupRecord) {
    match record {
        BackupRecord::Uploading(s) => {
            println!(
                "      {}  {}  {}  chunks {}/{}",
                s.backup_id, s.state, repo, s.next_sequence, s.chunk_count
            );
        }
        BackupRecord::Complete { metadata, path } => {
            println!(
                "      {}  COMPLETE  {}  {}  {}",
                metadata.backup_id,
                repo,
                metadata.chunk_count,
                path.display()
            );
        }
    }
}

fn cmd_trust_show(data_dir: PathBuf) -> Result<()> {
    let trust = TrustStore::load(&data_dir.join("trusted"))?;
    let peers = trust.list();
    if peers.is_empty() {
        println!("No trusted clients.");
        return Ok(());
    }
    for peer in peers {
        println!("{}  {}", peer.id, peer.public_key);
        println!("    fingerprint: {}", peer.fingerprint);
        println!("    repos:       {}", peer.repositories.join(", "));
        println!("    kind:        {}", peer.kind.as_str());
        if let Some(by) = &peer.delegated_by {
            println!("    delegated:   by {by}");
        }
        println!("    enrolled:    {}", peer.enrolled_at);
    }
    Ok(())
}

fn cmd_trust_revoke(data_dir: PathBuf, id: String) -> Result<()> {
    let id: ClientId = id.parse()?;
    let mut trust = TrustStore::load(&data_dir.join("trusted"))?;
    if trust.revoke(&id)? {
        println!("Revoked {id}");
    } else {
        println!("Client {id} was not trusted");
    }
    Ok(())
}

fn cmd_gen_certs(data_dir: PathBuf) -> Result<()> {
    tls::install_crypto_provider();
    std::fs::create_dir_all(data_dir.join("tls"))?;
    tls::generate_dev_certs(&data_dir)?;
    println!(
        "Wrote TLS transport certificates under {}/tls",
        data_dir.display()
    );
    println!("These certificates are not BackupSAS identity.");
    Ok(())
}

fn cmd_verify(
    data_dir: PathBuf,
    backup_id: Option<String>,
    all: bool,
    repository: Option<String>,
) -> Result<()> {
    let lines = run_verify(VerifyOptions {
        data_dir,
        backup_id,
        all,
        repository,
    })?;
    print!("{}", format_all(&lines));
    if any_invalid(&lines) {
        anyhow::bail!("one or more backups failed verification");
    }
    Ok(())
}
