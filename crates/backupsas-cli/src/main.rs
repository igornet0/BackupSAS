use anyhow::{Context, Result};
use backupsas_core::{BackupId, ClientId, Identity, DEFAULT_LISTEN};
use backupsas_cli::verify::{any_invalid, format_all, run_verify, VerifyOptions};
use backupsas_server::tls;
use backupsas_server::trust::TrustStore;
use backupsas_server::{init_data_dir, load_config, run, ServerState};
use backupsas_storage::{BackupRecord, StorageRoot};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "backupsas", about = "BackupSAS storage daemon and identity SDK")]
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
    /// Development helpers
    Dev {
        #[command(subcommand)]
        command: DevCmd,
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
    println!("Add this target in Avrora with Server ID + Public Key.");
    println!("The enrollment secret is consumed after the first successful enroll.");
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
