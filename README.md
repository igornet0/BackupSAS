# BackupSAS

Security and backup protocol SDK for Rust. A DBMS (Avrora or otherwise) depends on `backupsas-client` and gets a protected backup channel. The server stores ciphertext only and knows nothing about the database internals.

## Layout

| Crate | Role |
|-------|------|
| `backupsas-core` | Identity, Ed25519 keys, HKDF, manifests, errors |
| `backupsas-protocol` | Framed protocol v2 |
| `backupsas-storage` | Immutable chunk repository |
| `backupsas-server` | TLS transport + enrollment + authorization |
| `backupsas-client` | High-level SDK |
| `backupsas-cli` | `init`, `start`, `status`, `trust` |

## Principles

- TLS 1.3 is transport only. Identity is Ed25519 (`server_id` + public key + fingerprint).
- Trust is pinned to the public key. Address changes are fine; key changes are rejected.
- Mutual proof-of-possession on every connection.
- Enrollment uses a one-time bootstrap secret, then cryptographic identity.
- Backup encryption keys never leave the client.

## Server

```bash
cargo run -p backupsas-cli -- init --data-dir ./data
cargo run -p backupsas-cli -- start --data-dir ./data
```

`init` prints Server ID, public key, fingerprint, and a one-time enrollment secret.

## Client SDK (Avrora)

```rust
use backupsas_client::BackupSasClient;
use backupsas_core::{BackupEncryptionKey, BackupSasConfig};

let client = BackupSasClient::connect(config).await?;
let mut session = client.authenticate().await?;
let mut backup = session
    .create_backup(client.config(), database_id, snapshot_reader)
    .await?;
backup.upload().await?;
backup.commit().await?;
```

`BackupSasConfig` pins `server_id` and `server_public_key`. Optional `bootstrap_secret` is used only for the first enrollment.

Protocol: [docs/protocol-v2.md](docs/protocol-v2.md).
