# BackupSAS

Security and backup protocol SDK for Rust. A DBMS (Avrora or otherwise) depends on `backupsas-client` and gets a protected backup channel. The server stores ciphertext only and knows nothing about the database internals.

## Layout

| Crate | Role |
|-------|------|
| `backupsas-core` | Identity, Ed25519 keys, HKDF, manifests, Merkle verify, errors |
| `backupsas-protocol` | Framed protocol v2 |
| `backupsas-storage` | Immutable chunk repository, backup state machine |
| `backupsas-server` | TLS transport + enrollment + authorization |
| `backupsas-client` | High-level SDK (upload, restore) |
| `backupsas-cli` | `init`, `start`, `status`, `trust`, `verify` |

## Principles

- TLS 1.3 is transport only. Identity is Ed25519 (`server_id` + public key + fingerprint).
- Trust is pinned to the public key. Address changes are fine; key changes are rejected.
- Mutual proof-of-possession on every connection.
- Enrollment uses a one-time bootstrap secret, then cryptographic identity.
- Backup encryption keys never leave the client.
- **Integrity is proven by manifest + chunk hashes + Merkle root + `commit.json`.** `metadata.json` is audit-only and untrusted.

## Documentation

| Doc | Topic |
|-----|-------|
| [protocol-v2.md](docs/protocol-v2.md) | Wire protocol |
| [backup-format-v1.md](docs/backup-format-v1.md) | On-disk backup layout (frozen for restore) |
| [security-model.md](docs/security-model.md) | Trust boundaries |
| [identity.md](docs/identity.md) | Client/server identity |
| [enrollment.md](docs/enrollment.md) | Bootstrap enrollment |
| [threat-model.md](docs/threat-model.md) | Threat model |

## Server

```bash
cargo run -p backupsas-cli -- init --data-dir ./data
cargo run -p backupsas-cli -- start --data-dir ./data
```

`init` prints Server ID, public key, fingerprint, and a one-time enrollment secret.

## Verify (Phase 3)

Check cryptographic integrity of stored backups (manifest, chunk hashes, Merkle root, commit):

```bash
cargo run -p backupsas-cli -- verify --data-dir ./data --backup-id <backup_id>
cargo run -p backupsas-cli -- verify --data-dir ./data --all
cargo run -p backupsas-cli -- verify --data-dir ./data --all --repository avrora-prod
```

Exit code `0` when all checked backups are **VALID**; `1` on **INVALID** or error. Example output:

```
backup backup_…
repository avrora-prod
path /data/repositories/avrora-prod/backups/backup_…
VALID
```

On failure:

```
INVALID
└── chunk hash mismatch at sequence 1
```

Run the full test suite: `cargo test` (59 tests at Phase 3 completion).

## Client SDK

Upload:

```rust
use backupsas_client::BackupSasClient;
use backupsas_core::DatabaseId;

let client = BackupSasClient::connect(config).await?;
let mut session = client.authenticate().await?;
let mut backup = session
    .create_backup(client.config(), database_id, snapshot_reader)
    .await?;
backup.upload().await?;
backup.commit().await?;
```

`BackupSasConfig` pins `server_id` and `server_public_key`. Optional `bootstrap_secret` is used only for the first enrollment.

## Phase status

| Phase | Status |
|-------|--------|
| 1–2 | Identity, protocol, enrollment, upload |
| 3 | Backup Format v1, repository abstraction, failure tests, `verify` CLI |
| 4 | Restore (in progress) — read-only over Format v1 |
| 5 | Incremental backup, dedup, compression, retention, GC |
