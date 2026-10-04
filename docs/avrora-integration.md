# Avrora integration and node-to-node transfer

## 1. Public connect descriptor (`backupsas-connect/v1`)

`backupsas init` writes `connect.json`; `backupsas connect-info [--endpoint host:port]`
refreshes it (endpoints are persisted as `public_endpoints` in `server.toml`).

```json
{
  "format": "backupsas-connect/v1",
  "server_id": "sas_…",
  "public_key": "ed25519:…",
  "fingerprint": "SHA256:…",
  "endpoints": ["10.0.0.5:7420"],
  "server_name": "localhost",
  "ca_cert_pem": "-----BEGIN CERTIFICATE-----…",
  "repositories": ["avrora-prod"],
  "features": ["resume","verify","enroll","session","restore","list","transfer","relocate"],
  "issued_at": 1790000000,
  "signature": "<hex Ed25519 over canonical JSON without `signature`>"
}
```

* Self-signed by the node identity, domain tag `backupsas-connect-v1\0`.
* Contains **no secrets**. The one-time enrollment secret is handed over separately
  (`backupsas enroll-secret --kind database|node`). Issuing a new secret replaces the
  previous unused one.
* The importer pins `public_key`; TLS trusts only `ca_cert_pem`.

## 2. Avrora ↔ node

```
backupsas init --data-dir /var/lib/backupsas
backupsas connect-info --endpoint backup1.example:7420 --out backup1.json
backupsas start

avrora backup target add backup1 --connect backup1.json --secret bs_enroll_…
avrora backup schedule set --enabled true --time 02:00 --weekdays 1,3,5 \
    --targets local,backup1 --sections base,journal,runtime --retention-keep 7
avrora backup create manual-1 --targets backup1
avrora backup restore manual-1 --target r1 --from backup1   # vault unlocked
avrora backup recover --target r1                           # vault locked
```

Avrora keeps one Ed25519 client identity (`{control_dir}/backupsas/identity/`) for all
nodes. Data is encrypted in Avrora with a key derived via HKDF from the Master Key
(`key_id = avrora:master-hkdf:backup-v1`); nodes only ever see ciphertext.

## 3. Node ↔ node (`move` / `copy`)

```
# on node B
backupsas enroll-secret --kind node
# on node A
backupsas peer add --name b --connect b.json --secret bs_enroll_…
backupsas transfer --to b --mode move            # or --mode copy, --backup-id …
backupsas relocations
```

1. A authenticates on B with its `identity/node-client` (enrolled as `PeerKind::Node`).
2. `TRANSFER_OFFER` carries the owner's client id + public key. B adds the owner to its
   trust store as **delegated** (`delegated_by = <node client id>`); an existing owner
   entry must have the same pinned key.
3. Ciphertext chunks + original manifest are pushed with the normal
   `MANIFEST/CHUNK/VERIFY/COMMIT` flow; B verifies hashes and the Merkle root.
4. A records a `RelocationNotice` signed by A's identity (domain
   `backupsas-relocation-v1\0`) embedding B's signed descriptor.
5. The owner (Avrora) calls `PENDING_RELOCATIONS` on A, verifies the notice with A's
   pinned key, checks the backups are listed as `COMPLETE` on B, updates its catalog
   (move: replace location, copy: add location), registers B as a target, and sends
   `ACK_RELOCATION`. For `move`, A deletes its copy only after this ack.

## 4. Protocol additions (v2 feature bits)

| Type | Message | Notes |
|---|---|---|
| 0x50/0x51 | `LIST_BACKUPS` / `BACKUP_LIST` | owner-scoped, JSON payload |
| 0x52/0x53 | `DELETE_BACKUP` / `DELETED` | owner-only (retention) |
| 0x54/0x55 | `PENDING_RELOCATIONS` / `RELOCATIONS` | JSON payload |
| 0x56/0x57 | `ACK_RELOCATION` / `RELOCATION_ACKED` | triggers move cleanup |
| 0x60 | `TRANSFER_OFFER` → `CREATED` | `PeerKind::Node` only |

Feature bits: `LIST = 1<<5`, `TRANSFER = 1<<6`, `RELOCATE = 1<<7`.

## Trust notes

* A node peer is trusted to introduce owner identities (delegated trust) on the
  receiving node. Only issue `--kind node` secrets to nodes you operate.
* Relocation notices are accepted only from the node that already holds the data
  (pinned key) and only for the database's own client id.

## 5. Transfer / relocation state machine and crash safety

| Step | Persisted where | Crash here → effect on restart / retry |
|---|---|---|
| B: `TRANSFER_OFFER` → upload session | B `.state/<id>.json` | Partial upload is `UPLOADING`, never readable; retry resumes from `next_sequence` |
| B: `VERIFY` + `COMMIT` | B immutable backup dir | Commit only after all chunk hashes + Merkle root verify |
| A: record `RelocationNotice` | A `relocations/<id>.json` (atomic) | Retry `transfer`: B answers `COMMITTED` for an identical copy (same owner + `manifest_hash`), notice then written |
| Avrora: verify B lists `COMPLETE` with the **same `manifest_hash`** as A | — | No ack → A keeps its copy |
| Avrora: update catalog/targets, then `ACK_RELOCATION` | Avrora `backup_catalog.json`, `backup_targets.json` | Re-sync is idempotent (catalog relocate + target reuse); duplicate acks succeed |
| A: mark `acked`, then delete moved copies, then mark `cleaned` | A notice file | `acked && !cleaned` is completed at node startup (`finish_cleanups`) |

Authorization (all repository-scoped and owner-scoped): `CREATE`, `RESUME`, `STATUS <id>`,
`ABORT`, `OPEN_BACKUP`, `READ_CHUNK`, `LIST_BACKUPS`, `DELETE_BACKUP`, relocation
messages. Foreign backups are reported as "not found". Enrollment refuses an already
trusted client id (no re-keying) and claims the one-time secret atomically.

## 6. Disaster recovery (Avrora host lost)

The kit never contains the Master Key: it is recovered through the existing Master Key
mechanism (KeyPass / USB). Everything else needed is in the kit.

```
# while the server runs (vault unlocked) – or offline with --master-key-file
curl -X POST …/api/backup/export-kit > kit.json        # or:
avrora backup export-kit --out kit.json --master-key-file -   (hex on stdin)

# on the new host (no vault yet)
avrora backup import-kit --kit kit.json --master-key-file -
avrora backup catalog
avrora backup restore <backup_id> --target dr --from <target> --master-key-file -
avrora backup recover --target dr        # installs into the empty data dir
avrora serve                              # then unlock with the original Master Key
```

Kit (`avrora-backup-kit/v1`, file mode 0600): vault salt, key-derivation description,
backup key ids, Avrora client identity (public key in clear, secret key sealed with
AES-256-GCM under `HKDF(metadata_kek(master, salt), salt, "backup/avrora:kit-wrap-v1")`),
target descriptors, catalog and policy (imported with the schedule disabled).

**Key rotation.** `backup.json → encryption.key_id` selects the label for new remote
backups; each catalog location keeps the label it was written with, so older backups
stay restorable. Avrora has no Master Key rotation today; vault DEK rotation
(`rotate_node`) does not affect backup keys (they derive from the master-derived
metadata KEK). A future Master Key rotation must re-export the kit and either re-encrypt
or keep the old master for older backups.

## 7. Incomplete-upload garbage collection

Upload sessions record `last_activity` on every write. A node removes incomplete
uploads idle longer than `stale_upload_ttl_secs` (`server.toml`; default 7 days,
`0` disables) at startup and hourly. Sessions whose lock is held (upload in progress)
are skipped and idleness is re-checked under the lock; complete backups are never
touched. A transfer interrupted for longer than the TTL is simply redone from the
source, which keeps its copy until the owner acknowledges.

## 8. Key invariants

* Backup data key ≠ vault DEK; DEK rotation does not affect backups.
* Backup data key = HKDF over the Master-Key-derived metadata KEK + vault salt.
  A future Master Key rotation needs either the old Master Key for old backups or a
  re-encryption/migration step, plus a fresh recovery kit.
* Secrets (Ed25519 secret keys, data keys, enrollment secrets, session keys,
  plaintext buffers) are zeroized on drop and have redacted `Debug` output.
