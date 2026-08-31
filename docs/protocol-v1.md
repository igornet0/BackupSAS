# BackupSAS Protocol v1

**Superseded by [protocol-v2.md](protocol-v2.md).** Kept for historical reference.

Binary framed protocol over TLS 1.3 with mutual certificate authentication.

BackupSAS is an untrusted store: it receives ciphertext, manifests, and hashes. It never receives decryption keys and never inspects Avrora internals.

## Transport

- TLS 1.3 only
- mTLS required (client certificate signed by the server CA)
- After the handshake the server checks the client certificate SHA-256 fingerprint against `clients/<fingerprint>.toml`

## Frame

Every message:

```
[4 bytes magic "BSAS"]
[1 byte version = 1]
[1 byte msg_type]
[4 bytes payload_len, little-endian]
[payload]
```

Maximum payload size: 65 MiB.

Payload fields are encoded as:

| Type   | Encoding                         |
|--------|----------------------------------|
| `u8`   | 1 byte                           |
| `u32`  | 4 bytes little-endian            |
| `u64`  | 8 bytes little-endian            |
| string | `u32` length + UTF-8 bytes       |
| bytes  | `u32` length + raw bytes         |
| bool   | `u8` (`0` or `1`)                |

## Feature flags

`HELLO_ACK.features` is a `u64` bitmask:

| Bit | Name     | Value |
|-----|----------|-------|
| 0   | resume   | `1`   |
| 1   | verify   | `2`   |

Phase 1 advertises `resume | verify` (`3`).

## Messages

| Type | Code | Direction | Purpose |
|------|------|-----------|---------|
| `HELLO` | `0x01` | C→S | protocol version, client_id |
| `HELLO_ACK` | `0x02` | S→C | server_id, features |
| `AUTH` | `0x03` | C→S | client_id, database_id |
| `AUTH_OK` | `0x04` | S→C | |
| `AUTH_FAIL` | `0x05` | S→C | reason |
| `CREATE` | `0x10` | C→S | backup_id, database_id, repository, total_size, chunk_size, chunk_count |
| `CREATED` | `0x11` | S→C | backup_id, resume_from, has_manifest |
| `RESUME` | `0x12` | C→S | backup_id |
| `RESUME_ACK` | `0x13` | S→C | backup_id, last_verified_chunk, next_sequence, state, has_manifest |
| `MANIFEST` | `0x20` | C→S | backup_id, manifest JSON |
| `MANIFEST_ACK` | `0x21` | S→C | backup_id |
| `CHUNK` | `0x30` | C→S | backup_id, sequence, blake3 hash, ciphertext |
| `CHUNK_ACK` | `0x31` | S→C | sequence |
| `VERIFY` | `0x40` | C→S | backup_id |
| `VERIFY_OK` | `0x41` | S→C | backup_id |
| `VERIFY_FAIL` | `0x42` | S→C | backup_id, mismatch list |
| `COMMIT` | `0x50` | C→S | backup_id |
| `COMMITTED` | `0x51` | S→C | backup_id, final path |
| `ABORT` | `0x60` | C→S | backup_id |
| `ABORTED` | `0x61` | S→C | backup_id |
| `STATUS` | `0x70` | C→S | optional backup_id (empty = server) |
| `STATUS_RESP` | `0x71` | S→C | backup_id, state, next_sequence, chunk_count |
| `ERROR` | `0xFF` | S→C | protocol / application error |

## State machine

```
HELLO → HELLO_ACK → AUTH → AUTH_OK
                         ↓
              CREATE / RESUME / STATUS / ABORT
                         ↓
         MANIFEST? → CHUNK* → VERIFY → COMMIT
                         ↓
                    COMPLETE (immutable)

Disconnect before COMMIT leaves the backup in UPLOADING.
The next CREATE or RESUME returns next_sequence so the client can continue.
```

Backup states: `UPLOADING`, `VERIFYING`, `COMPLETE`, `ABORTED`.

`CREATE` for an existing `UPLOADING` backup returns `resume_from = next_sequence` instead of starting over.

Chunks are accepted strictly in order. The server hashes each chunk with BLAKE3 before `CHUNK_ACK`. `VERIFY` re-hashes every stored chunk against the manifest. `COMMIT` is refused unless verification succeeded.

## Integrity and encryption

- Chunk hash: `blake3:<hex>` over the stored ciphertext blob (`nonce || AES-256-GCM ciphertext`)
- Manifest hash: BLAKE3 over the JSON with `manifest_hash` cleared
- Encryption is client-side only. BackupSAS stores ciphertext.

## Resume

Example: 5120 chunks sent (sequences `0..5119`), then the connection drops.

```
C → RESUME  backup_id=bkp_…
S → RESUME_ACK  last_verified_chunk=5119  next_sequence=5120  state=UPLOADING
C → CHUNK sequence=5120 …
```
