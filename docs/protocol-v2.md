# BackupSAS Protocol v2

Binary framed protocol over TLS 1.3. TLS is transport encryption only.

BackupSAS identity is an Ed25519 public key, not a TLS certificate. Trust is established by pinning `server_id` + `public_key`. Changing IP, DNS, or port is allowed. Changing the public key is rejected.

BackupSAS is zero-knowledge storage: it receives ciphertext, manifests, and hashes. It never receives backup decryption keys.

Protocol v1 is superseded. See [protocol-v1.md](protocol-v1.md).

## Transport

- TLS 1.3, server certificate only (no mTLS)
- Application authentication via Ed25519 proof-of-possession
- Optional one-time enrollment with a bootstrap secret

## Frame

Same layout as v1, version byte = `2`:

```
[4 bytes magic "BSAS"]
[1 byte version = 2]
[1 byte msg_type]
[4 bytes payload_len, little-endian]
[payload]
```

Maximum payload size: 65 MiB.

## Feature flags

| Bit | Name    | Value |
|-----|---------|-------|
| 0   | resume  | `1`   |
| 1   | verify  | `2`   |
| 2   | enroll  | `4`   |
| 3   | session | `8`   |

Phase 2 advertises `15`.

## Messages

### Handshake (`0x01`–`0x06`)

| Type | Code | Direction |
|------|------|-----------|
| `HELLO` | `0x01` | C→S |
| `HELLO_ACK` | `0x02` | S→C |
| `SERVER_PROOF` | `0x03` | S→C |
| `CLIENT_PROOF` | `0x04` | C→S |
| `AUTH_OK` | `0x05` | S→C |
| `AUTH_FAIL` | `0x06` | S→C |

`HELLO` carries `client_id` and the raw 32-byte Ed25519 public key.
`HELLO_ACK` carries `server_id`, server public key, features, and a 32-byte nonce.

Proofs sign `nonce || participant_id || timestamp` (timestamp is unix seconds, little-endian `u64`). A proof is rejected if `|now - timestamp| > 300` seconds.

The client compares `HELLO_ACK.server_public_key` with the pinned key. Mismatch is a hard fail.

### Enrollment (`0x10`–`0x14`)

Used only when the client is not yet in the server trust store.

| Type | Code | Direction |
|------|------|-----------|
| `ENROLL` | `0x10` | C→S |
| `ENROLL_CHALLENGE` | `0x11` | S→C |
| `ENROLL_PROOF` | `0x12` | C→S |
| `ENROLL_OK` | `0x13` | S→C |
| `ENROLL_FAIL` | `0x14` | S→C |

The server stores `blake3(bootstrap_secret)` at init. After `ENROLL_OK` the secret file is deleted. The client proves possession by sending `blake3(enrollment_nonce || bootstrap_secret)` and an Ed25519 signature over `nonce || client_id || bootstrap_proof`.

### Session (`0x20`–`0x22`)

| Type | Code | Direction |
|------|------|-----------|
| `SESSION_OPEN` | `0x20` | C→S |
| `SESSION_OK` | `0x21` | S→C |
| `SESSION_CLOSE` | `0x22` | C→S |

Session keys (both sides, independently):

```
session_material = client_signature || server_signature || client_nonce || server_nonce
HKDF-SHA256(ikm=session_material, salt=session_id, info="backupsas-session-v2")
  → mac_key (32)
  → confirm_key (32)
```

### Upload (`0x30`–`0x40`)

CREATE / RESUME / MANIFEST / CHUNK / VERIFY / COMMIT / ABORT / STATUS.

Every client upload message includes `session_id`. The server rejects a mismatched or expired session.

## State machine

```
HELLO → HELLO_ACK → SERVER_PROOF
                 ↓
         [optional ENROLL]
                 ↓
         CLIENT_PROOF → AUTH_OK
                 ↓
         SESSION_OPEN → SESSION_OK
                 ↓
         CREATE / RESUME → MANIFEST? → CHUNK* → VERIFY → COMMIT
```

Disconnect before `COMMIT` leaves the backup `UPLOADING`. The next `CREATE` or `RESUME` returns `next_sequence`.

## Key separation

| Key | Role |
|-----|------|
| Ed25519 identity | Authentication and enrollment |
| Backup DEK (AES-256-GCM) | Client-side chunk encryption; never sent to the server |
| Session keys | HKDF-derived per connection |

## Identity files

```
/var/lib/backupsas/
├── identity/identity.toml    # server_id + public key
├── identity/identity.key     # Ed25519 secret (0600)
├── enrollment.secret         # blake3 hash; deleted after enroll
├── trusted/cli_….toml        # enrolled clients
└── tls/                      # transport certificates only
```
