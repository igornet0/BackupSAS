# Backup Format v1

Frozen wire/storage format for BackupSAS backups. Phase 4 restore and Phase 5 catalog must consume this format without modification.

**Version:** `1` (`format_version: 1` in manifest and commit)

## Directory layout

```
backup-<backup_id>/
├── header.json       # optional upload metadata (untrusted for integrity)
├── manifest.json     # trusted integrity manifest
├── metadata.json     # server audit record (untrusted for integrity)
├── commit.json       # sole proof of COMPLETE
└── chunks/
    ├── 000000        # ciphertext blob, sequence 0
    ├── 000001
    └── ...
```

Chunk filenames: six-digit zero-padded decimal sequence (`000000`, `000001`, …).

## State machine

```
CREATING
   ↓
UPLOADING
   ↓
VERIFYING
   ↓
COMPLETE
```

| State | Meaning |
|-------|---------|
| `CREATING` | Session allocated; manifest not yet stored |
| `UPLOADING` | Manifest stored; chunks in progress |
| `VERIFYING` | All chunks received; hash verification passed |
| `COMPLETE` | `commit.json` written and matches manifest |

On any error during `CREATING`, `UPLOADING`, or `VERIFYING`, state may regress or become `ABORTED`. **Never** transition to `COMPLETE` without valid `commit.json`.

`metadata.json` may list `COMPLETE` for operator convenience; cryptographic completeness is defined only by `commit.json`.

## Trusted vs untrusted files

| File | Integrity role |
|------|----------------|
| `manifest.json` | Trusted |
| `chunks/*` | Trusted (hashed) |
| `commit.json` | Trusted (finalization) |
| `header.json` | Untrusted (client hints) |
| `metadata.json` | Untrusted (server audit) |

`metadata.json` **never** participates in `manifest_hash`, `root_hash`, or verify logic.

## manifest.json schema

```json
{
  "format_version": 1,
  "backup_id": "bak_01J...",
  "database_id": "db_01J...",
  "chunk_size": 4194304,
  "total_size": 10485760,
  "encryption": {
    "scheme": "aes-256-gcm",
    "key_id": "avrora:vault:backup-key-1"
  },
  "chunks": [
    {
      "sequence": 0,
      "size": 4194304,
      "hash": "blake3:abcdef..."
    }
  ],
  "root_hash": "blake3:...",
  "manifest_hash": "blake3:..."
}
```

### Field rules

| Field | Type | Notes |
|-------|------|-------|
| `format_version` | `u32` | Must be `1` |
| `backup_id` | string | `bak_<ulid>` |
| `database_id` | string | `db_<ulid>` |
| `chunk_size` | `u64` | Plaintext chunk size used by client |
| `total_size` | `u64` | Total plaintext size |
| `encryption.scheme` | enum | `aes-256-gcm` |
| `encryption.key_id` | string | Opaque DEK reference; not secret material |
| `chunks` | array | Sorted by `sequence` ascending, contiguous `0..n-1` |
| `chunks[].sequence` | `u32` | Zero-based |
| `chunks[].size` | `u64` | Ciphertext byte length on disk |
| `chunks[].hash` | string | `blake3:<64 lowercase hex>` of ciphertext |
| `root_hash` | string | Merkle root (see below) |
| `manifest_hash` | string | Self-hash (see below) |

Unknown fields in manifest are **rejected** at verify time.

## Canonical JSON

`manifest_hash` is computed over canonical JSON of the manifest **without** the `manifest_hash` field.

### Rules

1. **Encoding:** UTF-8, no BOM.
2. **Whitespace:** No insignificant whitespace (no spaces outside strings, no newlines).
3. **Object keys:** Sorted lexicographically by UTF-8 byte order at every nesting level.
4. **Arrays:** Order preserved (chunk array order is semantic; must match `sequence`).
5. **Numbers:** JSON integers only — no `1.0`, no scientific notation. `u32`/`u64` rendered as decimal without leading zeros.
6. **Strings:** Standard JSON escaping (`\"`, `\\`, `\n`, `\uXXXX` for control chars).
7. **Timestamps:** Not present in manifest (timestamps live in `commit.json` and untrusted files).
8. **Enums:** Lowercase string literals (`aes-256-gcm`).
9. **Unknown fields:** Reject on parse/verify.
10. **Versioning:** `format_version` must be supported; unknown major format rejected.

### Example

Objects `{"a":1,"b":2}` and `{"b":2,"a":1}` produce identical canonical bytes.

### Algorithm

```
manifest_without_hash = manifest object with manifest_hash field removed
canonical_bytes = canonical_json(manifest_without_hash)
manifest_hash = "blake3:" + hex(blake3(canonical_bytes))
```

The `manifest_hash` field in stored `manifest.json` must equal this value.

## Chunk hashing

```
chunk_hash = blake3(ciphertext_bytes)
wire_form = "blake3:" + hex(chunk_hash)   # 64 lowercase hex chars
```

Hash is over **stored ciphertext** (AES-GCM output including nonce/tag as produced by client encryptor).

## Merkle root

Domain-separated BLAKE3 tree over chunk leaves. Hash wire form matches chunk hashes (`blake3:<hex>`).

### Domain tags (UTF-8 bytes)

| Tag | Value |
|-----|-------|
| `domain_leaf` | `backupsas/v1/leaf` |
| `domain_node` | `backupsas/v1/node` |

### Leaf

For chunk at `sequence = s` with ciphertext hash bytes `H` (32 bytes, raw BLAKE3 output):

```
leaf(s, H) = BLAKE3(domain_leaf || u64_be(s) || H)
```

`u64_be(s)` is 8-byte big-endian unsigned integer.

### Internal node

```
node(L, R) = BLAKE3(domain_node || L || R)
```

`L` and `R` are 32-byte child hashes (raw bytes, not hex strings).

### Tree construction

1. Build leaves `leaf(0, H0), leaf(1, H1), … leaf(n-1, Hn-1)`.
2. If level has odd count, **duplicate the last node** (promote last leaf/hash to pair with itself):

```
A  B  C
 \ /  |
  AB  CC
   \ /
  ROOT
```

3. Repeat until one 32-byte root remains.
4. `root_hash = "blake3:" + hex(root_bytes)`

Empty backup (`chunks` empty): `root_hash = "blake3:" + hex(BLAKE3(domain_leaf || u64_be(0) || BLAKE3(empty)))` — i.e. single leaf for sequence 0 with empty ciphertext hash.

### Verification order

1. Verify each chunk file hash matches `chunks[i].hash`
2. Recompute Merkle root from chunk hashes
3. Compare to `manifest.root_hash`
4. Verify `manifest_hash` over canonical manifest without `manifest_hash` field

## commit.json schema

Minimal finalization record:

```json
{
  "format_version": 1,
  "backup_id": "bak_01J...",
  "root_hash": "blake3:...",
  "manifest_hash": "blake3:...",
  "committed_at": "2026-08-30T12:00:00Z"
}
```

### CommitRecord fields

| Field | Type | Notes |
|-------|------|-------|
| `format_version` | `u32` | `1` |
| `backup_id` | string | Must equal `manifest.backup_id` |
| `root_hash` | string | Must equal `manifest.root_hash` |
| `manifest_hash` | string | Must equal `manifest.manifest_hash` |
| `committed_at` | string | RFC 3339 UTC with `Z` suffix |

`commit.json` uses **pretty-printed JSON** for human inspection. Integrity is by field equality with manifest, not by hashing commit itself.

### COMPLETE predicate

A backup is **cryptographically complete** iff:

1. `commit.json` exists and parses
2. `commit.backup_id == manifest.backup_id`
3. `commit.root_hash == manifest.root_hash`
4. `commit.manifest_hash == manifest.manifest_hash`
5. All chunk hashes match
6. Recomputed Merkle root matches `manifest.root_hash`
7. Recomputed `manifest_hash` matches `manifest.manifest_hash`

Only then: state `COMPLETE`, verify result `VALID`.

## header.json (optional, untrusted)

Client-supplied hints for operators. Not hashed. Example:

```json
{
  "client_label": "avrora-primary",
  "source_type": "memory"
}
```

## metadata.json (untrusted audit)

Server-written at commit. Example:

```json
{
  "backup_id": "bak_01J...",
  "database_id": "db_01J...",
  "client_id": "cli_01J...",
  "repository": "avrora-prod",
  "received_at": "2026-08-30T11:55:00Z",
  "committed_at": "2026-08-30T12:00:00Z",
  "state": "COMPLETE",
  "chunk_count": 3,
  "total_size": 10485760
}
```

Changing `metadata.json` does not affect verify outcome.

## Verify CLI output

```
VALID
```

or

```
INVALID
└── chunk hash mismatch at sequence 123
```

```
INVALID
└── commit root mismatch
```

```
INVALID
└── manifest_hash mismatch
```

```
INVALID
└── missing commit.json
```

## Related

- [security-model.md](security-model.md)
- [protocol-v2.md](protocol-v2.md)
