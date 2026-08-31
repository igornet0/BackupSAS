# BackupSAS Threat Model

Scope: BackupSAS Phase 2–3 (identity SDK + backup format v1). Assumes honest client software; threats are external attackers and compromised infrastructure.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Backup plaintext | Critical (client-side only) |
| Backup DEK | Critical (client only) |
| Client Ed25519 secret | High |
| Server Ed25519 secret | High |
| Bootstrap enrollment secret | High (one-time) |
| Backup ciphertext on disk | Medium (encrypted) |
| Manifest + commit | Integrity-critical |
| TLS transport cert | Low (not identity) |
| metadata.json | Low (audit only) |

## Attacker goals

1. Read backup plaintext without DEK
2. Forge or tamper backups undetected
3. Impersonate client or server
4. Replay old sessions or chunks
5. Roll back to an old backup version as "current"

## Stolen asset analysis

| Stolen | Attacker can | Attacker cannot |
|--------|--------------|-----------------|
| TLS server cert | Decrypt TLS for new connections if MITM + client trusts CA | Impersonate Ed25519 identity; decrypt backups |
| Server public key only | Identify server | Authenticate as server |
| Enrollment secret (before use) | Enroll one client identity | Decrypt backups; enroll after secret consumed |
| Client private key | Push backups to allowed repos; authenticate as client | Decrypt old backups without DEK |
| Server private key | Sign server proofs; deny service | Decrypt backups; forge client proofs |
| Backup repository disk | Copy ciphertext | Read plaintext without DEK |
| Session credentials (HKDF keys) | Affect single connection window | Decrypt backups; new sessions need PoP |
| metadata.json | Learn audit metadata | Prove integrity (not trusted) |

## Threat scenarios

### MITM on network

- **Mitigation:** TLS 1.3 + client pins Ed25519 `server_public_key` from `HELLO_ACK`
- TLS alone insufficient; identity pin required

### Malicious BackupSAS server

- Honest client encrypts with DEK before upload
- Client verifies manifest `root_hash` and `commit.json` after upload (Phase 3 verify)
- Server cannot produce valid client signatures without client key

### Malicious client

- Must be enrolled (bootstrap or admin trust file)
- Can only push to allowed `repositories`
- Cannot read other clients' backups
- Cannot decrypt stored ciphertext

### Corrupted storage / bit rot

- Per-chunk hash mismatch on verify
- `root_hash` mismatch if chunks altered
- `commit.json` mismatch if manifest altered
- **Detection:** `backupsas verify`, client-side verify before restore (Phase 4)

### Replay attack

- **Session:** Nonce + timestamp in proofs; ±300s window; new nonce per connection
- **Chunks:** Strict sequence; duplicate sequence rejected
- **Enrollment:** Secret one-time; deleted after use
- **Old backup as new:** New `backup_id`; commit binds specific manifest hash

### Rollback attack

- Attacker replaces backup directory with older copy
- **Detection:** Client should record `manifest_hash` / `commit.json` out-of-band (Avrora catalog, Phase 5)
- On-server: `commit.json` + Merkle verify detects chunk tampering within a backup

### Disk full during upload

- Upload fails; state remains `UPLOADING` or `VERIFYING`
- No `commit.json` → not `COMPLETE`
- Resume after space available

### Process crash

- Partial chunks in staging; resume from `next_sequence`
- No automatic `COMPLETE`

## Out of scope (documented for future)

- OS-level encryption of `identity.key` at rest
- HSM / keychain integration
- Admin API for multi-client enrollment after bootstrap consumed
- Byzantine replication across BackupSAS nodes

## Related

- [security-model.md](security-model.md)
- [backup-format-v1.md](backup-format-v1.md)
