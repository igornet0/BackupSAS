use crate::frame::FrameHeader;
use crate::wire::{WireReader, WireWriter};
use backupsas_core::{BackupSasError, Result};

pub const FEATURE_RESUME: u64 = 1 << 0;
pub const FEATURE_VERIFY: u64 = 1 << 1;
pub const FEATURE_ENROLL: u64 = 1 << 2;
pub const FEATURE_SESSION: u64 = 1 << 3;
pub const FEATURE_RESTORE: u64 = 1 << 4;
pub const FEATURES_V2: u64 =
    FEATURE_RESUME | FEATURE_VERIFY | FEATURE_ENROLL | FEATURE_SESSION | FEATURE_RESTORE;
pub const FEATURES_V1: u64 = FEATURE_RESUME | FEATURE_VERIFY;

pub type Features = u64;

const T_HELLO: u8 = 0x01;
const T_HELLO_ACK: u8 = 0x02;
const T_SERVER_PROOF: u8 = 0x03;
const T_CLIENT_PROOF: u8 = 0x04;
const T_AUTH_OK: u8 = 0x05;
const T_AUTH_FAIL: u8 = 0x06;

const T_ENROLL: u8 = 0x10;
const T_ENROLL_CHALLENGE: u8 = 0x11;
const T_ENROLL_PROOF: u8 = 0x12;
const T_ENROLL_OK: u8 = 0x13;
const T_ENROLL_FAIL: u8 = 0x14;

const T_SESSION_OPEN: u8 = 0x20;
const T_SESSION_OK: u8 = 0x21;
const T_SESSION_CLOSE: u8 = 0x22;

const T_CREATE: u8 = 0x30;
const T_CREATED: u8 = 0x31;
const T_RESUME: u8 = 0x32;
const T_RESUME_ACK: u8 = 0x33;
const T_MANIFEST: u8 = 0x34;
const T_MANIFEST_ACK: u8 = 0x35;
const T_CHUNK: u8 = 0x36;
const T_CHUNK_ACK: u8 = 0x37;
const T_VERIFY: u8 = 0x38;
const T_VERIFY_OK: u8 = 0x39;
const T_VERIFY_FAIL: u8 = 0x3A;
const T_COMMIT: u8 = 0x3B;
const T_COMMITTED: u8 = 0x3C;
const T_ABORT: u8 = 0x3D;
const T_ABORTED: u8 = 0x3E;
const T_STATUS: u8 = 0x3F;
const T_STATUS_RESP: u8 = 0x40;
const T_OPEN_BACKUP: u8 = 0x41;
const T_OPEN_BACKUP_OK: u8 = 0x42;
const T_READ_CHUNK: u8 = 0x43;
const T_READ_CHUNK_OK: u8 = 0x44;
const T_ERROR: u8 = 0xFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMismatch {
    pub sequence: u32,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello {
        protocol_version: u8,
        client_id: String,
        client_public_key: Vec<u8>,
    },
    HelloAck {
        server_id: String,
        server_public_key: Vec<u8>,
        features: Features,
        nonce: Vec<u8>,
    },
    ServerProof {
        timestamp: u64,
        signature: Vec<u8>,
    },
    ClientProof {
        timestamp: u64,
        signature: Vec<u8>,
    },
    AuthOk,
    AuthFail {
        reason: String,
    },
    Enroll {
        client_id: String,
        client_public_key: Vec<u8>,
        bootstrap_secret: String,
    },
    EnrollChallenge {
        nonce: Vec<u8>,
    },
    EnrollProof {
        signature: Vec<u8>,
        bootstrap_proof: String,
    },
    EnrollOk {
        client_id: String,
    },
    EnrollFail {
        reason: String,
    },
    SessionOpen {
        session_id: String,
        client_nonce: Vec<u8>,
        server_nonce: Vec<u8>,
    },
    SessionOk {
        session_id: String,
        expires_at: u64,
    },
    SessionClose {
        session_id: String,
    },
    Create {
        session_id: String,
        backup_id: String,
        database_id: String,
        repository: String,
        total_size: u64,
        chunk_size: u64,
        chunk_count: u32,
    },
    Created {
        backup_id: String,
        resume_from: u32,
        has_manifest: bool,
    },
    Resume {
        session_id: String,
        backup_id: String,
    },
    ResumeAck {
        backup_id: String,
        last_verified_chunk: u32,
        next_sequence: u32,
        state: String,
        has_manifest: bool,
    },
    Manifest {
        session_id: String,
        backup_id: String,
        bytes: Vec<u8>,
    },
    ManifestAck {
        backup_id: String,
    },
    Chunk {
        session_id: String,
        backup_id: String,
        sequence: u32,
        hash: String,
        payload: Vec<u8>,
    },
    ChunkAck {
        sequence: u32,
    },
    Verify {
        session_id: String,
        backup_id: String,
    },
    VerifyOk {
        backup_id: String,
    },
    VerifyFail {
        backup_id: String,
        mismatches: Vec<ChunkMismatch>,
    },
    Commit {
        session_id: String,
        backup_id: String,
    },
    Committed {
        backup_id: String,
        path: String,
    },
    Abort {
        session_id: String,
        backup_id: String,
    },
    Aborted {
        backup_id: String,
    },
    Status {
        session_id: String,
        backup_id: Option<String>,
    },
    StatusResp {
        backup_id: String,
        state: String,
        next_sequence: u32,
        chunk_count: u32,
    },
    OpenBackup {
        session_id: String,
        backup_id: String,
    },
    OpenBackupOk {
        backup_id: String,
        manifest_bytes: Vec<u8>,
        commit_bytes: Vec<u8>,
    },
    ReadChunk {
        session_id: String,
        backup_id: String,
        sequence: u32,
    },
    ReadChunkOk {
        backup_id: String,
        sequence: u32,
        payload: Vec<u8>,
    },
    Error {
        reason: String,
    },
}

impl Message {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "HELLO",
            Self::HelloAck { .. } => "HELLO_ACK",
            Self::ServerProof { .. } => "SERVER_PROOF",
            Self::ClientProof { .. } => "CLIENT_PROOF",
            Self::AuthOk => "AUTH_OK",
            Self::AuthFail { .. } => "AUTH_FAIL",
            Self::Enroll { .. } => "ENROLL",
            Self::EnrollChallenge { .. } => "ENROLL_CHALLENGE",
            Self::EnrollProof { .. } => "ENROLL_PROOF",
            Self::EnrollOk { .. } => "ENROLL_OK",
            Self::EnrollFail { .. } => "ENROLL_FAIL",
            Self::SessionOpen { .. } => "SESSION_OPEN",
            Self::SessionOk { .. } => "SESSION_OK",
            Self::SessionClose { .. } => "SESSION_CLOSE",
            Self::Create { .. } => "CREATE",
            Self::Created { .. } => "CREATED",
            Self::Resume { .. } => "RESUME",
            Self::ResumeAck { .. } => "RESUME_ACK",
            Self::Manifest { .. } => "MANIFEST",
            Self::ManifestAck { .. } => "MANIFEST_ACK",
            Self::Chunk { .. } => "CHUNK",
            Self::ChunkAck { .. } => "CHUNK_ACK",
            Self::Verify { .. } => "VERIFY",
            Self::VerifyOk { .. } => "VERIFY_OK",
            Self::VerifyFail { .. } => "VERIFY_FAIL",
            Self::Commit { .. } => "COMMIT",
            Self::Committed { .. } => "COMMITTED",
            Self::Abort { .. } => "ABORT",
            Self::Aborted { .. } => "ABORTED",
            Self::Status { .. } => "STATUS",
            Self::StatusResp { .. } => "STATUS_RESP",
            Self::OpenBackup { .. } => "OPEN_BACKUP",
            Self::OpenBackupOk { .. } => "OPEN_BACKUP_OK",
            Self::ReadChunk { .. } => "READ_CHUNK",
            Self::ReadChunkOk { .. } => "READ_CHUNK_OK",
            Self::Error { .. } => "ERROR",
        }
    }

    fn msg_type(&self) -> u8 {
        match self {
            Self::Hello { .. } => T_HELLO,
            Self::HelloAck { .. } => T_HELLO_ACK,
            Self::ServerProof { .. } => T_SERVER_PROOF,
            Self::ClientProof { .. } => T_CLIENT_PROOF,
            Self::AuthOk => T_AUTH_OK,
            Self::AuthFail { .. } => T_AUTH_FAIL,
            Self::Enroll { .. } => T_ENROLL,
            Self::EnrollChallenge { .. } => T_ENROLL_CHALLENGE,
            Self::EnrollProof { .. } => T_ENROLL_PROOF,
            Self::EnrollOk { .. } => T_ENROLL_OK,
            Self::EnrollFail { .. } => T_ENROLL_FAIL,
            Self::SessionOpen { .. } => T_SESSION_OPEN,
            Self::SessionOk { .. } => T_SESSION_OK,
            Self::SessionClose { .. } => T_SESSION_CLOSE,
            Self::Create { .. } => T_CREATE,
            Self::Created { .. } => T_CREATED,
            Self::Resume { .. } => T_RESUME,
            Self::ResumeAck { .. } => T_RESUME_ACK,
            Self::Manifest { .. } => T_MANIFEST,
            Self::ManifestAck { .. } => T_MANIFEST_ACK,
            Self::Chunk { .. } => T_CHUNK,
            Self::ChunkAck { .. } => T_CHUNK_ACK,
            Self::Verify { .. } => T_VERIFY,
            Self::VerifyOk { .. } => T_VERIFY_OK,
            Self::VerifyFail { .. } => T_VERIFY_FAIL,
            Self::Commit { .. } => T_COMMIT,
            Self::Committed { .. } => T_COMMITTED,
            Self::Abort { .. } => T_ABORT,
            Self::Aborted { .. } => T_ABORTED,
            Self::Status { .. } => T_STATUS,
            Self::StatusResp { .. } => T_STATUS_RESP,
            Self::OpenBackup { .. } => T_OPEN_BACKUP,
            Self::OpenBackupOk { .. } => T_OPEN_BACKUP_OK,
            Self::ReadChunk { .. } => T_READ_CHUNK,
            Self::ReadChunkOk { .. } => T_READ_CHUNK_OK,
            Self::Error { .. } => T_ERROR,
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        match self {
            Self::Hello {
                protocol_version,
                client_id,
                client_public_key,
            } => {
                w.write_u8(*protocol_version);
                w.write_str(client_id);
                w.write_bytes(client_public_key);
            }
            Self::HelloAck {
                server_id,
                server_public_key,
                features,
                nonce,
            } => {
                w.write_str(server_id);
                w.write_bytes(server_public_key);
                w.write_u64(*features);
                w.write_bytes(nonce);
            }
            Self::ServerProof {
                timestamp,
                signature,
            } => {
                w.write_u64(*timestamp);
                w.write_bytes(signature);
            }
            Self::ClientProof {
                timestamp,
                signature,
            } => {
                w.write_u64(*timestamp);
                w.write_bytes(signature);
            }
            Self::AuthOk => {}
            Self::AuthFail { reason } => w.write_str(reason),
            Self::Enroll {
                client_id,
                client_public_key,
                bootstrap_secret,
            } => {
                w.write_str(client_id);
                w.write_bytes(client_public_key);
                w.write_str(bootstrap_secret);
            }
            Self::EnrollChallenge { nonce } => w.write_bytes(nonce),
            Self::EnrollProof {
                signature,
                bootstrap_proof,
            } => {
                w.write_bytes(signature);
                w.write_str(bootstrap_proof);
            }
            Self::EnrollOk { client_id } => w.write_str(client_id),
            Self::EnrollFail { reason } => w.write_str(reason),
            Self::SessionOpen {
                session_id,
                client_nonce,
                server_nonce,
            } => {
                w.write_str(session_id);
                w.write_bytes(client_nonce);
                w.write_bytes(server_nonce);
            }
            Self::SessionOk {
                session_id,
                expires_at,
            } => {
                w.write_str(session_id);
                w.write_u64(*expires_at);
            }
            Self::SessionClose { session_id } => w.write_str(session_id),
            Self::Create {
                session_id,
                backup_id,
                database_id,
                repository,
                total_size,
                chunk_size,
                chunk_count,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
                w.write_str(database_id);
                w.write_str(repository);
                w.write_u64(*total_size);
                w.write_u64(*chunk_size);
                w.write_u32(*chunk_count);
            }
            Self::Created {
                backup_id,
                resume_from,
                has_manifest,
            } => {
                w.write_str(backup_id);
                w.write_u32(*resume_from);
                w.write_u8(u8::from(*has_manifest));
            }
            Self::Resume {
                session_id,
                backup_id,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
            }
            Self::ResumeAck {
                backup_id,
                last_verified_chunk,
                next_sequence,
                state,
                has_manifest,
            } => {
                w.write_str(backup_id);
                w.write_u32(*last_verified_chunk);
                w.write_u32(*next_sequence);
                w.write_str(state);
                w.write_u8(u8::from(*has_manifest));
            }
            Self::Manifest {
                session_id,
                backup_id,
                bytes,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
                w.write_bytes(bytes);
            }
            Self::ManifestAck { backup_id } => w.write_str(backup_id),
            Self::Chunk {
                session_id,
                backup_id,
                sequence,
                hash,
                payload,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
                w.write_u32(*sequence);
                w.write_str(hash);
                w.write_bytes(payload);
            }
            Self::ChunkAck { sequence } => w.write_u32(*sequence),
            Self::Verify {
                session_id,
                backup_id,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
            }
            Self::VerifyOk { backup_id } => w.write_str(backup_id),
            Self::VerifyFail {
                backup_id,
                mismatches,
            } => {
                w.write_str(backup_id);
                w.write_u32(mismatches.len() as u32);
                for m in mismatches {
                    w.write_u32(m.sequence);
                    w.write_str(&m.expected);
                    w.write_str(&m.actual);
                }
            }
            Self::Commit {
                session_id,
                backup_id,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
            }
            Self::Committed { backup_id, path } => {
                w.write_str(backup_id);
                w.write_str(path);
            }
            Self::Abort {
                session_id,
                backup_id,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
            }
            Self::Aborted { backup_id } => w.write_str(backup_id),
            Self::Status {
                session_id,
                backup_id,
            } => {
                w.write_str(session_id);
                match backup_id {
                    Some(id) => w.write_str(id),
                    None => w.write_str(""),
                }
            }
            Self::StatusResp {
                backup_id,
                state,
                next_sequence,
                chunk_count,
            } => {
                w.write_str(backup_id);
                w.write_str(state);
                w.write_u32(*next_sequence);
                w.write_u32(*chunk_count);
            }
            Self::OpenBackup {
                session_id,
                backup_id,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
            }
            Self::OpenBackupOk {
                backup_id,
                manifest_bytes,
                commit_bytes,
            } => {
                w.write_str(backup_id);
                w.write_bytes(manifest_bytes);
                w.write_bytes(commit_bytes);
            }
            Self::ReadChunk {
                session_id,
                backup_id,
                sequence,
            } => {
                w.write_str(session_id);
                w.write_str(backup_id);
                w.write_u32(*sequence);
            }
            Self::ReadChunkOk {
                backup_id,
                sequence,
                payload,
            } => {
                w.write_str(backup_id);
                w.write_u32(*sequence);
                w.write_bytes(payload);
            }
            Self::Error { reason } => w.write_str(reason),
        }
        w.finish()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload = self.encode_payload();
        let header = FrameHeader::new(self.msg_type(), payload.len() as u32)?;
        let mut out = Vec::with_capacity(crate::frame::HEADER_LEN + payload.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode(msg_type: u8, payload: &[u8]) -> Result<Self> {
        let mut r = WireReader::new(payload);
        let msg = match msg_type {
            T_HELLO => Self::Hello {
                protocol_version: r.read_u8()?,
                client_id: r.read_string()?,
                client_public_key: r.read_bytes()?.to_vec(),
            },
            T_HELLO_ACK => Self::HelloAck {
                server_id: r.read_string()?,
                server_public_key: r.read_bytes()?.to_vec(),
                features: r.read_u64()?,
                nonce: r.read_bytes()?.to_vec(),
            },
            T_SERVER_PROOF => Self::ServerProof {
                timestamp: r.read_u64()?,
                signature: r.read_bytes()?.to_vec(),
            },
            T_CLIENT_PROOF => Self::ClientProof {
                timestamp: r.read_u64()?,
                signature: r.read_bytes()?.to_vec(),
            },
            T_AUTH_OK => Self::AuthOk,
            T_AUTH_FAIL => Self::AuthFail {
                reason: r.read_string()?,
            },
            T_ENROLL => Self::Enroll {
                client_id: r.read_string()?,
                client_public_key: r.read_bytes()?.to_vec(),
                bootstrap_secret: r.read_string()?,
            },
            T_ENROLL_CHALLENGE => Self::EnrollChallenge {
                nonce: r.read_bytes()?.to_vec(),
            },
            T_ENROLL_PROOF => Self::EnrollProof {
                signature: r.read_bytes()?.to_vec(),
                bootstrap_proof: r.read_string()?,
            },
            T_ENROLL_OK => Self::EnrollOk {
                client_id: r.read_string()?,
            },
            T_ENROLL_FAIL => Self::EnrollFail {
                reason: r.read_string()?,
            },
            T_SESSION_OPEN => Self::SessionOpen {
                session_id: r.read_string()?,
                client_nonce: r.read_bytes()?.to_vec(),
                server_nonce: r.read_bytes()?.to_vec(),
            },
            T_SESSION_OK => Self::SessionOk {
                session_id: r.read_string()?,
                expires_at: r.read_u64()?,
            },
            T_SESSION_CLOSE => Self::SessionClose {
                session_id: r.read_string()?,
            },
            T_CREATE => Self::Create {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
                database_id: r.read_string()?,
                repository: r.read_string()?,
                total_size: r.read_u64()?,
                chunk_size: r.read_u64()?,
                chunk_count: r.read_u32()?,
            },
            T_CREATED => Self::Created {
                backup_id: r.read_string()?,
                resume_from: r.read_u32()?,
                has_manifest: r.read_u8()? != 0,
            },
            T_RESUME => Self::Resume {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
            },
            T_RESUME_ACK => Self::ResumeAck {
                backup_id: r.read_string()?,
                last_verified_chunk: r.read_u32()?,
                next_sequence: r.read_u32()?,
                state: r.read_string()?,
                has_manifest: r.read_u8()? != 0,
            },
            T_MANIFEST => Self::Manifest {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
                bytes: r.read_bytes()?.to_vec(),
            },
            T_MANIFEST_ACK => Self::ManifestAck {
                backup_id: r.read_string()?,
            },
            T_CHUNK => Self::Chunk {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
                sequence: r.read_u32()?,
                hash: r.read_string()?,
                payload: r.read_bytes()?.to_vec(),
            },
            T_CHUNK_ACK => Self::ChunkAck {
                sequence: r.read_u32()?,
            },
            T_VERIFY => Self::Verify {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
            },
            T_VERIFY_OK => Self::VerifyOk {
                backup_id: r.read_string()?,
            },
            T_VERIFY_FAIL => {
                let backup_id = r.read_string()?;
                let n = r.read_u32()? as usize;
                let mut mismatches = Vec::with_capacity(n);
                for _ in 0..n {
                    mismatches.push(ChunkMismatch {
                        sequence: r.read_u32()?,
                        expected: r.read_string()?,
                        actual: r.read_string()?,
                    });
                }
                Self::VerifyFail {
                    backup_id,
                    mismatches,
                }
            }
            T_COMMIT => Self::Commit {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
            },
            T_COMMITTED => Self::Committed {
                backup_id: r.read_string()?,
                path: r.read_string()?,
            },
            T_ABORT => Self::Abort {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
            },
            T_ABORTED => Self::Aborted {
                backup_id: r.read_string()?,
            },
            T_STATUS => Self::Status {
                session_id: r.read_string()?,
                backup_id: {
                    let id = r.read_string()?;
                    if id.is_empty() { None } else { Some(id) }
                },
            },
            T_STATUS_RESP => Self::StatusResp {
                backup_id: r.read_string()?,
                state: r.read_string()?,
                next_sequence: r.read_u32()?,
                chunk_count: r.read_u32()?,
            },
            T_OPEN_BACKUP => Self::OpenBackup {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
            },
            T_OPEN_BACKUP_OK => Self::OpenBackupOk {
                backup_id: r.read_string()?,
                manifest_bytes: r.read_bytes()?.to_vec(),
                commit_bytes: r.read_bytes()?.to_vec(),
            },
            T_READ_CHUNK => Self::ReadChunk {
                session_id: r.read_string()?,
                backup_id: r.read_string()?,
                sequence: r.read_u32()?,
            },
            T_READ_CHUNK_OK => Self::ReadChunkOk {
                backup_id: r.read_string()?,
                sequence: r.read_u32()?,
                payload: r.read_bytes()?.to_vec(),
            },
            T_ERROR => Self::Error {
                reason: r.read_string()?,
            },
            other => {
                return Err(BackupSasError::Protocol(format!(
                    "unknown message type 0x{other:02X}"
                )));
            }
        };
        r.finish()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Message) {
        let encoded = msg.encode().unwrap();
        let header = crate::frame::FrameHeader::decode(encoded[..10].try_into().unwrap()).unwrap();
        assert_eq!(header.version, 2);
        let decoded = Message::decode(header.msg_type, &encoded[10..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn handshake_and_upload_roundtrip() {
        roundtrip(Message::Hello {
            protocol_version: 2,
            client_id: "cli_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            client_public_key: vec![1; 32],
        });
        roundtrip(Message::HelloAck {
            server_id: "sas_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            server_public_key: vec![2; 32],
            features: FEATURES_V2,
            nonce: vec![3; 32],
        });
        roundtrip(Message::ServerProof {
            timestamp: 1,
            signature: vec![4; 64],
        });
        roundtrip(Message::ClientProof {
            timestamp: 2,
            signature: vec![5; 64],
        });
        roundtrip(Message::Enroll {
            client_id: "cli_x".into(),
            client_public_key: vec![6; 32],
            bootstrap_secret: "bs_enroll_ab".into(),
        });
        roundtrip(Message::EnrollChallenge { nonce: vec![7; 32] });
        roundtrip(Message::EnrollProof {
            signature: vec![8; 64],
            bootstrap_proof: "blake3:aa".into(),
        });
        roundtrip(Message::EnrollOk {
            client_id: "cli_x".into(),
        });
        roundtrip(Message::SessionOpen {
            session_id: "ses_1".into(),
            client_nonce: vec![9; 32],
            server_nonce: vec![10; 32],
        });
        roundtrip(Message::Create {
            session_id: "ses_1".into(),
            backup_id: "bkp_1".into(),
            database_id: "db_1".into(),
            repository: "avrora-prod".into(),
            total_size: 100,
            chunk_size: 16,
            chunk_count: 2,
        });
        roundtrip(Message::Chunk {
            session_id: "ses_1".into(),
            backup_id: "bkp_1".into(),
            sequence: 0,
            hash: "blake3:x".into(),
            payload: vec![1, 2, 3],
        });
        roundtrip(Message::AuthOk);
        roundtrip(Message::OpenBackup {
            session_id: "ses_1".into(),
            backup_id: "bkp_1".into(),
        });
        roundtrip(Message::OpenBackupOk {
            backup_id: "bkp_1".into(),
            manifest_bytes: br#"{"format_version":1}"#.to_vec(),
            commit_bytes: br#"{"format_version":1}"#.to_vec(),
        });
        roundtrip(Message::ReadChunk {
            session_id: "ses_1".into(),
            backup_id: "bkp_1".into(),
            sequence: 2,
        });
        roundtrip(Message::ReadChunkOk {
            backup_id: "bkp_1".into(),
            sequence: 2,
            payload: vec![9, 9, 9],
        });
        roundtrip(Message::Error {
            reason: "boom".into(),
        });
    }
}
