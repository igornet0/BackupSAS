use crate::frame::FrameHeader;
use crate::wire::{WireReader, WireWriter};
use backupsas_core::{BackupSasError, Result};

pub const FEATURE_RESUME: u64 = 1 << 0;
pub const FEATURE_VERIFY: u64 = 1 << 1;
pub const FEATURES_V1: u64 = FEATURE_RESUME | FEATURE_VERIFY;

pub type Features = u64;

const T_HELLO: u8 = 0x01;
const T_HELLO_ACK: u8 = 0x02;
const T_AUTH: u8 = 0x03;
const T_AUTH_OK: u8 = 0x04;
const T_AUTH_FAIL: u8 = 0x05;
const T_CREATE: u8 = 0x10;
const T_CREATED: u8 = 0x11;
const T_RESUME: u8 = 0x12;
const T_RESUME_ACK: u8 = 0x13;
const T_MANIFEST: u8 = 0x20;
const T_MANIFEST_ACK: u8 = 0x21;
const T_CHUNK: u8 = 0x30;
const T_CHUNK_ACK: u8 = 0x31;
const T_VERIFY: u8 = 0x40;
const T_VERIFY_OK: u8 = 0x41;
const T_VERIFY_FAIL: u8 = 0x42;
const T_COMMIT: u8 = 0x50;
const T_COMMITTED: u8 = 0x51;
const T_ABORT: u8 = 0x60;
const T_ABORTED: u8 = 0x61;
const T_STATUS: u8 = 0x70;
const T_STATUS_RESP: u8 = 0x71;
const T_ERROR: u8 = 0xFF;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMismatch {
    pub sequence: u32,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V1Message {
    Hello {
        protocol_version: u8,
        client_id: String,
    },
    HelloAck {
        server_id: String,
        features: Features,
    },
    Auth {
        client_id: String,
        database_id: String,
    },
    AuthOk,
    AuthFail {
        reason: String,
    },
    Create {
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
        backup_id: String,
        bytes: Vec<u8>,
    },
    ManifestAck {
        backup_id: String,
    },
    Chunk {
        backup_id: String,
        sequence: u32,
        hash: String,
        payload: Vec<u8>,
    },
    ChunkAck {
        sequence: u32,
    },
    Verify {
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
        backup_id: String,
    },
    Committed {
        backup_id: String,
        path: String,
    },
    Abort {
        backup_id: String,
    },
    Aborted {
        backup_id: String,
    },
    Status {
        backup_id: Option<String>,
    },
    StatusResp {
        backup_id: String,
        state: String,
        next_sequence: u32,
        chunk_count: u32,
    },
    Error {
        reason: String,
    },
}

impl V1Message {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Hello { .. } => "HELLO",
            Self::HelloAck { .. } => "HELLO_ACK",
            Self::Auth { .. } => "AUTH",
            Self::AuthOk => "AUTH_OK",
            Self::AuthFail { .. } => "AUTH_FAIL",
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
            Self::Error { .. } => "ERROR",
        }
    }

    fn msg_type(&self) -> u8 {
        match self {
            Self::Hello { .. } => T_HELLO,
            Self::HelloAck { .. } => T_HELLO_ACK,
            Self::Auth { .. } => T_AUTH,
            Self::AuthOk => T_AUTH_OK,
            Self::AuthFail { .. } => T_AUTH_FAIL,
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
            Self::Error { .. } => T_ERROR,
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        match self {
            Self::Hello {
                protocol_version,
                client_id,
            } => {
                w.write_u8(*protocol_version);
                w.write_str(client_id);
            }
            Self::HelloAck {
                server_id,
                features,
            } => {
                w.write_str(server_id);
                w.write_u64(*features);
            }
            Self::Auth {
                client_id,
                database_id,
            } => {
                w.write_str(client_id);
                w.write_str(database_id);
            }
            Self::AuthOk => {}
            Self::AuthFail { reason } => w.write_str(reason),
            Self::Create {
                backup_id,
                database_id,
                repository,
                total_size,
                chunk_size,
                chunk_count,
            } => {
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
            Self::Resume { backup_id } => w.write_str(backup_id),
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
            Self::Manifest { backup_id, bytes } => {
                w.write_str(backup_id);
                w.write_bytes(bytes);
            }
            Self::ManifestAck { backup_id } => w.write_str(backup_id),
            Self::Chunk {
                backup_id,
                sequence,
                hash,
                payload,
            } => {
                w.write_str(backup_id);
                w.write_u32(*sequence);
                w.write_str(hash);
                w.write_bytes(payload);
            }
            Self::ChunkAck { sequence } => w.write_u32(*sequence),
            Self::Verify { backup_id } => w.write_str(backup_id),
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
            Self::Commit { backup_id } => w.write_str(backup_id),
            Self::Committed { backup_id, path } => {
                w.write_str(backup_id);
                w.write_str(path);
            }
            Self::Abort { backup_id } => w.write_str(backup_id),
            Self::Aborted { backup_id } => w.write_str(backup_id),
            Self::Status { backup_id } => match backup_id {
                Some(id) => w.write_str(id),
                None => w.write_str(""),
            },
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
            Self::Error { reason } => w.write_str(reason),
        }
        w.finish()
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload = self.encode_payload();
        let header = FrameHeader::with_version(1, self.msg_type(), payload.len() as u32)?;
        let mut out = Vec::with_capacity(crate::frame::HEADER_LEN + payload.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode(msg_type: u8, payload: &[u8]) -> Result<Self> {
        let mut r = WireReader::new(payload);
        let msg = match msg_type {
            T_HELLO => {
                let protocol_version = r.read_u8()?;
                let client_id = r.read_string()?;
                Self::Hello {
                    protocol_version,
                    client_id,
                }
            }
            T_HELLO_ACK => {
                let server_id = r.read_string()?;
                let features = r.read_u64()?;
                Self::HelloAck {
                    server_id,
                    features,
                }
            }
            T_AUTH => {
                let client_id = r.read_string()?;
                let database_id = r.read_string()?;
                Self::Auth {
                    client_id,
                    database_id,
                }
            }
            T_AUTH_OK => Self::AuthOk,
            T_AUTH_FAIL => Self::AuthFail {
                reason: r.read_string()?,
            },
            T_CREATE => Self::Create {
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
                backup_id: r.read_string()?,
                bytes: r.read_bytes()?.to_vec(),
            },
            T_MANIFEST_ACK => Self::ManifestAck {
                backup_id: r.read_string()?,
            },
            T_CHUNK => Self::Chunk {
                backup_id: r.read_string()?,
                sequence: r.read_u32()?,
                hash: r.read_string()?,
                payload: r.read_bytes()?.to_vec(),
            },
            T_CHUNK_ACK => Self::ChunkAck {
                sequence: r.read_u32()?,
            },
            T_VERIFY => Self::Verify {
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
                backup_id: r.read_string()?,
            },
            T_COMMITTED => Self::Committed {
                backup_id: r.read_string()?,
                path: r.read_string()?,
            },
            T_ABORT => Self::Abort {
                backup_id: r.read_string()?,
            },
            T_ABORTED => Self::Aborted {
                backup_id: r.read_string()?,
            },
            T_STATUS => {
                let id = r.read_string()?;
                Self::Status {
                    backup_id: if id.is_empty() { None } else { Some(id) },
                }
            }
            T_STATUS_RESP => Self::StatusResp {
                backup_id: r.read_string()?,
                state: r.read_string()?,
                next_sequence: r.read_u32()?,
                chunk_count: r.read_u32()?,
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

    fn roundtrip(msg: V1Message) {
        let encoded = msg.encode().unwrap();
        let header = crate::frame::FrameHeader::decode(encoded[..10].try_into().unwrap()).unwrap();
        let decoded = V1Message::decode(header.msg_type, &encoded[10..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(V1Message::Hello {
            protocol_version: 1,
            client_id: "cli_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        });
        roundtrip(V1Message::HelloAck {
            server_id: "sas_01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            features: FEATURES_V1,
        });
        roundtrip(V1Message::Auth {
            client_id: "cli_x".into(),
            database_id: "db_x".into(),
        });
        roundtrip(V1Message::AuthOk);
        roundtrip(V1Message::AuthFail {
            reason: "unknown client".into(),
        });
        roundtrip(V1Message::Create {
            backup_id: "bkp_1".into(),
            database_id: "db_1".into(),
            repository: "avrora-prod".into(),
            total_size: 500,
            chunk_size: 64,
            chunk_count: 8,
        });
        roundtrip(V1Message::Created {
            backup_id: "bkp_1".into(),
            resume_from: 3,
            has_manifest: true,
        });
        roundtrip(V1Message::Resume {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::ResumeAck {
            backup_id: "bkp_1".into(),
            last_verified_chunk: 2,
            next_sequence: 3,
            state: "UPLOADING".into(),
            has_manifest: true,
        });
        roundtrip(V1Message::Manifest {
            backup_id: "bkp_1".into(),
            bytes: b"{\"v\":1}".to_vec(),
        });
        roundtrip(V1Message::ManifestAck {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::Chunk {
            backup_id: "bkp_1".into(),
            sequence: 0,
            hash: "blake3:abc".into(),
            payload: vec![1, 2, 3, 4],
        });
        roundtrip(V1Message::ChunkAck { sequence: 0 });
        roundtrip(V1Message::Verify {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::VerifyOk {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::VerifyFail {
            backup_id: "bkp_1".into(),
            mismatches: vec![ChunkMismatch {
                sequence: 2,
                expected: "a".into(),
                actual: "b".into(),
            }],
        });
        roundtrip(V1Message::Commit {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::Committed {
            backup_id: "bkp_1".into(),
            path: "/var/lib/backupsas/repositories/avrora-prod/backups/2026/08/30/backup-01".into(),
        });
        roundtrip(V1Message::Abort {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::Aborted {
            backup_id: "bkp_1".into(),
        });
        roundtrip(V1Message::Status { backup_id: None });
        roundtrip(V1Message::Status {
            backup_id: Some("bkp_1".into()),
        });
        roundtrip(V1Message::StatusResp {
            backup_id: "bkp_1".into(),
            state: "COMPLETE".into(),
            next_sequence: 8,
            chunk_count: 8,
        });
        roundtrip(V1Message::Error {
            reason: "boom".into(),
        });
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = V1Message::AuthOk.encode().unwrap();
        buf[0] = b'X';
        let err = crate::frame::FrameHeader::decode(buf[..10].try_into().unwrap()).unwrap_err();
        assert!(matches!(err, BackupSasError::Protocol(_)));
    }
}
