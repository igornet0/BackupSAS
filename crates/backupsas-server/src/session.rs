use crate::ServerState;
use backupsas_core::{
    crypto, envelope::AuthProof, pin_matches, BackupId, BackupSasError, BackupState, ClientId,
    DatabaseId, EnrollmentRecord, EnrollmentSecret, ParticipantId, PublicKey, Result, SessionId,
    SessionInfo, TrustedPeer, DEFAULT_REPO_NAME,
};
use backupsas_protocol::{
    read_frame, write_frame, ChunkMismatch, Message, FEATURES_V2,
};
use backupsas_storage::{BackupRecord, CreateUpload};
use tokio::io::{split, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info};

pub async fn run_session(stream: TlsStream<TcpStream>, state: ServerState) -> Result<()> {
    let (mut reader, mut writer) = split(stream);

    let hello = read_frame(&mut reader).await?;
    let Message::Hello {
        client_id,
        client_public_key,
        ..
    } = hello
    else {
        return send_error(&mut writer, "expected HELLO").await;
    };

    let client_id: ClientId = client_id.parse()?;
    let client_pk = PublicKey::from_bytes(to_array32(&client_public_key)?)?;
    let server_nonce = crypto::random_nonce();

    write_frame(
        &mut writer,
        &Message::HelloAck {
            server_id: state.identity.id.to_string(),
            server_public_key: state.identity.public_key.to_bytes().to_vec(),
            features: FEATURES_V2,
            nonce: server_nonce.to_vec(),
        },
    )
    .await?;

    let server_proof = AuthProof::create(&state.identity, &server_nonce);
    write_frame(
        &mut writer,
        &Message::ServerProof {
            timestamp: server_proof.timestamp,
            signature: server_proof.signature.to_vec(),
        },
    )
    .await?;

    loop {
        let msg = read_frame(&mut reader).await?;
        match msg {
            Message::Enroll {
                client_id: enroll_id,
                client_public_key: enroll_pk,
                bootstrap_secret,
            } => {
                handle_enroll(
                    &mut reader,
                    &mut writer,
                    &state,
                    enroll_id.parse()?,
                    PublicKey::from_bytes(to_array32(&enroll_pk)?)?,
                    bootstrap_secret,
                )
                .await?;
            }
            Message::ClientProof {
                timestamp,
                signature,
            } => {
                let proof = AuthProof {
                    timestamp,
                    signature: to_array64(&signature)?,
                };
                return finish_auth(
                    &mut reader,
                    &mut writer,
                    &state,
                    client_id,
                    client_pk,
                    &server_nonce,
                    proof,
                )
                .await;
            }
            other => {
                return send_error(
                    &mut writer,
                    &format!("expected ENROLL or CLIENT_PROOF, got {}", other.type_name()),
                )
                .await;
            }
        }
    }
}

async fn handle_enroll(
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    state: &ServerState,
    client_id: ClientId,
    public_key: PublicKey,
    bootstrap_secret: String,
) -> Result<()> {
    let secret = match EnrollmentSecret::parse(bootstrap_secret) {
        Ok(s) => s,
        Err(e) => {
            write_frame(
                writer,
                &Message::EnrollFail {
                    reason: e.to_string(),
                },
            )
            .await?;
            return Ok(());
        }
    };

    let path = crate::enrollment_path(&state.config.data_dir);
    let record = match EnrollmentRecord::load(&path) {
        Ok(r) => r,
        Err(_) => {
            write_frame(
                writer,
                &Message::EnrollFail {
                    reason: "enrollment secret is no longer available".into(),
                },
            )
            .await?;
            return Ok(());
        }
    };
    if !record.matches(&secret) {
        write_frame(
            writer,
            &Message::EnrollFail {
                reason: "bootstrap secret mismatch".into(),
            },
        )
        .await?;
        return Ok(());
    }

    let pending_nonce = crypto::random_nonce();
    write_frame(
        writer,
        &Message::EnrollChallenge {
            nonce: pending_nonce.to_vec(),
        },
    )
    .await?;

    let Message::EnrollProof {
        signature,
        bootstrap_proof,
    } = read_frame(reader).await?
    else {
        write_frame(
            writer,
            &Message::EnrollFail {
                reason: "expected ENROLL_PROOF".into(),
            },
        )
        .await?;
        return Ok(());
    };

    let expected_proof = secret.proof(&pending_nonce);
    if !crypto::constant_time_eq(expected_proof.as_bytes(), bootstrap_proof.as_bytes()) {
        write_frame(
            writer,
            &Message::EnrollFail {
                reason: "bootstrap proof mismatch".into(),
            },
        )
        .await?;
        return Ok(());
    }

    let mut signed = Vec::new();
    signed.extend_from_slice(&pending_nonce);
    signed.extend_from_slice(client_id.to_string().as_bytes());
    signed.extend_from_slice(bootstrap_proof.as_bytes());
    if let Err(e) = crypto::verify(&public_key, &signed, &signature) {
        write_frame(
            writer,
            &Message::EnrollFail {
                reason: e.to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    let repos: Vec<String> = state
        .config
        .repositories
        .iter()
        .map(|r| r.name.clone())
        .collect();
    let repos = if repos.is_empty() {
        vec![DEFAULT_REPO_NAME.to_string()]
    } else {
        repos
    };
    let peer = TrustedPeer::new(ParticipantId::Client(client_id), public_key, repos);
    {
        let mut trust = state
            .trust
            .lock()
            .map_err(|_| BackupSasError::Other("trust lock poisoned".into()))?;
        trust.insert(peer)?;
    }
    let _ = std::fs::remove_file(path);

    write_frame(
        writer,
        &Message::EnrollOk {
            client_id: client_id.to_string(),
        },
    )
    .await?;
    info!(%client_id, "client enrolled");
    Ok(())
}

async fn finish_auth(
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    state: &ServerState,
    client_id: ClientId,
    client_pk: PublicKey,
    server_nonce: &[u8],
    proof: AuthProof,
) -> Result<()> {
    let peer = {
        let trust = state
            .trust
            .lock()
            .map_err(|_| BackupSasError::Other("trust lock poisoned".into()))?;
        trust.get(&client_id).cloned()
    };
    let Some(peer) = peer else {
        write_frame(
            writer,
            &Message::AuthFail {
                reason: "unknown client identity".into(),
            },
        )
        .await?;
        return Ok(());
    };
    pin_matches(&peer.public_key, &client_pk)?;
    if let Err(e) = proof.verify(&peer.public_key, &client_id.to_string(), server_nonce) {
        write_frame(
            writer,
            &Message::AuthFail {
                reason: e.to_string(),
            },
        )
        .await?;
        return Ok(());
    }

    write_frame(writer, &Message::AuthOk).await?;
    info!(%client_id, "client authenticated");

    let session_msg = read_frame(reader).await?;
    let Message::SessionOpen {
        session_id,
        client_nonce,
        server_nonce: open_server_nonce,
    } = session_msg
    else {
        return send_error(writer, "expected SESSION_OPEN").await;
    };
    let session_id: SessionId = session_id.parse()?;
    let info = SessionInfo::new(session_id);
    let _ = crypto::derive_session_keys(
        &session_id,
        &proof.signature,
        &state.identity.sign(&crypto::proof_message(
            server_nonce,
            &state.identity.id.to_string(),
            proof.timestamp,
        )),
        &client_nonce,
        &open_server_nonce,
    )?;
    write_frame(
        writer,
        &Message::SessionOk {
            session_id: session_id.to_string(),
            expires_at: info.expires_at.unix_timestamp() as u64,
        },
    )
    .await?;

    handle_ready(
        reader,
        writer,
        state,
        &peer.repositories,
        client_id,
        session_id,
        info,
    )
    .await
}

async fn handle_ready(
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    state: &ServerState,
    allowed_repos: &[String],
    client_id: ClientId,
    session_id: SessionId,
    info: SessionInfo,
) -> Result<()> {
    loop {
        if !info.is_active() {
            return send_error(writer, "session expired").await;
        }
        let msg = match read_frame(reader).await {
            Ok(m) => m,
            Err(BackupSasError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected");
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        debug!(msg = msg.type_name(), "received");
        match msg {
            Message::Create {
                session_id: sid,
                backup_id,
                database_id,
                repository,
                total_size,
                chunk_size,
                chunk_count,
            } => {
                require_session(&sid, &session_id)?;
                if !allowed_repos.iter().any(|r| r == &repository) {
                    write_frame(
                        writer,
                        &Message::Error {
                            reason: format!(
                                "client is not allowed to use repository `{repository}`"
                            ),
                        },
                    )
                    .await?;
                    return Ok(());
                }
                let backup_id: BackupId = backup_id.parse()?;
                let database_id: DatabaseId = database_id.parse()?;
                let repo = state.storage.repo(&repository)?;
                let session = repo.create_upload(CreateUpload {
                    backup_id,
                    database_id,
                    client_id,
                    total_size,
                    chunk_size,
                    chunk_count,
                })?;
                write_frame(
                    writer,
                    &Message::Created {
                        backup_id: backup_id.to_string(),
                        resume_from: session.next_sequence,
                        has_manifest: session.has_manifest,
                    },
                )
                .await?;
                handle_upload(reader, writer, state, &repository, backup_id, &session_id).await?;
            }
            Message::Resume {
                session_id: sid,
                backup_id,
            } => {
                require_session(&sid, &session_id)?;
                let backup_id: BackupId = backup_id.parse()?;
                let (repo, record) = state.storage.find_backup(&backup_id)?;
                let session = match record {
                    BackupRecord::Uploading(s) => s,
                    BackupRecord::Complete { .. } => {
                        write_frame(
                            writer,
                            &Message::Error {
                                reason: format!("backup {backup_id} is already complete"),
                            },
                        )
                        .await?;
                        continue;
                    }
                };
                write_frame(
                    writer,
                    &Message::ResumeAck {
                        backup_id: backup_id.to_string(),
                        last_verified_chunk: session.last_verified_chunk(),
                        next_sequence: session.next_sequence,
                        state: session.state.as_str().to_string(),
                        has_manifest: session.has_manifest,
                    },
                )
                .await?;
                handle_upload(reader, writer, state, repo.name(), backup_id, &session_id).await?;
            }
            Message::Status {
                session_id: sid,
                backup_id,
            } => {
                require_session(&sid, &session_id)?;
                match backup_id {
                    Some(id) => {
                        let backup_id: BackupId = id.parse()?;
                        match state.storage.find_backup(&backup_id) {
                            Ok((_, record)) => {
                                write_frame(writer, &status_resp(&backup_id, &record)).await?;
                            }
                            Err(e) => {
                                write_frame(
                                    writer,
                                    &Message::Error {
                                        reason: e.to_string(),
                                    },
                                )
                                .await?;
                            }
                        }
                    }
                    None => {
                        write_frame(
                            writer,
                            &Message::StatusResp {
                                backup_id: String::new(),
                                state: format!("server:{}", state.config.server_id),
                                next_sequence: 0,
                                chunk_count: 0,
                            },
                        )
                        .await?;
                    }
                }
            }
            Message::Abort {
                session_id: sid,
                backup_id,
            } => {
                require_session(&sid, &session_id)?;
                let backup_id: BackupId = backup_id.parse()?;
                if let Ok((repo, _)) = state.storage.find_backup(&backup_id) {
                    repo.abort(&backup_id)?;
                }
                write_frame(
                    writer,
                    &Message::Aborted {
                        backup_id: backup_id.to_string(),
                    },
                )
                .await?;
            }
            Message::SessionClose { .. } => return Ok(()),
            other => {
                write_frame(
                    writer,
                    &Message::Error {
                        reason: format!("unexpected message {}", other.type_name()),
                    },
                )
                .await?;
                return Ok(());
            }
        }
    }
}

async fn handle_upload(
    reader: &mut ReadHalf<TlsStream<TcpStream>>,
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    state: &ServerState,
    repository: &str,
    backup_id: BackupId,
    session_id: &SessionId,
) -> Result<()> {
    let repo = state.storage.repo(repository)?;
    loop {
        let msg = match read_frame(reader).await {
            Ok(m) => m,
            Err(BackupSasError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        match msg {
            Message::Manifest {
                session_id: sid,
                backup_id: id,
                bytes,
            } => {
                require_session(&sid, session_id)?;
                if id != backup_id.to_string() {
                    return send_error(writer, "manifest backup_id mismatch").await;
                }
                repo.store_manifest(&backup_id, &bytes)?;
                write_frame(
                    writer,
                    &Message::ManifestAck {
                        backup_id: backup_id.to_string(),
                    },
                )
                .await?;
            }
            Message::Chunk {
                session_id: sid,
                backup_id: id,
                sequence,
                hash,
                payload,
            } => {
                require_session(&sid, session_id)?;
                if id != backup_id.to_string() {
                    return send_error(writer, "chunk backup_id mismatch").await;
                }
                match repo.write_chunk(&backup_id, sequence, &hash, &payload) {
                    Ok(_) => write_frame(writer, &Message::ChunkAck { sequence }).await?,
                    Err(e) => {
                        write_frame(
                            writer,
                            &Message::Error {
                                reason: e.to_string(),
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }
            Message::Verify {
                session_id: sid,
                backup_id: id,
            } => {
                require_session(&sid, session_id)?;
                if id != backup_id.to_string() {
                    return send_error(writer, "verify backup_id mismatch").await;
                }
                let report = repo.verify(&backup_id)?;
                if report.ok {
                    write_frame(
                        writer,
                        &Message::VerifyOk {
                            backup_id: backup_id.to_string(),
                        },
                    )
                    .await?;
                } else {
                    write_frame(
                        writer,
                        &Message::VerifyFail {
                            backup_id: backup_id.to_string(),
                            mismatches: report
                                .mismatches
                                .into_iter()
                                .map(|(sequence, expected, actual)| ChunkMismatch {
                                    sequence,
                                    expected,
                                    actual,
                                })
                                .collect(),
                        },
                    )
                    .await?;
                }
            }
            Message::Commit {
                session_id: sid,
                backup_id: id,
            } => {
                require_session(&sid, session_id)?;
                if id != backup_id.to_string() {
                    return send_error(writer, "commit backup_id mismatch").await;
                }
                match repo.commit(&backup_id) {
                    Ok(path) => {
                        write_frame(
                            writer,
                            &Message::Committed {
                                backup_id: backup_id.to_string(),
                                path: path.display().to_string(),
                            },
                        )
                        .await?;
                        info!(%backup_id, path = %path.display(), "backup committed");
                        return Ok(());
                    }
                    Err(e) => {
                        write_frame(
                            writer,
                            &Message::Error {
                                reason: e.to_string(),
                            },
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }
            Message::Abort {
                session_id: sid,
                backup_id: id,
            } => {
                require_session(&sid, session_id)?;
                let id: BackupId = id.parse()?;
                repo.abort(&id)?;
                write_frame(
                    writer,
                    &Message::Aborted {
                        backup_id: id.to_string(),
                    },
                )
                .await?;
                return Ok(());
            }
            other => {
                write_frame(
                    writer,
                    &Message::Error {
                        reason: format!("unexpected during upload: {}", other.type_name()),
                    },
                )
                .await?;
                return Ok(());
            }
        }
    }
}

fn require_session(got: &str, expected: &SessionId) -> Result<()> {
    if got != expected.to_string() {
        return Err(BackupSasError::Session("session_id mismatch".into()));
    }
    Ok(())
}

fn status_resp(backup_id: &BackupId, record: &BackupRecord) -> Message {
    match record {
        BackupRecord::Uploading(s) => Message::StatusResp {
            backup_id: backup_id.to_string(),
            state: s.state.as_str().to_string(),
            next_sequence: s.next_sequence,
            chunk_count: s.chunk_count,
        },
        BackupRecord::Complete { metadata, .. } => Message::StatusResp {
            backup_id: backup_id.to_string(),
            state: BackupState::Complete.as_str().to_string(),
            next_sequence: metadata.chunk_count,
            chunk_count: metadata.chunk_count,
        },
    }
}

fn to_array32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| BackupSasError::Auth("expected 32-byte public key".into()))
}

fn to_array64(bytes: &[u8]) -> Result<[u8; 64]> {
    bytes
        .try_into()
        .map_err(|_| BackupSasError::Auth("expected 64-byte signature".into()))
}

async fn send_error(
    writer: &mut WriteHalf<TlsStream<TcpStream>>,
    reason: &str,
) -> Result<()> {
    write_frame(
        writer,
        &Message::Error {
            reason: reason.into(),
        },
    )
    .await?;
    Ok(())
}
