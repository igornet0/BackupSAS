use crate::connection::Connection;
use backupsas_core::{
    BackupSasConfig, BackupSasError, PublicKey, Result, SessionId, SessionInfo, crypto,
    envelope::AuthProof, pin_matches,
};
use backupsas_protocol::{Message, PROTOCOL_VERSION};

pub struct AuthenticatedSession {
    pub conn: Connection,
    pub session_id: SessionId,
    pub info: SessionInfo,
}

pub async fn authenticate(config: &BackupSasConfig) -> Result<AuthenticatedSession> {
    let mut conn = Connection::connect(config).await?;

    conn.send(&Message::Hello {
        protocol_version: PROTOCOL_VERSION,
        client_id: config.client_identity.id.to_string(),
        client_public_key: config.client_identity.public_key.to_bytes().to_vec(),
    })
    .await?;

    let Message::HelloAck {
        server_id,
        server_public_key,
        nonce,
        ..
    } = conn.recv().await?
    else {
        return Err(BackupSasError::Protocol("expected HELLO_ACK".into()));
    };

    if server_id != config.server_id.to_string() {
        return Err(BackupSasError::TrustPinMismatch {
            expected: config.server_id.to_string(),
            actual: server_id,
        });
    }
    let server_pk = PublicKey::from_bytes(
        server_public_key
            .as_slice()
            .try_into()
            .map_err(|_| BackupSasError::Auth("invalid server public key length".into()))?,
    )?;
    pin_matches(&config.server_public_key, &server_pk)?;

    let Message::ServerProof {
        timestamp,
        signature,
    } = conn.recv().await?
    else {
        return Err(BackupSasError::Protocol("expected SERVER_PROOF".into()));
    };
    let server_proof = AuthProof {
        timestamp,
        signature: signature
            .as_slice()
            .try_into()
            .map_err(|_| BackupSasError::Auth("invalid server signature length".into()))?,
    };
    server_proof.verify(&server_pk, &server_id, &nonce)?;

    if let Some(secret) = &config.bootstrap_secret {
        conn.send(&Message::Enroll {
            client_id: config.client_identity.id.to_string(),
            client_public_key: config.client_identity.public_key.to_bytes().to_vec(),
            bootstrap_secret: secret.as_str().into(),
        })
        .await?;
        match conn.recv().await? {
            Message::EnrollChallenge {
                nonce: enroll_nonce,
            } => {
                let bootstrap_proof = secret.proof(&enroll_nonce);
                let mut signed = Vec::new();
                signed.extend_from_slice(&enroll_nonce);
                signed.extend_from_slice(config.client_identity.id.to_string().as_bytes());
                signed.extend_from_slice(bootstrap_proof.as_bytes());
                let signature = config.client_identity.sign(&signed);
                conn.send(&Message::EnrollProof {
                    signature: signature.to_vec(),
                    bootstrap_proof,
                })
                .await?;
                match conn.recv().await? {
                    Message::EnrollOk { .. } => {}
                    Message::EnrollFail { reason } => {
                        return Err(BackupSasError::Enrollment(reason));
                    }
                    other => {
                        return Err(BackupSasError::Protocol(format!(
                            "unexpected {}",
                            other.type_name()
                        )));
                    }
                }
            }
            Message::EnrollFail { reason } => {
                // Already enrolled / secret consumed — continue if we can authenticate.
                if !reason.contains("no longer available") && !reason.contains("already") {
                    return Err(BackupSasError::Enrollment(reason));
                }
            }
            other => {
                return Err(BackupSasError::Protocol(format!(
                    "unexpected {}",
                    other.type_name()
                )));
            }
        }
    }

    let client_proof = AuthProof::create(&config.client_identity, &nonce);
    conn.send(&Message::ClientProof {
        timestamp: client_proof.timestamp,
        signature: client_proof.signature.to_vec(),
    })
    .await?;

    match conn.recv().await? {
        Message::AuthOk => {}
        Message::AuthFail { reason } => return Err(BackupSasError::Auth(reason)),
        other => {
            return Err(BackupSasError::Protocol(format!(
                "unexpected {}",
                other.type_name()
            )));
        }
    }

    let session_id = SessionId::new();
    let client_nonce = crypto::random_nonce();
    let server_nonce = crypto::random_nonce();
    conn.send(&Message::SessionOpen {
        session_id: session_id.to_string(),
        client_nonce: client_nonce.to_vec(),
        server_nonce: server_nonce.to_vec(),
    })
    .await?;
    match conn.recv().await? {
        Message::SessionOk {
            session_id: sid, ..
        } if sid == session_id.to_string() => {}
        Message::Error { reason } => return Err(BackupSasError::Session(reason)),
        other => {
            return Err(BackupSasError::Protocol(format!(
                "unexpected {}",
                other.type_name()
            )));
        }
    }

    let info = SessionInfo::new(session_id);
    let _ = crypto::derive_session_keys(
        &session_id,
        &client_proof.signature,
        &server_proof.signature,
        &client_nonce,
        &server_nonce,
    )?;

    Ok(AuthenticatedSession {
        conn,
        session_id,
        info,
    })
}
