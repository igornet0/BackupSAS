//! Outgoing node-to-node transfer (`move` / `copy`).
//!
//! Ciphertext is pushed as-is: this node never holds the owner's data key.
//! After the target commits, a signed [`RelocationNotice`] is recorded per
//! owner so the database can learn the new location on its next sync.

use crate::peers::{PeerStore, peer_client_config};
use crate::relocations::RelocationStore;
use crate::trust::TrustStore;
use backupsas_client::{BackupSasClient, TransferOffer};
use backupsas_core::{
    BackupId, BackupSasError, ClientId, Identity, ParticipantId, RelocationNotice, Result,
    ServerConfig, TransferMode,
};
use backupsas_storage::StorageRoot;
use std::collections::BTreeMap;
use tracing::info;

#[derive(Debug, Clone)]
pub struct TransferRequest {
    pub peer: String,
    pub repository: String,
    /// `None` transfers every complete backup in the repository.
    pub backup_ids: Option<Vec<BackupId>>,
    pub mode: TransferMode,
}

#[derive(Debug, Clone)]
pub struct TransferReport {
    pub transferred: Vec<BackupId>,
    pub notices: Vec<RelocationNotice>,
}

pub async fn run_transfer(config: &ServerConfig, req: &TransferRequest) -> Result<TransferReport> {
    let data_dir = config.data_dir.as_path();
    let identity = Identity::load(&data_dir.join("identity"))?;
    let ParticipantId::Server(source_server_id) = identity.id else {
        return Err(BackupSasError::Other(
            "node identity is not a server".into(),
        ));
    };
    let peer = PeerStore::open(data_dir)?.get(&req.peer)?;
    if peer.descriptor.server_id == source_server_id {
        return Err(BackupSasError::Other("cannot transfer to self".into()));
    }
    let storage = StorageRoot::open(config)?;
    let repo = storage.repo(&req.repository)?;
    let trust = TrustStore::load(&data_dir.join("trusted"))?;
    let relocations = RelocationStore::open(data_dir)?;

    let wanted: Vec<BackupId> = match &req.backup_ids {
        Some(ids) => ids.clone(),
        None => repo
            .list_complete()?
            .into_iter()
            .map(|(_, m)| m.backup_id)
            .collect(),
    };
    if wanted.is_empty() {
        return Ok(TransferReport {
            transferred: vec![],
            notices: vec![],
        });
    }

    let cfg = peer_client_config(data_dir, &peer, None)?;
    let mut session = BackupSasClient::new(cfg).authenticate().await?;
    let transfer_id = format!("trf_{}", ulid_like());

    let mut by_owner: BTreeMap<ClientId, Vec<BackupId>> = BTreeMap::new();
    for backup_id in &wanted {
        if relocations.is_moved_away(backup_id)? {
            return Err(BackupSasError::Other(format!(
                "backup {backup_id} was already moved away"
            )));
        }
        let (_, meta) = repo.complete_metadata(backup_id)?;
        let owner = trust.get(&meta.client_id).ok_or_else(|| {
            BackupSasError::Auth(format!(
                "owner {} of {backup_id} is not in the trust store",
                meta.client_id
            ))
        })?;
        let manifest_bytes = repo.read_manifest_bytes(backup_id)?;
        let offer = TransferOffer {
            transfer_id: transfer_id.clone(),
            mode: req.mode,
            repository: peer.repository.clone(),
            owner_client_id: meta.client_id.to_string(),
            owner_public_key: owner.public_key.to_bytes().to_vec(),
        };
        let owner_id = meta.client_id;
        session
            .push_encrypted(&offer, &manifest_bytes, |seq| {
                repo.read_complete_chunk(backup_id, owner_id, seq)
            })
            .await?;
        info!(%backup_id, peer = %req.peer, mode = %req.mode, "backup transferred");
        by_owner.entry(owner_id).or_default().push(*backup_id);
    }
    session.close().await?;

    let mut notices = Vec::new();
    for (i, (owner, backup_ids)) in by_owner.into_iter().enumerate() {
        let notice = RelocationNotice {
            relocation_id: format!("rel_{}_{i}", ulid_like()),
            mode: req.mode,
            source_server_id,
            owner_client_id: owner,
            repository: req.repository.clone(),
            backup_ids,
            target: peer.descriptor.clone(),
            target_repository: peer.repository.clone(),
            created_at: backupsas_core::crypto::timestamp_now(),
            signature: String::new(),
        }
        .sign(&identity)?;
        relocations.insert(notice.clone())?;
        notices.push(notice);
    }

    Ok(TransferReport {
        transferred: wanted,
        notices,
    })
}

fn ulid_like() -> String {
    // BackupId is a ULID; reuse its generator without the `bkp_` prefix.
    BackupId::new().ulid().to_string()
}

/// Delete locally the backups listed in an acknowledged `move` notice.
pub fn finalize_move(storage: &StorageRoot, notice: &RelocationNotice) -> Result<()> {
    if notice.mode != TransferMode::Move {
        return Ok(());
    }
    let repo = storage.repo(&notice.repository)?;
    for id in &notice.backup_ids {
        match repo.delete_complete(id) {
            Ok(()) | Err(BackupSasError::BackupNotFound(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
