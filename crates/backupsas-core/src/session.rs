use crate::id::SessionId;
use time::OffsetDateTime;
use zeroize::ZeroizeOnDrop;

pub const SESSION_TTL_SECS: i64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Open,
    Expired,
    Closed,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub mac_key: [u8; 32],
    pub confirm_key: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys([redacted])")
    }
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl SessionInfo {
    pub fn new(session_id: SessionId) -> Self {
        let created_at = OffsetDateTime::now_utc();
        let expires_at = created_at + time::Duration::seconds(SESSION_TTL_SECS);
        Self {
            session_id,
            created_at,
            expires_at,
        }
    }

    pub fn is_active(&self) -> bool {
        OffsetDateTime::now_utc() < self.expires_at
    }

    pub fn state(&self) -> SessionState {
        if self.is_active() {
            SessionState::Open
        } else {
            SessionState::Expired
        }
    }
}
