use crate::error::{BackupSasError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use ulid::Ulid;

macro_rules! prefixed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Ulid);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            pub fn new() -> Self {
                Self(Ulid::new())
            }

            pub fn from_ulid(ulid: Ulid) -> Self {
                Self(ulid)
            }

            pub fn ulid(&self) -> Ulid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{}", $prefix, self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }

        impl FromStr for $name {
            type Err = BackupSasError;

            fn from_str(s: &str) -> Result<Self> {
                let rest = s.strip_prefix($prefix).ok_or_else(|| {
                    BackupSasError::InvalidId(format!(
                        "expected prefix `{}` in `{s}`",
                        $prefix
                    ))
                })?;
                let ulid = rest.parse::<Ulid>().map_err(|_| {
                    BackupSasError::InvalidId(format!("invalid ULID in `{s}`"))
                })?;
                Ok(Self(ulid))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

prefixed_id!(ServerId, "sas_");
prefixed_id!(BackupId, "bkp_");
prefixed_id!(DatabaseId, "db_");
prefixed_id!(RepositoryId, "repo_");
prefixed_id!(ClientId, "cli_");
prefixed_id!(SessionId, "ses_");

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ParticipantId {
    Server(ServerId),
    Client(ClientId),
}

impl ParticipantId {
    pub fn as_str_owned(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ParticipantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(id) => write!(f, "{id}"),
            Self::Client(id) => write!(f, "{id}"),
        }
    }
}

impl FromStr for ParticipantId {
    type Err = BackupSasError;

    fn from_str(s: &str) -> Result<Self> {
        if s.starts_with(ServerId::PREFIX) {
            return Ok(Self::Server(s.parse()?));
        }
        if s.starts_with(ClientId::PREFIX) {
            return Ok(Self::Client(s.parse()?));
        }
        Err(BackupSasError::InvalidId(format!(
            "expected `{sas}` or `{cli}` prefix in `{s}`",
            sas = ServerId::PREFIX,
            cli = ClientId::PREFIX
        )))
    }
}

impl Serialize for ParticipantId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ParticipantId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl From<ServerId> for ParticipantId {
    fn from(id: ServerId) -> Self {
        Self::Server(id)
    }
}

impl From<ClientId> for ParticipantId {
    fn from(id: ClientId) -> Self {
        Self::Client(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_backup_id() {
        let id = BackupId::new();
        let s = id.to_string();
        assert!(s.starts_with("bkp_"));
        let parsed: BackupId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let sas = ServerId::new().to_string();
        let err = sas.parse::<BackupId>().unwrap_err();
        assert!(matches!(err, BackupSasError::InvalidId(_)));
    }

    #[test]
    fn serde_roundtrip() {
        let id = DatabaseId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: DatabaseId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
