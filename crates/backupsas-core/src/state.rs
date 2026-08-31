use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupState {
    Creating,
    Uploading,
    Verifying,
    Complete,
    Aborted,
}

impl BackupState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "CREATING",
            Self::Uploading => "UPLOADING",
            Self::Verifying => "VERIFYING",
            Self::Complete => "COMPLETE",
            Self::Aborted => "ABORTED",
        }
    }
}

impl std::fmt::Display for BackupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
