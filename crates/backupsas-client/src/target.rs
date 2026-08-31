use backupsas_core::{BackupId, DatabaseId, Result};

/// Audit hints passed to a restore target before payload write.
///
/// Sourced from the trusted manifest during restore — not from untrusted `metadata.json`.
#[derive(Debug, Clone, Default)]
pub struct RestoreMetadata {
    pub backup_id: Option<BackupId>,
    pub database_id: Option<DatabaseId>,
    pub total_size: u64,
    pub chunk_count: u32,
    pub label: Option<String>,
}

/// Writable restore destination. Implementations must be `Send` for async client use.
pub trait RestoreTarget: Send {
    fn metadata(&mut self, metadata: &RestoreMetadata) -> Result<()>;
    fn write_range(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    fn finalize(&mut self) -> Result<()>;
}

/// In-memory restore target for tests and SDK reference implementation.
#[derive(Debug, Clone)]
pub struct MemoryRestoreTarget {
    data: Vec<u8>,
    metadata: Option<RestoreMetadata>,
}

impl MemoryRestoreTarget {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            metadata: None,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            metadata: None,
        }
    }

    pub fn restore_metadata(&self) -> Option<&RestoreMetadata> {
        self.metadata.as_ref()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl Default for MemoryRestoreTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl RestoreTarget for MemoryRestoreTarget {
    fn metadata(&mut self, metadata: &RestoreMetadata) -> Result<()> {
        self.metadata = Some(metadata.clone());
        if metadata.total_size > 0 {
            self.data.resize(metadata.total_size as usize, 0);
        }
        Ok(())
    }

    fn write_range(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let start = offset as usize;
        let end = start.saturating_add(data.len());
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(data);
        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        if let Some(meta) = &self.metadata {
            if meta.total_size > 0 && self.data.len() as u64 > meta.total_size {
                self.data.truncate(meta.total_size as usize);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_target_writes_ranges() {
        let mut target = MemoryRestoreTarget::new();
        target
            .metadata(&RestoreMetadata {
                total_size: 11,
                ..Default::default()
            })
            .unwrap();
        target.write_range(0, b"hello").unwrap();
        target.write_range(5, b"-world").unwrap();
        target.finalize().unwrap();
        assert_eq!(target.bytes(), b"hello-world");
    }

    #[test]
    fn memory_target_extends_on_out_of_order_write() {
        let mut target = MemoryRestoreTarget::new();
        target.write_range(5, b"tail").unwrap();
        assert_eq!(target.bytes(), b"\0\0\0\0\0tail");
    }
}
