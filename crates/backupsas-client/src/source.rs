use backupsas_core::Result;

/// Client-side metadata about a backup source (untrusted on server; used for header.json hints).
#[derive(Debug, Clone, Default)]
pub struct BackupSourceMetadata {
    pub label: Option<String>,
    pub source_type: Option<String>,
}

/// Readable backup payload for upload. Implementations must be `Send` for async client use.
pub trait BackupSource: Send {
    fn metadata(&self) -> Result<BackupSourceMetadata>;
    fn total_size(&self) -> u64;
    fn read_range(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>;
}

/// In-memory backup source for tests and SDK reference implementation.
#[derive(Debug, Clone)]
pub struct MemoryBackupSource {
    data: Vec<u8>,
    label: Option<String>,
}

impl MemoryBackupSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            label: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

impl BackupSource for MemoryBackupSource {
    fn metadata(&self) -> Result<BackupSourceMetadata> {
        Ok(BackupSourceMetadata {
            label: self.label.clone(),
            source_type: Some("memory".into()),
        })
    }

    fn total_size(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_range(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let start = offset as usize;
        if start > self.data.len() {
            return Ok(Vec::new());
        }
        let end = start.saturating_add(len).min(self.data.len());
        Ok(self.data[start..end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_source_reads_ranges() {
        let mut src = MemoryBackupSource::new(b"hello-world".to_vec());
        assert_eq!(src.total_size(), 11);
        assert_eq!(src.read_range(0, 5).unwrap(), b"hello");
        assert_eq!(src.read_range(6, 5).unwrap(), b"world");
    }
}
