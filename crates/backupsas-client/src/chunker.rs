use backupsas_core::{BackupSasError, Result};
use std::io::Read;

/// Plaintext chunk. Wiped on drop; `Debug` shows only the length.
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct Chunk {
    #[zeroize(skip)]
    pub sequence: u32,
    pub plaintext: Vec<u8>,
}

impl std::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chunk")
            .field("sequence", &self.sequence)
            .field("plaintext_len", &self.plaintext.len())
            .finish()
    }
}

pub fn chunk_reader<R: Read>(reader: R, chunk_size: usize) -> Result<Vec<Chunk>> {
    ChunkIter::new(reader, chunk_size).collect()
}

pub struct ChunkIter<R> {
    reader: R,
    chunk_size: usize,
    sequence: u32,
    done: bool,
}

impl<R: Read> ChunkIter<R> {
    pub fn new(reader: R, chunk_size: usize) -> Self {
        Self {
            reader,
            chunk_size: chunk_size.max(1),
            sequence: 0,
            done: false,
        }
    }
}

impl<R: Read> Iterator for ChunkIter<R> {
    type Item = Result<Chunk>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let mut buf = vec![0u8; self.chunk_size];
        let mut filled = 0;
        while filled < self.chunk_size {
            match self.reader.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.done = true;
                    return Some(Err(BackupSasError::Io(e)));
                }
            }
        }
        if filled == 0 {
            self.done = true;
            return None;
        }
        buf.truncate(filled);
        let sequence = self.sequence;
        self.sequence += 1;
        Some(Ok(Chunk {
            sequence,
            plaintext: buf,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn splits_and_handles_remainder() {
        let data = vec![1u8; 50];
        let chunks = chunk_reader(Cursor::new(data), 16).unwrap();
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].plaintext.len(), 16);
        assert_eq!(chunks[3].plaintext.len(), 2);
        assert_eq!(chunks[3].sequence, 3);
    }

    #[test]
    fn empty_reader() {
        let chunks = chunk_reader(Cursor::new(Vec::<u8>::new()), 16).unwrap();
        assert!(chunks.is_empty());
    }
}
