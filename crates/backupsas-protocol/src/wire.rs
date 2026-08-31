use backupsas_core::{BackupSasError, Result};

pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        self.write_u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub struct WireReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(BackupSasError::Protocol("truncated payload".into()));
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let b = self.read_exact(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_u64(&mut self) -> Result<u64> {
        let b = self.read_exact(8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.read_exact(len)
    }

    pub fn read_string(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| BackupSasError::Protocol("invalid utf-8".into()))
    }

    pub fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(BackupSasError::Protocol(format!(
                "trailing payload bytes: {}",
                self.buf.len() - self.pos
            )));
        }
        Ok(())
    }
}
