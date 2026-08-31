use crate::frame::{FrameHeader, HEADER_LEN};
use crate::message::Message;
use backupsas_core::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message> {
    let mut header_buf = [0u8; HEADER_LEN];
    reader.read_exact(&mut header_buf).await?;
    let header = FrameHeader::decode(&header_buf)?;
    let mut payload = vec![0u8; header.payload_len as usize];
    if header.payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Message::decode(header.msg_type, &payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, msg: &Message) -> Result<()> {
    let bytes = msg.encode()?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;

    #[tokio::test]
    async fn async_roundtrip() {
        let msg = Message::ChunkAck { sequence: 42 };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();
        let decoded = read_frame(&mut buf.as_slice()).await.unwrap();
        assert_eq!(msg, decoded);
    }
}
