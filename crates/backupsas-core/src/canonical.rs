use crate::error::{BackupSasError, Result};
use serde_json::Value;

/// Serialize a JSON value to canonical UTF-8 bytes (no insignificant whitespace, sorted keys).
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                write_u64(u, out);
            } else if let Some(i) = n.as_i64() {
                if i < 0 {
                    return Err(BackupSasError::InvalidManifest(
                        "canonical JSON rejects negative integers".into(),
                    ));
                }
                write_u64(i as u64, out);
            } else {
                return Err(BackupSasError::InvalidManifest(
                    "canonical JSON requires integer numbers".into(),
                ));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&str> = map.keys().map(|k| k.as_str()).collect();
            keys.sort_unstable();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_u64(n: u64, out: &mut Vec<u8>) {
    let mut buf = itoa::Buffer::new();
    out.extend_from_slice(buf.format(n).as_bytes());
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if c.is_control() => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => {
                let mut enc = [0u8; 4];
                let bytes = c.encode_utf8(&mut enc);
                out.extend_from_slice(bytes.as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_sorted() {
        let a = canonical_bytes(&json!({"a":1,"b":2})).unwrap();
        let b = canonical_bytes(&json!({"b":2,"a":1})).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, b"{\"a\":1,\"b\":2}");
    }

    #[test]
    fn no_whitespace() {
        let bytes =
            canonical_bytes(&json!({"chunks":[{"sequence":0,"size":10,"hash":"x"}]})).unwrap();
        assert!(!bytes.contains(&b' '));
        assert!(!bytes.contains(&b'\n'));
    }
}
