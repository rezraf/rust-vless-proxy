use rand::Rng;

/// Modify TLS ClientHello to use a fake SNI while connecting to the real server.
///
/// Finds the SNI extension in the raw ClientHello bytes and replaces the
/// server name with `fake_sni`. This is "domain fronting" — the outer
/// (plaintext) SNI shows a legitimate domain, while the actual connection
/// goes to our proxy server.
///
/// Returns `true` if the SNI was successfully replaced.
/// Only works when `fake_sni` has the same byte length as the original SNI.
pub fn replace_sni_in_client_hello(data: &mut [u8], fake_sni: &str) -> bool {
    if data.len() < 5 || data[0] != 0x16 {
        return false;
    }

    let fake_bytes = fake_sni.as_bytes();

    let mut i = 5; // Skip TLS record header
    if i >= data.len() || data[i] != 0x01 {
        return false; // Not ClientHello
    }
    i += 4; // Skip handshake type + length

    if i + 2 > data.len() {
        return false;
    }
    i += 2; // client version
    i += 32; // random

    if i >= data.len() {
        return false;
    }
    let session_id_len = data[i] as usize;
    i += 1 + session_id_len;

    if i + 2 > data.len() {
        return false;
    }
    let cipher_suites_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2 + cipher_suites_len;

    if i >= data.len() {
        return false;
    }
    let compression_len = data[i] as usize;
    i += 1 + compression_len;

    if i + 2 > data.len() {
        return false;
    }
    let extensions_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;

    let extensions_end = i + extensions_len;

    while i + 4 <= extensions_end && i + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[i], data[i + 1]]);
        let ext_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;

        if ext_type == 0x0000 {
            let sni_start = i + 4;
            if sni_start + 5 > data.len() {
                return false;
            }

            let name_len =
                u16::from_be_bytes([data[sni_start + 3], data[sni_start + 4]]) as usize;
            let name_start = sni_start + 5;

            if name_start + name_len > data.len() || fake_bytes.len() != name_len {
                return false;
            }

            data[name_start..name_start + name_len].copy_from_slice(fake_bytes);
            return true;
        }

        i += 4 + ext_len;
    }

    false
}

/// Split a TLS record into multiple smaller valid TLS records.
///
/// Some DPI systems only inspect the first TLS record. By splitting the
/// ClientHello across multiple records, the SNI is hidden from simple
/// inspection.
pub fn split_tls_record(data: &[u8], max_fragment: usize) -> Vec<Vec<u8>> {
    if data.len() < 5 || max_fragment == 0 {
        return vec![data.to_vec()];
    }

    let record_type = data[0];
    let version = [data[1], data[2]];
    let payload = &data[5..];

    if payload.len() <= max_fragment {
        return vec![data.to_vec()];
    }

    let mut records = Vec::new();
    let mut offset = 0;

    while offset < payload.len() {
        let chunk_end = (offset + max_fragment).min(payload.len());
        let chunk = &payload[offset..chunk_end];
        let chunk_len = chunk.len() as u16;

        let mut record = Vec::with_capacity(5 + chunk.len());
        record.push(record_type);
        record.extend_from_slice(&version);
        record.extend_from_slice(&chunk_len.to_be_bytes());
        record.extend_from_slice(chunk);

        records.push(record);
        offset = chunk_end;
    }

    records
}

/// Generate random padding bytes to add noise to the traffic pattern.
pub fn generate_padding(max_len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(16..=max_len);
    let mut padding = vec![0u8; len];
    rng.fill(&mut padding[..]);
    padding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_tls_record() {
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x14]; // 20 byte payload
        data.extend_from_slice(&[0xAA; 20]);

        let records = split_tls_record(&data, 8);
        assert_eq!(records.len(), 3); // 8 + 8 + 4

        for rec in &records {
            assert_eq!(rec[0], 0x16);
            assert_eq!(rec[1], 0x03);
            assert_eq!(rec[2], 0x03);
        }

        let len0 = u16::from_be_bytes([records[0][3], records[0][4]]) as usize;
        let len1 = u16::from_be_bytes([records[1][3], records[1][4]]) as usize;
        let len2 = u16::from_be_bytes([records[2][3], records[2][4]]) as usize;
        assert_eq!(len0, 8);
        assert_eq!(len1, 8);
        assert_eq!(len2, 4);
        assert_eq!(len0 + len1 + len2, 20);
    }

    #[test]
    fn test_split_small_record() {
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x04];
        data.extend_from_slice(&[0xBB; 4]);

        let records = split_tls_record(&data, 8);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0], data);
    }

    #[test]
    fn test_padding_generation() {
        let padding = generate_padding(256);
        assert!(padding.len() >= 16);
        assert!(padding.len() <= 256);
    }

    #[test]
    fn test_replace_sni_non_tls() {
        let mut data = vec![0x00; 10];
        assert!(!replace_sni_in_client_hello(&mut data, "test"));
    }
}
