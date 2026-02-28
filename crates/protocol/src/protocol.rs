use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;
use uuid::Uuid;

/// VLESS-like protocol frame:
///
/// ```text
/// +----------+------+---------+------+----------+---------+
/// | version  | uuid | cmd     | atyp | address  | payload |
/// | 1 byte   | 16 B | 1 byte  | 1 B  | variable | rest    |
/// +----------+------+---------+------+----------+---------+
/// ```
///
/// version = 0x01
/// cmd: 0x01 = TCP, 0x02 = UDP
/// atyp: 0x01 = IPv4 (4+2), 0x03 = domain (1+len+2), 0x04 = IPv6 (16+2)

pub const PROTOCOL_VERSION: u8 = 0x01;

/// Frame types for WebSocket messages after the initial handshake.
/// Each WS binary message starts with a 1-byte frame type prefix.
///
/// ```text
/// +----------+---------+
/// | type     | payload |
/// | 1 byte   | rest    |
/// +----------+---------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Real data payload — forward to the target
    Data,
    /// Random padding — server/client should ignore
    Padding,
}

impl FrameType {
    pub fn as_byte(self) -> u8 {
        match self {
            FrameType::Data => 0x00,
            FrameType::Padding => 0x01,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x00 => Ok(FrameType::Data),
            0x01 => Ok(FrameType::Padding),
            _ => Err(ProtocolError::InvalidFrameType(b)),
        }
    }

    /// Wrap payload bytes in a framed message (prepend type byte).
    pub fn wrap(self, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + payload.len());
        buf.push(self.as_byte());
        buf.extend_from_slice(payload);
        buf
    }

    /// Parse a framed message: returns (frame_type, payload_slice).
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), ProtocolError> {
        if data.is_empty() {
            return Err(ProtocolError::BufferTooShort);
        }
        let ft = Self::from_byte(data[0])?;
        Ok((ft, &data[1..]))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

impl Command {
    pub fn as_byte(self) -> u8 {
        match self {
            Command::Tcp => 0x01,
            Command::Udp => 0x02,
        }
    }

    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x01 => Ok(Command::Tcp),
            0x02 => Ok(Command::Udp),
            _ => Err(ProtocolError::InvalidCommand(b)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4([u8; 4], u16),
    Domain(String, u16),
    Ipv6([u8; 16], u16),
}

impl Address {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Address::Ipv4(ip, port) => {
                buf.put_u8(0x01);
                buf.extend_from_slice(ip);
                buf.put_u16(*port);
            }
            Address::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.put_u8(0x03);
                buf.put_u8(domain_bytes.len() as u8);
                buf.extend_from_slice(domain_bytes);
                buf.put_u16(*port);
            }
            Address::Ipv6(ip, port) => {
                buf.put_u8(0x04);
                buf.extend_from_slice(ip);
                buf.put_u16(*port);
            }
        }
    }

    pub fn decode(buf: &mut &[u8]) -> Result<Self, ProtocolError> {
        if buf.is_empty() {
            return Err(ProtocolError::BufferTooShort);
        }
        let atyp = buf[0];
        buf.advance(1);

        match atyp {
            0x01 => {
                if buf.remaining() < 6 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let mut ip = [0u8; 4];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Address::Ipv4(ip, port))
            }
            0x03 => {
                if buf.is_empty() {
                    return Err(ProtocolError::BufferTooShort);
                }
                let len = buf[0] as usize;
                buf.advance(1);
                if buf.remaining() < len + 2 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let mut domain_bytes = vec![0u8; len];
                buf.copy_to_slice(&mut domain_bytes);
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|_| ProtocolError::InvalidDomain)?;
                let port = buf.get_u16();
                Ok(Address::Domain(domain, port))
            }
            0x04 => {
                if buf.remaining() < 18 {
                    return Err(ProtocolError::BufferTooShort);
                }
                let mut ip = [0u8; 16];
                buf.copy_to_slice(&mut ip);
                let port = buf.get_u16();
                Ok(Address::Ipv6(ip, port))
            }
            _ => Err(ProtocolError::InvalidAddressType(atyp)),
        }
    }

    pub fn to_socket_string(&self) -> String {
        match self {
            Address::Ipv4(ip, port) => {
                format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
            }
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
            Address::Ipv6(ip, port) => {
                let segments: Vec<String> = (0..8)
                    .map(|i| format!("{:x}", u16::from_be_bytes([ip[i * 2], ip[i * 2 + 1]])))
                    .collect();
                format!("[{}]:{}", segments.join(":"), port)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestHeader {
    pub uuid: Uuid,
    pub command: Command,
    pub address: Address,
}

impl RequestHeader {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(PROTOCOL_VERSION);
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.put_u8(self.command.as_byte());
        self.address.encode(&mut buf);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), ProtocolError> {
        let mut buf: &[u8] = data;
        let start_len = buf.remaining();

        if buf.remaining() < 18 {
            return Err(ProtocolError::BufferTooShort);
        }

        let version = buf.get_u8();
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::InvalidVersion(version));
        }

        let mut uuid_bytes = [0u8; 16];
        buf.copy_to_slice(&mut uuid_bytes);
        let uuid = Uuid::from_bytes(uuid_bytes);

        if buf.is_empty() {
            return Err(ProtocolError::BufferTooShort);
        }
        let command = Command::from_byte(buf.get_u8())?;
        let address = Address::decode(&mut buf)?;

        let consumed = start_len - buf.remaining();
        Ok((
            RequestHeader {
                uuid,
                command,
                address,
            },
            consumed,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct ResponseHeader {
    pub version: u8,
}

impl ResponseHeader {
    pub fn new() -> Self {
        Self {
            version: PROTOCOL_VERSION,
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(2);
        buf.put_u8(self.version);
        buf.put_u8(0); // addon length = 0
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), ProtocolError> {
        if data.len() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let version = data[0];
        let addon_len = data[1] as usize;
        let total = 2 + addon_len;
        if data.len() < total {
            return Err(ProtocolError::BufferTooShort);
        }
        Ok((ResponseHeader { version }, total))
    }
}

impl Default for ResponseHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid protocol version: {0}")]
    InvalidVersion(u8),
    #[error("invalid command: {0}")]
    InvalidCommand(u8),
    #[error("invalid address type: {0}")]
    InvalidAddressType(u8),
    #[error("invalid domain encoding")]
    InvalidDomain,
    #[error("invalid frame type: {0}")]
    InvalidFrameType(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request_ipv4() {
        let header = RequestHeader {
            uuid: Uuid::new_v4(),
            command: Command::Tcp,
            address: Address::Ipv4([127, 0, 0, 1], 8080),
        };
        let encoded = header.encode();
        let (decoded, consumed) = RequestHeader::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.uuid, header.uuid);
        assert_eq!(decoded.command, Command::Tcp);
        assert_eq!(decoded.address, Address::Ipv4([127, 0, 0, 1], 8080));
    }

    #[test]
    fn roundtrip_request_domain() {
        let header = RequestHeader {
            uuid: Uuid::new_v4(),
            command: Command::Tcp,
            address: Address::Domain("example.com".to_string(), 443),
        };
        let encoded = header.encode();
        let (decoded, consumed) = RequestHeader::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.address,
            Address::Domain("example.com".to_string(), 443)
        );
    }

    #[test]
    fn roundtrip_request_ipv6() {
        let ipv6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let header = RequestHeader {
            uuid: Uuid::new_v4(),
            command: Command::Udp,
            address: Address::Ipv6(ipv6, 53),
        };
        let encoded = header.encode();
        let (decoded, _) = RequestHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.command, Command::Udp);
        assert_eq!(decoded.address, Address::Ipv6(ipv6, 53));
    }

    #[test]
    fn roundtrip_response() {
        let resp = ResponseHeader::new();
        let encoded = resp.encode();
        let (decoded, consumed) = ResponseHeader::decode(&encoded).unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }

    #[test]
    fn invalid_version() {
        let mut data = [0u8; 33];
        data[0] = 0xFF;
        let err = RequestHeader::decode(&data).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidVersion(0xFF)));
    }

    #[test]
    fn buffer_too_short() {
        let data = [0x01];
        let err = RequestHeader::decode(&data).unwrap_err();
        assert!(matches!(err, ProtocolError::BufferTooShort));
    }

    #[test]
    fn address_to_socket_string() {
        assert_eq!(
            Address::Ipv4([10, 0, 0, 1], 443).to_socket_string(),
            "10.0.0.1:443"
        );
        assert_eq!(
            Address::Domain("google.com".to_string(), 80).to_socket_string(),
            "google.com:80"
        );
    }

    #[test]
    fn frame_type_data_wrap_parse() {
        let payload = b"hello world";
        let wrapped = FrameType::Data.wrap(payload);
        assert_eq!(wrapped[0], 0x00);
        assert_eq!(&wrapped[1..], payload);

        let (ft, parsed) = FrameType::parse(&wrapped).unwrap();
        assert_eq!(ft, FrameType::Data);
        assert_eq!(parsed, payload);
    }

    #[test]
    fn frame_type_padding_wrap_parse() {
        let padding = vec![0xAA; 64];
        let wrapped = FrameType::Padding.wrap(&padding);
        assert_eq!(wrapped[0], 0x01);

        let (ft, parsed) = FrameType::parse(&wrapped).unwrap();
        assert_eq!(ft, FrameType::Padding);
        assert_eq!(parsed, &padding[..]);
    }

    #[test]
    fn frame_type_invalid() {
        let data = [0xFF, 0x00];
        let err = FrameType::parse(&data).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidFrameType(0xFF)));
    }

    #[test]
    fn frame_type_empty() {
        let err = FrameType::parse(&[]).unwrap_err();
        assert!(matches!(err, ProtocolError::BufferTooShort));
    }
}
