use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use viavless_protocol::Address;

/// SOCKS5 command types (internal to handshake logic)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocksCommand {
    Connect,
    UdpAssociate,
}

/// Result of SOCKS5 handshake
pub enum SocksRequest {
    /// TCP CONNECT — stream is ready for data relay
    Connect(Address, TcpStream),
    /// UDP ASSOCIATE — client wants a UDP relay, TCP stream stays open as keepalive
    UdpAssociate(Address, TcpStream, std::net::SocketAddr),
}

/// SOCKS5 handshake — supports CONNECT and UDP ASSOCIATE without auth.
///
/// RFC 1928:
/// 1. Client greeting: VER(0x05) NMETHODS METHODS
/// 2. Server choice:   VER(0x05) METHOD(0x00 = no auth)
/// 3. Client request:  VER CMD RSV ATYP DST.ADDR DST.PORT
/// 4. Server reply:    VER REP RSV ATYP BND.ADDR BND.PORT
pub async fn handshake(mut stream: TcpStream) -> anyhow::Result<SocksRequest> {
    // 1. Read greeting
    let mut buf = [0u8; 258];
    stream.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow::anyhow!("not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    stream.read_exact(&mut buf[..nmethods]).await?;

    // 2. Reply: no auth
    stream.write_all(&[0x05, 0x00]).await?;

    // 3. Read request
    stream.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow::anyhow!("not SOCKS5 request"));
    }

    let cmd = buf[1];
    let command = match cmd {
        0x01 => SocksCommand::Connect,
        0x03 => SocksCommand::UdpAssociate,
        _ => {
            // Command not supported
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(anyhow::anyhow!("unsupported SOCKS5 cmd: {}", cmd));
        }
    };

    let atyp = buf[3];
    let address = read_address(&mut stream, &mut buf, atyp).await?;

    match command {
        SocksCommand::Connect => {
            // Reply: success, BND.ADDR = 0.0.0.0:0
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Ok(SocksRequest::Connect(address, stream))
        }
        SocksCommand::UdpAssociate => {
            // Bind a local UDP socket for the client to send datagrams to
            let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
            let udp_addr = udp_socket.local_addr()?;

            // Reply with the UDP relay address
            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            match udp_addr {
                std::net::SocketAddr::V4(v4) => {
                    reply.extend_from_slice(&v4.ip().octets());
                    reply.extend_from_slice(&v4.port().to_be_bytes());
                }
                std::net::SocketAddr::V6(_) => {
                    // Fallback to 0.0.0.0:port for simplicity
                    reply.extend_from_slice(&[0, 0, 0, 0]);
                    reply.extend_from_slice(&udp_addr.port().to_be_bytes());
                }
            }
            stream.write_all(&reply).await?;

            // The UDP socket address is returned so the caller can manage the relay.
            // The TCP stream must stay open — when it closes, the UDP association ends.
            Ok(SocksRequest::UdpAssociate(address, stream, udp_addr))
        }
    }
}

async fn read_address(
    stream: &mut TcpStream,
    buf: &mut [u8; 258],
    atyp: u8,
) -> anyhow::Result<Address> {
    match atyp {
        0x01 => {
            // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = [buf[0], buf[1], buf[2], buf[3]];
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok(Address::Ipv4(ip, port))
        }
        0x03 => {
            // Domain
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
            let domain = String::from_utf8(buf[..len].to_vec())
                .map_err(|_| anyhow::anyhow!("bad domain"))?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            Ok(Address::Domain(domain, port))
        }
        0x04 => {
            // IPv6
            stream.read_exact(&mut buf[..18]).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok(Address::Ipv6(ip, port))
        }
        _ => {
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(anyhow::anyhow!("unsupported address type: {}", atyp))
        }
    }
}
