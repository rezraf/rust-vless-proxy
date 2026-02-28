use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use viavless_protocol::Address;

/// SOCKS5 handshake — поддерживаем CONNECT без аутентификации.
///
/// RFC 1928:
/// 1. Client greeting: VER(0x05) NMETHODS METHODS
/// 2. Server choice:   VER(0x05) METHOD(0x00 = no auth)
/// 3. Client request:  VER CMD(0x01=CONNECT) RSV ATYP DST.ADDR DST.PORT
/// 4. Server reply:    VER REP RSV ATYP BND.ADDR BND.PORT

pub async fn handshake(mut stream: TcpStream) -> anyhow::Result<(Address, TcpStream)> {
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

    // 3. Read connect request
    stream.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 || buf[1] != 0x01 {
        // Only CONNECT supported
        // Send failure reply
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(anyhow::anyhow!("only CONNECT supported, got cmd={}", buf[1]));
    }

    let atyp = buf[3];
    let address = match atyp {
        0x01 => {
            // IPv4
            stream.read_exact(&mut buf[..6]).await?;
            let ip = [buf[0], buf[1], buf[2], buf[3]];
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Address::Ipv4(ip, port)
        }
        0x03 => {
            // Domain
            stream.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            stream.read_exact(&mut buf[..len + 2]).await?;
            let domain =
                String::from_utf8(buf[..len].to_vec()).map_err(|_| anyhow::anyhow!("bad domain"))?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            Address::Domain(domain, port)
        }
        0x04 => {
            // IPv6
            stream.read_exact(&mut buf[..18]).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Address::Ipv6(ip, port)
        }
        _ => {
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(anyhow::anyhow!("unsupported address type: {}", atyp));
        }
    };

    // 4. Send success reply (BND.ADDR = 0.0.0.0:0)
    stream
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    Ok((address, stream))
}
