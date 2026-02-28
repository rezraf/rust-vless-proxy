use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use viavless_protocol::{Address, Command, FrameType, RequestHeader, ResponseHeader, UdpPacket};

use crate::dpi;
use crate::fragment_stream::FragmentingStream;
use crate::Config;

enum MaybeFragmented {
    Plain(TcpStream),
    Fragmented(FragmentingStream),
}

impl AsyncRead for MaybeFragmented {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeFragmented::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            MaybeFragmented::Fragmented(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeFragmented {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeFragmented::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            MaybeFragmented::Fragmented(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeFragmented::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            MaybeFragmented::Fragmented(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeFragmented::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            MaybeFragmented::Fragmented(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Establish a WebSocket connection to the proxy server with DPI evasion.
async fn connect_ws(
    config: &Config,
    command: Command,
    target: &Address,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<
        tokio_rustls::client::TlsStream<MaybeFragmented>,
    >,
> {
    let server_addr = format!("{}:{}", config.server_host, config.server_port);
    let tcp_stream = TcpStream::connect(&server_addr).await?;
    tcp_stream.set_nodelay(true)?;

    let stream = if config.fragment_enabled {
        MaybeFragmented::Fragmented(FragmentingStream::new(
            tcp_stream,
            config.fragment_size,
            true,
            config.fake_sni.clone(),
        ))
    } else {
        MaybeFragmented::Plain(tcp_stream)
    };

    let tls_stream = tls_connect(stream, &config.server_sni).await?;

    let ws_url = format!("wss://{}{}", config.server_sni, config.ws_path);
    let (mut ws_stream, _) = tokio_tungstenite::client_async(&ws_url, tls_stream).await?;

    // Send protocol header
    let uuid: Uuid = config.uuid.parse()?;
    let header = RequestHeader {
        uuid,
        command,
        address: target.clone(),
    };
    ws_stream
        .send(Message::Binary(header.encode().to_vec().into()))
        .await?;

    // Read response header
    let resp_msg = ws_stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("server closed before response"))??;

    match &resp_msg {
        Message::Binary(d) => {
            ResponseHeader::decode(d.as_ref())?;
        }
        _ => return Err(anyhow::anyhow!("expected binary response")),
    };

    Ok(ws_stream)
}

/// TCP relay: SOCKS5 stream <-> WebSocket tunnel
pub async fn tcp_relay(
    mut socks_stream: TcpStream,
    target: &Address,
    config: &Config,
) -> anyhow::Result<()> {
    let ws_stream = connect_ws(config, Command::Tcp, target).await?;

    let (mut ws_write, mut ws_read) = ws_stream.split();
    let (mut socks_read, mut socks_write) = socks_stream.split();

    let padding_enabled = config.padding_enabled;
    let padding_max = config.padding_max;

    let socks_to_ws = async {
        let mut buf = vec![0u8; 8192];
        let mut msg_count: u32 = 0;
        loop {
            match socks_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let framed = FrameType::Data.wrap(&buf[..n]);
                    if ws_write
                        .send(Message::Binary(framed.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }

                    msg_count += 1;
                    if padding_enabled && should_send_padding(msg_count) {
                        let padding = dpi::generate_padding(padding_max);
                        let framed_pad = FrameType::Padding.wrap(&padding);
                        let _ = ws_write.send(Message::Binary(framed_pad.into())).await;
                    }
                }
            }
        }
        let _ = ws_write.send(Message::Close(None)).await;
    };

    let ws_to_socks = async {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => match FrameType::parse(&data) {
                    Ok((FrameType::Data, payload)) => {
                        if socks_write.write_all(payload).await.is_err() {
                            break;
                        }
                    }
                    Ok((FrameType::Padding, _)) => continue,
                    Err(_) => {
                        if socks_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                },
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        let _ = socks_write.shutdown().await;
    };

    tokio::select! {
        _ = socks_to_ws => {}
        _ = ws_to_socks => {}
    }

    Ok(())
}

/// UDP relay: local UDP socket <-> WebSocket tunnel with UdpPacket framing.
///
/// The TCP keepalive stream stays open — when it closes, the UDP association ends.
pub async fn udp_relay(
    mut tcp_keepalive: TcpStream,
    udp_bind_addr: std::net::SocketAddr,
    config: &Config,
) -> anyhow::Result<()> {
    // Use a dummy address for the initial handshake — UDP doesn't have a fixed target
    let dummy_addr = Address::Ipv4([0, 0, 0, 0], 0);
    let ws_stream = connect_ws(config, Command::Udp, &dummy_addr).await?;

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Bind the local UDP socket that the SOCKS5 client sends datagrams to
    let udp_socket = Arc::new(UdpSocket::bind(udp_bind_addr).await?);
    let udp_recv = udp_socket.clone();
    let udp_send = udp_socket.clone();

    // Track the client's UDP address (set on first datagram)
    let client_addr: Arc<tokio::sync::Mutex<Option<std::net::SocketAddr>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    let client_addr_recv = client_addr.clone();

    let padding_enabled = config.padding_enabled;
    let padding_max = config.padding_max;

    // Local UDP -> WebSocket
    let udp_to_ws = async {
        let mut buf = vec![0u8; 65535];
        let mut msg_count: u32 = 0;
        loop {
            match udp_recv.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    // Remember client address
                    {
                        let mut addr = client_addr.lock().await;
                        if addr.is_none() {
                            *addr = Some(src);
                        }
                    }

                    // Parse SOCKS5 UDP request header:
                    // RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2) + DATA
                    if n < 4 {
                        continue;
                    }
                    let frag = buf[2];
                    if frag != 0 {
                        // Fragmentation not supported — skip
                        continue;
                    }

                    let _atyp = buf[3];
                    let (address, data_offset) = match parse_socks_udp_addr(&buf[3..n]) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let data_start = 3 + data_offset; // 3 bytes for RSV+FRAG

                    if data_start >= n {
                        continue;
                    }

                    let pkt = UdpPacket {
                        address,
                        payload: buf[data_start..n].to_vec(),
                    };
                    let encoded = pkt.encode();
                    let framed = FrameType::Data.wrap(&encoded);

                    if ws_write
                        .send(Message::Binary(framed.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }

                    msg_count += 1;
                    if padding_enabled && should_send_padding(msg_count) {
                        let padding = dpi::generate_padding(padding_max);
                        let framed_pad = FrameType::Padding.wrap(&padding);
                        let _ = ws_write.send(Message::Binary(framed_pad.into())).await;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = ws_write.send(Message::Close(None)).await;
    };

    // WebSocket -> Local UDP
    let ws_to_udp = async {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => match FrameType::parse(&data) {
                    Ok((FrameType::Data, payload)) => {
                        if let Ok(pkt) = UdpPacket::decode(payload) {
                            let client = client_addr_recv.lock().await;
                            if let Some(client_addr) = *client {
                                // Build SOCKS5 UDP response header:
                                // RSV(2=0x0000) + FRAG(1=0x00) + ATYP+ADDR+PORT + DATA
                                let mut resp = vec![0x00, 0x00, 0x00];
                                let addr_bytes = encode_socks_udp_addr(&pkt.address);
                                resp.extend_from_slice(&addr_bytes);
                                resp.extend_from_slice(&pkt.payload);
                                let _ = udp_send.send_to(&resp, client_addr).await;
                            }
                        }
                    }
                    Ok((FrameType::Padding, _)) => continue,
                    Err(_) => {}
                },
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    };

    // TCP keepalive — when this closes, the UDP association ends
    let keepalive = async {
        let mut buf = [0u8; 1];
        // Block until TCP closes
        let _ = tcp_keepalive.read(&mut buf).await;
    };

    tokio::select! {
        _ = udp_to_ws => {}
        _ = ws_to_udp => {}
        _ = keepalive => {}
    }

    Ok(())
}

/// Parse address from SOCKS5 UDP datagram (starting at ATYP).
/// Returns (Address, bytes_consumed_including_atyp).
fn parse_socks_udp_addr(buf: &[u8]) -> anyhow::Result<(Address, usize)> {
    if buf.is_empty() {
        return Err(anyhow::anyhow!("empty"));
    }
    let atyp = buf[0];
    match atyp {
        0x01 => {
            if buf.len() < 7 {
                return Err(anyhow::anyhow!("short ipv4"));
            }
            let ip = [buf[1], buf[2], buf[3], buf[4]];
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Address::Ipv4(ip, port), 7))
        }
        0x03 => {
            if buf.len() < 2 {
                return Err(anyhow::anyhow!("short domain"));
            }
            let len = buf[1] as usize;
            if buf.len() < 2 + len + 2 {
                return Err(anyhow::anyhow!("short domain data"));
            }
            let domain = String::from_utf8(buf[2..2 + len].to_vec())?;
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((Address::Domain(domain, port), 2 + len + 2))
        }
        0x04 => {
            if buf.len() < 19 {
                return Err(anyhow::anyhow!("short ipv6"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Address::Ipv6(ip, port), 19))
        }
        _ => Err(anyhow::anyhow!("unknown atyp {}", atyp)),
    }
}

/// Encode address for SOCKS5 UDP response header.
fn encode_socks_udp_addr(addr: &Address) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr {
        Address::Ipv4(ip, port) => {
            buf.push(0x01);
            buf.extend_from_slice(ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Domain(domain, port) => {
            let bytes = domain.as_bytes();
            buf.push(0x03);
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Address::Ipv6(ip, port) => {
            buf.push(0x04);
            buf.extend_from_slice(ip);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    buf
}

fn should_send_padding(msg_count: u32) -> bool {
    let mut rng = rand::thread_rng();
    if msg_count % 5 == 0 {
        rng.gen_bool(0.7)
    } else {
        rng.gen_bool(0.3)
    }
}

async fn tls_connect<S>(
    stream: S,
    sni: &str,
) -> anyhow::Result<tokio_rustls::client::TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls_pki_types::ServerName::try_from(sni.to_string())?;

    let tls_stream = connector.connect(server_name, stream).await?;
    Ok(tls_stream)
}
