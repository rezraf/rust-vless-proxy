use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use viavless_protocol::{Address, Command, FrameType, RequestHeader, ResponseHeader, UdpPacket};

/// Run server with TLS (standalone mode).
pub async fn run_tls(
    listen: &str,
    uuid_str: &str,
    tls_cert: &Path,
    tls_key: &Path,
    ws_path: &str,
) -> anyhow::Result<()> {
    let allowed_uuid: Uuid = uuid_str.parse()?;
    let tls_acceptor = make_tls_acceptor(tls_cert, tls_key)?;
    let listener = TcpListener::bind(listen).await?;
    let ws_path = ws_path.to_string();

    tracing::info!("listening (TLS) on {}", listen);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let ws_path = ws_path.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tls_connection(stream, acceptor, allowed_uuid, &ws_path).await {
                tracing::warn!(peer = %peer_addr, error = %e, "connection failed");
            }
        });
    }
}

/// Run server without TLS (behind reverse proxy like Caddy/nginx).
pub async fn run_plain(
    listen: &str,
    uuid_str: &str,
    ws_path: &str,
) -> anyhow::Result<()> {
    let allowed_uuid: Uuid = uuid_str.parse()?;
    let listener = TcpListener::bind(listen).await?;
    let ws_path = ws_path.to_string();

    tracing::info!("listening (plain WS) on {}", listen);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let ws_path = ws_path.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_plain_connection(stream, allowed_uuid, &ws_path).await {
                tracing::warn!(peer = %peer_addr, error = %e, "connection failed");
            }
        });
    }
}

async fn handle_tls_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    allowed_uuid: Uuid,
    ws_path: &str,
) -> anyhow::Result<()> {
    let tls_stream = acceptor.accept(stream).await?;
    let ws_stream = accept_ws(tls_stream, ws_path).await?;
    handle_ws(ws_stream, allowed_uuid).await
}

async fn handle_plain_connection(
    stream: TcpStream,
    allowed_uuid: Uuid,
    ws_path: &str,
) -> anyhow::Result<()> {
    let ws_stream = accept_ws(stream, ws_path).await?;
    handle_ws(ws_stream, allowed_uuid).await
}

async fn accept_ws<S>(
    stream: S,
    ws_path: &str,
) -> anyhow::Result<tokio_tungstenite::WebSocketStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let ws_path_owned = ws_path.to_string();
    let ws_stream = tokio_tungstenite::accept_hdr_async(
        stream,
        move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
              resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            if req.uri().path() == ws_path_owned {
                Ok(resp)
            } else {
                tracing::debug!(path = %req.uri().path(), "rejected: wrong path");
                let resp = tokio_tungstenite::tungstenite::handshake::server::Response::builder()
                    .status(404)
                    .body(None)
                    .unwrap();
                Err(resp)
            }
        },
    )
    .await?;
    Ok(ws_stream)
}

async fn handle_ws<S>(
    ws_stream: tokio_tungstenite::WebSocketStream<S>,
    allowed_uuid: Uuid,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut ws_write, mut ws_read) = ws_stream.split();

    let first_msg = ws_read
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("connection closed before header"))??;

    let data = match &first_msg {
        Message::Binary(d) => d.as_ref(),
        _ => return Err(anyhow::anyhow!("expected binary message")),
    };

    let (header, consumed) = RequestHeader::decode(data)?;

    if header.uuid != allowed_uuid {
        tracing::warn!(uuid = %header.uuid, "unauthorized uuid");
        return Err(anyhow::anyhow!("unauthorized"));
    }

    tracing::info!(
        cmd = ?header.command,
        target = %header.address.to_socket_string(),
        "new tunnel"
    );

    match header.command {
        Command::Tcp => {
            handle_tcp(&header, &data[consumed..], &mut ws_write, &mut ws_read).await
        }
        Command::Udp => handle_udp(&mut ws_write, &mut ws_read).await,
    }
}

async fn handle_tcp(
    header: &RequestHeader,
    initial_payload: &[u8],
    ws_write: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ws_read: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
) -> anyhow::Result<()> {
    let target = header.address.to_socket_string();
    let mut remote = TcpStream::connect(&target).await?;

    let resp = ResponseHeader::new().encode();
    ws_write.send(Message::Binary(resp.to_vec().into())).await?;

    if !initial_payload.is_empty() {
        remote.write_all(initial_payload).await?;
    }

    let (mut remote_read, mut remote_write) = remote.split();

    let ws_to_remote = async {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => match FrameType::parse(&data) {
                    Ok((FrameType::Data, payload)) => {
                        if remote_write.write_all(payload).await.is_err() {
                            break;
                        }
                    }
                    Ok((FrameType::Padding, _)) => continue,
                    Err(_) => {
                        if remote_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                },
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        let _ = remote_write.shutdown().await;
    };

    let remote_to_ws = async {
        let mut buf = vec![0u8; 8192];
        loop {
            match remote_read.read(&mut buf).await {
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
                }
            }
        }
        let _ = ws_write.send(Message::Close(None)).await;
    };

    tokio::select! {
        _ = ws_to_remote => {}
        _ = remote_to_ws => {}
    }

    tracing::debug!(target = %target, "tcp tunnel closed");
    Ok(())
}

async fn handle_udp(
    ws_write: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    ws_read: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
              + Unpin),
) -> anyhow::Result<()> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = udp_socket.local_addr()?;
    tracing::debug!(udp_bind = %local_addr, "udp relay socket bound");

    let resp = ResponseHeader::new().encode();
    ws_write.send(Message::Binary(resp.to_vec().into())).await?;

    let udp_recv = Arc::new(udp_socket);
    let udp_send = udp_recv.clone();

    let ws_to_udp = async {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => match FrameType::parse(&data) {
                    Ok((FrameType::Data, payload)) => {
                        if let Ok(pkt) = UdpPacket::decode(payload) {
                            let target = pkt.address.to_socket_string();
                            match resolve_addr(&target).await {
                                Ok(addr) => {
                                    let _ = udp_send.send_to(&pkt.payload, addr).await;
                                }
                                Err(e) => {
                                    tracing::debug!(target = %target, error = %e, "udp resolve failed");
                                }
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

    let udp_to_ws = async {
        let mut buf = vec![0u8; 65535];
        loop {
            match udp_recv.recv_from(&mut buf).await {
                Ok((n, src_addr)) => {
                    let pkt = UdpPacket {
                        address: socket_addr_to_address(src_addr),
                        payload: buf[..n].to_vec(),
                    };
                    let framed = FrameType::Data.wrap(&pkt.encode());
                    if ws_write
                        .send(Message::Binary(framed.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = ws_write.send(Message::Close(None)).await;
    };

    tokio::select! {
        _ = ws_to_udp => {}
        _ = udp_to_ws => {}
    }

    tracing::debug!("udp relay closed");
    Ok(())
}

fn socket_addr_to_address(addr: SocketAddr) -> Address {
    match addr {
        SocketAddr::V4(v4) => Address::Ipv4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => Address::Ipv6(v6.ip().octets(), v6.port()),
    }
}

async fn resolve_addr(target: &str) -> anyhow::Result<SocketAddr> {
    use tokio::net::lookup_host;
    lookup_host(target)
        .await?
        .next()
        .ok_or_else(|| anyhow::anyhow!("dns resolution failed for {}", target))
}

fn make_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let cert_data = std::fs::read(cert_path)?;
    let key_data = std::fs::read(key_path)?;

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_data.as_slice()).collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut key_data.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
