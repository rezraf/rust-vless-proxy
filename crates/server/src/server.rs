use std::path::Path;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use viavless_protocol::{Command, FrameType, RequestHeader, ResponseHeader};

pub async fn run(
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

    tracing::info!("listening on {}", listen);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
        let ws_path = ws_path.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, acceptor, allowed_uuid, &ws_path).await
            {
                tracing::warn!(peer = %peer_addr, error = %e, "connection failed");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    allowed_uuid: Uuid,
    ws_path: &str,
) -> anyhow::Result<()> {
    let tls_stream = acceptor.accept(stream).await?;

    let ws_stream = tokio_tungstenite::accept_hdr_async(
        tls_stream,
        |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
         resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
            if req.uri().path() == ws_path {
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

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Read first message — expect protocol header (not framed)
    let first_msg = ws_read
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("connection closed before header"))??;

    let data = match &first_msg {
        Message::Binary(d) => d.as_ref(),
        _ => return Err(anyhow::anyhow!("expected binary message")),
    };

    let (header, consumed) = RequestHeader::decode(data)?;

    // Auth check
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
        Command::Udp => {
            tracing::warn!("UDP not yet implemented");
            Err(anyhow::anyhow!("UDP not supported yet"))
        }
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

    // Send response header
    let resp = ResponseHeader::new().encode();
    ws_write.send(Message::Binary(resp.to_vec().into())).await?;

    // Forward initial payload if any
    if !initial_payload.is_empty() {
        remote.write_all(initial_payload).await?;
    }

    let (mut remote_read, mut remote_write) = remote.split();

    // WS -> remote: parse FrameType, forward Data, skip Padding
    let ws_to_remote = async {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    match FrameType::parse(&data) {
                        Ok((FrameType::Data, payload)) => {
                            if remote_write.write_all(payload).await.is_err() {
                                break;
                            }
                        }
                        Ok((FrameType::Padding, _)) => {
                            // Silently discard padding frames
                            continue;
                        }
                        Err(_) => {
                            // Fallback: treat as raw data (backwards compatibility)
                            if remote_write.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        let _ = remote_write.shutdown().await;
    };

    // Remote -> WS: wrap in FrameType::Data
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

    tracing::debug!(target = %target, "tunnel closed");
    Ok(())
}

fn make_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<TlsAcceptor> {
    let cert_data = std::fs::read(cert_path)?;
    let key_data = std::fs::read(key_path)?;

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_data.as_slice())
            .collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut key_data.as_slice())?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}
