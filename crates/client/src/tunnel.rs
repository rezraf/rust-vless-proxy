use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
use viavless_protocol::{Address, Command, FrameType, RequestHeader, ResponseHeader};

use crate::dpi;
use crate::fragment_stream::FragmentingStream;
use crate::Config;

/// Enum wrapping either a plain TcpStream or a FragmentingStream,
/// so we can pass either to the TLS connector.
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

pub async fn connect_and_relay(
    mut socks_stream: TcpStream,
    target: &Address,
    config: &Config,
) -> anyhow::Result<()> {
    // Step 1: TCP connect to the proxy server
    let server_addr = format!("{}:{}", config.server_host, config.server_port);
    let tcp_stream = TcpStream::connect(&server_addr).await?;

    // Step 2: Wrap in FragmentingStream for DPI evasion
    tcp_stream.set_nodelay(true)?;

    let stream = if config.fragment_enabled {
        let frag_stream = FragmentingStream::new(
            tcp_stream,
            config.fragment_size,
            true,
            config.fake_sni.clone(),
        );
        MaybeFragmented::Fragmented(frag_stream)
    } else {
        MaybeFragmented::Plain(tcp_stream)
    };

    // Step 3: TLS handshake — ClientHello will be fragmented by FragmentingStream
    let tls_stream = tls_connect(stream, &config.server_sni).await?;

    // Step 4: WebSocket upgrade over TLS
    let ws_url = format!("wss://{}{}", config.server_sni, config.ws_path);
    let (mut ws_stream, _) = tokio_tungstenite::client_async(&ws_url, tls_stream).await?;

    // Step 5: Send protocol header (not framed — it's the initial handshake)
    let uuid: Uuid = config.uuid.parse()?;
    let header = RequestHeader {
        uuid,
        command: Command::Tcp,
        address: target.clone(),
    };
    let header_bytes = header.encode();
    ws_stream
        .send(Message::Binary(header_bytes.to_vec().into()))
        .await?;

    // Step 6: Read response header
    let resp_msg = ws_stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("server closed before response"))??;

    let resp_data = match &resp_msg {
        Message::Binary(d) => d.as_ref(),
        _ => return Err(anyhow::anyhow!("expected binary response")),
    };

    let (_resp_header, resp_consumed) = ResponseHeader::decode(resp_data)?;

    if resp_consumed < resp_data.len() {
        socks_stream.write_all(&resp_data[resp_consumed..]).await?;
    }

    // Step 7: Bidirectional relay with FrameType framing and padding
    let (mut ws_write, mut ws_read) = ws_stream.split();
    let (mut socks_read, mut socks_write) = socks_stream.split();

    let padding_enabled = config.padding_enabled;
    let padding_max = config.padding_max;

    // SOCKS -> WebSocket (wrap data in FrameType::Data, inject padding)
    let socks_to_ws = async {
        let mut buf = vec![0u8; 8192];
        let mut msg_count: u32 = 0;
        loop {
            match socks_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    // Wrap real data in Data frame
                    let framed = FrameType::Data.wrap(&buf[..n]);
                    if ws_write
                        .send(Message::Binary(framed.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }

                    // Periodically inject padding to break traffic patterns
                    msg_count += 1;
                    if padding_enabled && should_send_padding(msg_count) {
                        let padding = dpi::generate_padding(padding_max);
                        let framed_pad = FrameType::Padding.wrap(&padding);
                        let _ = ws_write
                            .send(Message::Binary(framed_pad.into()))
                            .await;
                    }
                }
            }
        }
        let _ = ws_write.send(Message::Close(None)).await;
    };

    // WebSocket -> SOCKS (parse FrameType, skip padding)
    let ws_to_socks = async {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    match FrameType::parse(&data) {
                        Ok((FrameType::Data, payload)) => {
                            if socks_write.write_all(payload).await.is_err() {
                                break;
                            }
                        }
                        Ok((FrameType::Padding, _)) => {
                            // Silently discard padding
                            continue;
                        }
                        Err(_) => {
                            // Fallback: treat as raw data (backwards compatibility)
                            if socks_write.write_all(&data).await.is_err() {
                                break;
                            }
                        }
                    }
                }
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

/// Decide whether to send a padding frame based on message count.
/// Uses randomization to avoid creating a predictable pattern.
fn should_send_padding(msg_count: u32) -> bool {
    let mut rng = rand::thread_rng();
    // ~30% chance after each real message, higher chance every 5th message
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
