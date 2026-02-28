mod dpi;
mod fragment_stream;
mod socks5;
mod tunnel;

use socks5::SocksRequest;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct Config {
    socks_listen: String,
    server_host: String,
    server_port: u16,
    server_sni: String,
    ws_path: String,
    uuid: String,
    fake_sni: Option<String>,
    fragment_enabled: bool,
    fragment_size: usize,
    padding_enabled: bool,
    padding_max: usize,
}

impl Config {
    fn from_env() -> Self {
        Self {
            socks_listen: std::env::var("VIAVLESS_SOCKS_LISTEN")
                .unwrap_or_else(|_| "127.0.0.1:1080".into()),
            server_host: std::env::var("VIAVLESS_SERVER_HOST")
                .expect("VIAVLESS_SERVER_HOST must be set"),
            server_port: std::env::var("VIAVLESS_SERVER_PORT")
                .unwrap_or_else(|_| "443".into())
                .parse()
                .expect("invalid port"),
            server_sni: std::env::var("VIAVLESS_SERVER_SNI")
                .unwrap_or_else(|_| std::env::var("VIAVLESS_SERVER_HOST").unwrap_or_default()),
            ws_path: std::env::var("VIAVLESS_WS_PATH").unwrap_or_else(|_| "/ws".into()),
            uuid: std::env::var("VIAVLESS_UUID").expect("VIAVLESS_UUID must be set"),
            fake_sni: std::env::var("VIAVLESS_FAKE_SNI").ok(),
            fragment_enabled: std::env::var("VIAVLESS_FRAGMENT")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            fragment_size: std::env::var("VIAVLESS_FRAGMENT_SIZE")
                .unwrap_or_else(|_| "40".into())
                .parse()
                .unwrap_or(40),
            padding_enabled: std::env::var("VIAVLESS_PADDING")
                .unwrap_or_else(|_| "true".into())
                .parse()
                .unwrap_or(true),
            padding_max: std::env::var("VIAVLESS_PADDING_MAX")
                .unwrap_or_else(|_| "256".into())
                .parse()
                .unwrap_or(256),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("viavless=info".parse()?))
        .init();

    let config = Config::from_env();
    tracing::info!(
        listen = %config.socks_listen,
        server = %config.server_host,
        fragment = config.fragment_enabled,
        padding = config.padding_enabled,
        "starting viavless client"
    );

    let listener = tokio::net::TcpListener::bind(&config.socks_listen).await?;
    let config = std::sync::Arc::new(config);

    loop {
        let (stream, peer) = listener.accept().await?;
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks(stream, &config).await {
                tracing::warn!(peer = %peer, error = %e, "socks connection failed");
            }
        });
    }
}

async fn handle_socks(
    stream: tokio::net::TcpStream,
    config: &Config,
) -> anyhow::Result<()> {
    match socks5::handshake(stream).await? {
        SocksRequest::Connect(target_addr, socks_stream) => {
            tracing::info!(target = %target_addr.to_socket_string(), "socks5 tcp connect");
            tunnel::tcp_relay(socks_stream, &target_addr, config).await
        }
        SocksRequest::UdpAssociate(_target_addr, tcp_keepalive, udp_bind_addr) => {
            tracing::info!(udp_bind = %udp_bind_addr, "socks5 udp associate");
            tunnel::udp_relay(tcp_keepalive, udp_bind_addr, config).await
        }
    }
}
