mod server;

use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
struct Config {
    listen: String,
    uuid: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    ws_path: String,
    no_tls: bool,
}

impl Config {
    fn from_env() -> Self {
        let no_tls = std::env::var("VIAVLESS_NO_TLS")
            .unwrap_or_else(|_| "false".into())
            .parse()
            .unwrap_or(false);

        Self {
            listen: std::env::var("VIAVLESS_LISTEN")
                .unwrap_or_else(|_| if no_tls { "0.0.0.0:8080".into() } else { "0.0.0.0:443".into() }),
            uuid: std::env::var("VIAVLESS_UUID").expect("VIAVLESS_UUID must be set"),
            tls_cert: std::env::var("VIAVLESS_TLS_CERT").ok().map(PathBuf::from),
            tls_key: std::env::var("VIAVLESS_TLS_KEY").ok().map(PathBuf::from),
            ws_path: std::env::var("VIAVLESS_WS_PATH").unwrap_or_else(|_| "/ws".into()),
            no_tls,
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
        listen = %config.listen,
        ws_path = %config.ws_path,
        no_tls = config.no_tls,
        "starting viavless server"
    );

    if config.no_tls {
        // Plain WebSocket mode — for use behind a TLS-terminating reverse proxy (Caddy, nginx)
        server::run_plain(&config.listen, &config.uuid, &config.ws_path).await
    } else {
        let cert = config.tls_cert.unwrap_or_else(|| PathBuf::from("cert.pem"));
        let key = config.tls_key.unwrap_or_else(|| PathBuf::from("key.pem"));
        server::run_tls(&config.listen, &config.uuid, &cert, &key, &config.ws_path).await
    }
}
