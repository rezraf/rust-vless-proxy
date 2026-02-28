mod server;

use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, serde::Deserialize)]
struct Config {
    listen: String,
    uuid: String,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    ws_path: String,
}

impl Config {
    fn from_env() -> Self {
        Self {
            listen: std::env::var("VIAVLESS_LISTEN").unwrap_or_else(|_| "0.0.0.0:443".into()),
            uuid: std::env::var("VIAVLESS_UUID").expect("VIAVLESS_UUID must be set"),
            tls_cert: PathBuf::from(
                std::env::var("VIAVLESS_TLS_CERT").unwrap_or_else(|_| "cert.pem".into()),
            ),
            tls_key: PathBuf::from(
                std::env::var("VIAVLESS_TLS_KEY").unwrap_or_else(|_| "key.pem".into()),
            ),
            ws_path: std::env::var("VIAVLESS_WS_PATH").unwrap_or_else(|_| "/ws".into()),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("viavless=info".parse()?))
        .init();

    let config = Config::from_env();
    tracing::info!(listen = %config.listen, ws_path = %config.ws_path, "starting viavless server");

    server::run(
        &config.listen,
        &config.uuid,
        &config.tls_cert,
        &config.tls_key,
        &config.ws_path,
    )
    .await
}
