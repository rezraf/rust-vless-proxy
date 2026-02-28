mod server;

use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

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

        let uuid = std::env::var("VIAVLESS_UUID")
            .unwrap_or_else(|_| Uuid::new_v4().to_string());

        Self {
            listen: std::env::var("VIAVLESS_LISTEN")
                .unwrap_or_else(|_| if no_tls { "0.0.0.0:8080".into() } else { "0.0.0.0:443".into() }),
            uuid,
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
        server::run_plain(&config.listen, &config.uuid, &config.ws_path).await
    } else if config.tls_cert.is_some() || config.tls_key.is_some() {
        // Manual cert mode — user provided cert/key files
        let cert = config.tls_cert.unwrap_or_else(|| PathBuf::from("cert.pem"));
        let key = config.tls_key.unwrap_or_else(|| PathBuf::from("key.pem"));
        server::run_tls(&config.listen, &config.uuid, &cert, &key, &config.ws_path).await
    } else {
        // Reality mode — auto-generate self-signed cert, print fingerprint
        let (tls_acceptor, fingerprint) = server::generate_self_signed_tls()?;

        println!();
        println!("========================================");
        println!("  VIAVLESS SERVER - REALITY MODE");
        println!("========================================");
        println!("  Fingerprint: {}", fingerprint);
        println!("  UUID:        {}", config.uuid);
        println!("  Listen:      {}", config.listen);
        println!("  WS Path:     {}", config.ws_path);
        println!("========================================");
        println!();
        println!("  Client command:");
        println!("  docker run -d --name viavless-client \\");
        println!("    -p 1080:1080 \\");
        println!("    -e VIAVLESS_SERVER_HOST=<YOUR_SERVER_IP> \\");
        println!("    -e VIAVLESS_UUID={} \\", config.uuid);
        println!("    -e VIAVLESS_FINGERPRINT={} \\", fingerprint);
        println!("    -e VIAVLESS_SOCKS_LISTEN=0.0.0.0:1080 \\");
        println!("    ghcr.io/rezraf/viavless-client:latest");
        println!();

        tracing::info!(fingerprint = %fingerprint, "reality mode: self-signed cert generated");
        server::run_tls_with_acceptor(&config.listen, &config.uuid, tls_acceptor, &config.ws_path).await
    }
}
