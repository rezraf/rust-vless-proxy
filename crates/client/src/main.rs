mod dpi;
mod fragment_stream;
mod socks5;
mod tunnel;

use std::sync::Arc;

use socks5::SocksRequest;
use tokio_rustls::TlsConnector;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

struct Config {
    socks_listen: String,
    server_host: String,
    server_port: u16,
    server_sni: String,
    ws_path: String,
    uuid: Uuid,
    fake_sni: Option<String>,
    fragment_enabled: bool,
    fragment_size: usize,
    padding_enabled: bool,
    padding_max: usize,
    tls_connector: TlsConnector,
}

/// Custom TLS certificate verifier that checks SHA-256 fingerprint
/// instead of validating against a CA chain (Reality mode).
#[derive(Debug)]
struct FingerprintVerifier {
    expected_fingerprint: Vec<u8>,
}

impl FingerprintVerifier {
    fn new(hex_fingerprint: &str) -> anyhow::Result<Self> {
        let expected = hex::decode(hex_fingerprint)
            .map_err(|_| anyhow::anyhow!("VIAVLESS_FINGERPRINT is not valid hex"))?;
        if expected.len() != 32 {
            return Err(anyhow::anyhow!("VIAVLESS_FINGERPRINT must be a SHA-256 hash (64 hex chars)"));
        }
        Ok(Self { expected_fingerprint: expected })
    }
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::{Sha256, Digest};

        let fingerprint = Sha256::digest(end_entity.as_ref());

        if fingerprint.as_slice() == self.expected_fingerprint.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            let got = hex::encode(fingerprint);
            tracing::error!(
                expected = hex::encode(&self.expected_fingerprint),
                got = %got,
                "server certificate fingerprint mismatch"
            );
            Err(rustls::Error::General("certificate fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl Config {
    fn from_env() -> Self {
        let uuid: Uuid = std::env::var("VIAVLESS_UUID")
            .expect("VIAVLESS_UUID must be set")
            .parse()
            .expect("VIAVLESS_UUID is not a valid UUID");

        let fingerprint = std::env::var("VIAVLESS_FINGERPRINT").ok();

        let tls_connector = if let Some(ref fp) = fingerprint {
            // Reality mode — verify by fingerprint, no CA needed
            let verifier = FingerprintVerifier::new(fp)
                .expect("invalid VIAVLESS_FINGERPRINT");
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth();
            TlsConnector::from(Arc::new(tls_config))
        } else {
            // Standard mode — verify against system CA roots
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            TlsConnector::from(Arc::new(tls_config))
        };

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
                .unwrap_or_else(|_| {
                    if fingerprint.is_some() {
                        // In reality mode, SNI doesn't matter — use a dummy
                        "viavless.local".into()
                    } else {
                        std::env::var("VIAVLESS_SERVER_HOST").unwrap_or_default()
                    }
                }),
            ws_path: std::env::var("VIAVLESS_WS_PATH").unwrap_or_else(|_| "/ws".into()),
            uuid,
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
            tls_connector,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("viavless=info".parse()?))
        .init();

    let config = Config::from_env();

    let mode = if std::env::var("VIAVLESS_FINGERPRINT").is_ok() { "reality" } else { "standard" };
    tracing::info!(
        listen = %config.socks_listen,
        server = %config.server_host,
        mode = mode,
        fragment = config.fragment_enabled,
        padding = config.padding_enabled,
        "starting viavless client"
    );

    let listener = tokio::net::TcpListener::bind(&config.socks_listen).await?;
    let config = Arc::new(config);

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
