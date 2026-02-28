# rust-vless-proxy

A high-performance VLESS-like proxy written in Rust with advanced DPI (Deep Packet Inspection) evasion techniques.

## Features

- **SOCKS5 local proxy** — drop-in replacement for any app that supports SOCKS5
- **TLS + WebSocket transport** — looks like regular HTTPS traffic to any observer
- **UUID authentication** — only authorized clients can use the proxy
- **TCP & UDP relay** — full TCP tunneling + UDP support (DNS, etc.)
- **Traffic padding** — random noise frames break traffic analysis patterns

### DPI Evasion Techniques

| Technique | Description |
|-----------|-------------|
| **TLS ClientHello fragmentation** | Splits the first TLS handshake message into multiple tiny TCP segments with random sizes, preventing DPI from reading the SNI field |
| **TLS record splitting** | Breaks a single TLS record into multiple valid TLS records with smaller payloads |
| **Fake SNI (domain fronting)** | Replaces the SNI in ClientHello with a legitimate domain (e.g., `www.google.com`) |
| **Traffic padding** | Injects random-sized padding frames between real data to defeat traffic analysis |
| **TCP_NODELAY fragmentation** | Forces each write to go as a separate TCP segment |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENT MACHINE                             │
│                                                                     │
│  ┌──────────┐    SOCKS5     ┌──────────────────────────────────┐   │
│  │ Browser  │──────────────▶│       viavless-client             │   │
│  │ / App    │  127.0.0.1    │                                  │   │
│  └──────────┘   :1080       │  ┌─────────────────────────────┐ │   │
│                             │  │ DPI Evasion Layer            │ │   │
│                             │  │ • ClientHello fragmentation  │ │   │
│                             │  │ • TLS record splitting       │ │   │
│                             │  │ • Fake SNI injection         │ │   │
│                             │  │ • Traffic padding            │ │   │
│                             │  └─────────────────────────────┘ │   │
│                             └──────────┬───────────────────────┘   │
│                                        │ TLS + WebSocket            │
└────────────────────────────────────────┼───────────────────────────┘
                                         │
                    ═══════ Internet (DPI can't read this) ════════
                                         │
┌────────────────────────────────────────┼───────────────────────────┐
│                          VPS / SERVER  │                            │
│                             ┌──────────▼───────────────────────┐   │
│                             │       viavless-server             │   │
│                             │                                  │   │
│                             │  1. TLS terminate                │   │
│                             │  2. WebSocket accept             │   │
│                             │  3. UUID auth check              │   │
│                             │  4. Parse FrameType (Data/Pad)   │   │
│                             │  5. TCP/UDP relay to target      │   │
│                             └──────────┬───────────────────────┘   │
│                                        │                            │
│                             ┌──────────▼───────────────────────┐   │
│                             │     Target (google.com, etc)     │   │
│                             └──────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

## Protocol

Binary protocol inspired by VLESS:

```
Request Header:
┌─────────┬──────────┬─────────┬──────┬──────────┬─────────┐
│ version │   UUID   │   cmd   │ atyp │ address  │ payload │
│ 1 byte  │  16 B    │ 1 byte  │ 1 B  │ variable │  rest   │
└─────────┴──────────┴─────────┴──────┴──────────┴─────────┘

Data frames (after handshake):
┌──────────┬─────────┐
│ type     │ payload │
│ 1 byte   │  rest   │
└──────────┴─────────┘
type: 0x00 = Data, 0x01 = Padding (discarded)
```

## Quick Start

### 1. Setup

```bash
git clone https://github.com/rezraf/rust-vless-proxy.git
cd rust-vless-proxy

# Generate UUID + self-signed TLS certs + .env
./setup.sh your-domain.com
```

### 2. Server (on VPS)

```bash
cargo run --release -p viavless-server
```

Or with Docker:

```bash
docker compose up -d
```

### 3. Client (on local machine)

```bash
export VIAVLESS_SERVER_HOST=your-domain.com
export VIAVLESS_UUID=<uuid-from-setup>
export VIAVLESS_FRAGMENT=true
export VIAVLESS_PADDING=true

cargo run --release -p viavless-client
```

### 4. Configure your browser

Set SOCKS5 proxy to `127.0.0.1:1080`

## Configuration

All configuration is done via environment variables:

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `VIAVLESS_LISTEN` | `0.0.0.0:443` | Listen address |
| `VIAVLESS_UUID` | *required* | Client UUID for auth |
| `VIAVLESS_TLS_CERT` | `cert.pem` | TLS certificate path |
| `VIAVLESS_TLS_KEY` | `key.pem` | TLS private key path |
| `VIAVLESS_WS_PATH` | `/ws` | WebSocket endpoint path |

### Client

| Variable | Default | Description |
|----------|---------|-------------|
| `VIAVLESS_SOCKS_LISTEN` | `127.0.0.1:1080` | Local SOCKS5 listen address |
| `VIAVLESS_SERVER_HOST` | *required* | Server hostname |
| `VIAVLESS_SERVER_PORT` | `443` | Server port |
| `VIAVLESS_SERVER_SNI` | same as host | TLS SNI (for CDN setups) |
| `VIAVLESS_WS_PATH` | `/ws` | WebSocket path |
| `VIAVLESS_UUID` | *required* | Auth UUID |
| `VIAVLESS_FRAGMENT` | `true` | Enable ClientHello fragmentation |
| `VIAVLESS_FRAGMENT_SIZE` | `40` | Max fragment size in bytes |
| `VIAVLESS_PADDING` | `true` | Enable traffic padding |
| `VIAVLESS_PADDING_MAX` | `256` | Max padding size in bytes |
| `VIAVLESS_FAKE_SNI` | *none* | Fake SNI domain for domain fronting |
| `RUST_LOG` | *none* | Log level (`viavless=debug`) |

## Docker Compose (with Let's Encrypt)

The included `docker-compose.yml` uses Caddy for automatic HTTPS:

```bash
# Edit .env with your domain and UUID
cp .env.example .env
vim .env

# Start
docker compose up -d

# Check logs
docker compose logs -f
```

Caddy automatically obtains and renews Let's Encrypt certificates.

## Building from Source

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Binaries will be in target/release/
ls -la target/release/viavless-{client,server}
```

## How DPI Evasion Works

### TLS ClientHello Fragmentation

DPI systems inspect the first TCP segment to find the TLS ClientHello and extract the SNI (Server Name Indication). By splitting this message into multiple tiny TCP segments (1-40 bytes each, randomized), the DPI system cannot reassemble and read the SNI.

```
Normal:   [Full ClientHello with SNI in one TCP segment]  <- DPI reads SNI
Evaded:   [5B] [12B] [3B] [28B] [7B] [19B] ...           <- DPI sees garbage
```

### Fake SNI (Domain Fronting)

The outer TLS ClientHello (visible to DPI) contains a legitimate domain like `www.google.com`, while the actual connection goes to our proxy server. This works when the proxy is behind a CDN that ignores the SNI mismatch.

### Traffic Padding

Random-sized padding frames are injected between real data. The server discards them. This prevents traffic analysis that looks for patterns in packet sizes and timing.

## License

MIT — see [LICENSE](LICENSE)
