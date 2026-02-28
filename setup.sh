#!/bin/bash
set -e

# Generate UUID and self-signed TLS certificates for viavless

UUID=$(uuidgen | tr '[:upper:]' '[:lower:]')
DOMAIN="${1:-proxy.example.com}"

echo "=== Viavless Setup ==="
echo ""
echo "Generated UUID: $UUID"
echo "Domain: $DOMAIN"
echo ""

# Generate self-signed TLS cert (for testing; use Let's Encrypt in production)
if [ ! -f cert.pem ] || [ ! -f key.pem ]; then
    echo "Generating self-signed TLS certificate..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout key.pem -out cert.pem -days 365 -nodes \
        -subj "/CN=$DOMAIN" 2>/dev/null
    echo "Created cert.pem and key.pem"
else
    echo "cert.pem and key.pem already exist, skipping"
fi

# Generate .env file
cat > .env <<EOF
# === Server config ===
VIAVLESS_LISTEN=0.0.0.0:443
VIAVLESS_UUID=$UUID
VIAVLESS_TLS_CERT=cert.pem
VIAVLESS_TLS_KEY=key.pem
VIAVLESS_WS_PATH=/ws

# === Client config (copy to client machine) ===
# VIAVLESS_SOCKS_LISTEN=127.0.0.1:1080
# VIAVLESS_SERVER_HOST=$DOMAIN
# VIAVLESS_SERVER_PORT=443
# VIAVLESS_SERVER_SNI=$DOMAIN
# VIAVLESS_WS_PATH=/ws
# VIAVLESS_UUID=$UUID
# VIAVLESS_FRAGMENT=true
# VIAVLESS_FRAGMENT_SIZE=40
# VIAVLESS_PADDING=true
# VIAVLESS_PADDING_MAX=256

# Logging
RUST_LOG=viavless=info
EOF

echo "Created .env"
echo ""
echo "=== Quick start ==="
echo ""
echo "Server (on VPS):"
echo "  cargo run --release -p viavless-server"
echo ""
echo "Client (on local machine):"
echo "  VIAVLESS_SERVER_HOST=$DOMAIN VIAVLESS_UUID=$UUID cargo run --release -p viavless-client"
echo ""
echo "Then configure your browser/system to use SOCKS5 proxy at 127.0.0.1:1080"
