#!/bin/bash
# deploy.sh - Interactive deployment script for s3-crypt-proxy on Ubuntu 24 LTS
# This script sets up a fresh VM with the proxy and memkey server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
INSTALL_DIR="/opt/s3-crypt-proxy"
CONFIG_DIR="/etc/s3-crypt-proxy"
DATA_DIR="/var/lib/s3-crypt-proxy"
LOG_DIR="/var/log/s3-crypt-proxy"
SERVICE_USER="s3crypt"
PROXY_PORT="8080"
ADMIN_PORT="9090"
MEMKEY_PORT="7070"

# Print functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

prompt() {
    local var_name=$1
    local prompt_text=$2
    local default_value=$3
    local is_secret=${4:-false}
    
    if [ -n "$default_value" ]; then
        prompt_text="$prompt_text [$default_value]"
    fi
    
    if [ "$is_secret" = true ]; then
        read -sp "$prompt_text: " value
        echo
    else
        read -p "$prompt_text: " value
    fi
    
    if [ -z "$value" ] && [ -n "$default_value" ]; then
        value="$default_value"
    fi
    
    eval "$var_name='$value'"
}

prompt_yes_no() {
    local prompt_text=$1
    local default=${2:-n}
    
    if [ "$default" = "y" ]; then
        prompt_text="$prompt_text [Y/n]"
    else
        prompt_text="$prompt_text [y/N]"
    fi
    
    read -p "$prompt_text: " response
    response=${response:-$default}
    
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (use sudo)"
    fi
}

# Check Ubuntu version
check_ubuntu() {
    if [ ! -f /etc/os-release ]; then
        error "Cannot detect OS version"
    fi
    
    . /etc/os-release
    
    if [ "$ID" != "ubuntu" ]; then
        warn "This script is designed for Ubuntu. Detected: $ID"
        if ! prompt_yes_no "Continue anyway?"; then
            exit 1
        fi
    fi
    
    if [[ "$VERSION_ID" != "24."* ]]; then
        warn "This script is designed for Ubuntu 24.x. Detected: $VERSION_ID"
        if ! prompt_yes_no "Continue anyway?"; then
            exit 1
        fi
    fi
    
    success "Detected Ubuntu $VERSION_ID"
}

# Install dependencies
install_dependencies() {
    info "Updating package lists..."
    apt-get update -qq
    
    info "Installing dependencies..."
    apt-get install -y -qq \
        curl \
        wget \
        jq \
        openssl \
        ca-certificates \
        gnupg \
        lsb-release
    
    # Install Go if not present
    if ! command -v go &> /dev/null; then
        info "Installing Go 1.22..."
        wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
    fi
    
    success "Dependencies installed"
}

# Create service user
create_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        info "User $SERVICE_USER already exists"
    else
        info "Creating service user: $SERVICE_USER"
        useradd --system --shell /bin/false --home-dir "$DATA_DIR" "$SERVICE_USER"
    fi
    success "Service user ready"
}

# Create directories
create_directories() {
    info "Creating directories..."
    
    mkdir -p "$INSTALL_DIR/bin"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    # Config dir: root owns it, s3crypt group can read, others have no access
    chown root:"$SERVICE_USER" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    
    success "Directories created"
}

# Collect configuration
collect_config() {
    echo
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    S3-Crypt-Proxy Configuration                ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo
    
    # Proxy settings
    echo -e "${YELLOW}── Proxy Settings ──${NC}"
    prompt PROXY_PORT "Proxy listen port" "$PROXY_PORT"
    prompt ADMIN_PORT "Admin API port" "$ADMIN_PORT"
    prompt MEMKEY_PORT "Memkey server port" "$MEMKEY_PORT"
    
    echo
    echo -e "${YELLOW}── Backend S3 Settings ──${NC}"
    prompt S3_ENDPOINT "S3 endpoint URL (e.g., https://s3.amazonaws.com or https://minio.local:9000)" ""
    prompt S3_REGION "S3 region" "us-east-1"
    prompt S3_ACCESS_KEY "S3 access key" ""
    prompt S3_SECRET_KEY "S3 secret key" "" true
    
    if prompt_yes_no "Use path-style addressing? (required for MinIO)" "n"; then
        S3_PATH_STYLE="true"
    else
        S3_PATH_STYLE="false"
    fi
    
    if prompt_yes_no "Skip TLS verification for S3 backend?" "n"; then
        S3_SKIP_TLS="true"
    else
        S3_SKIP_TLS="false"
    fi
    
    echo
    echo -e "${YELLOW}── Client Authentication ──${NC}"
    echo "Generate credentials for PBS to use when connecting to the proxy"
    prompt CLIENT_ACCESS_KEY "Client access key" "$(openssl rand -hex 16)"
    prompt CLIENT_SECRET_KEY "Client secret key" "$(openssl rand -hex 32)" true
    
    echo
    echo -e "${YELLOW}── Bucket Access Control ──${NC}"
    echo "Specify which buckets clients can access (comma-separated)"
    echo "Leave empty to allow access to all buckets (not recommended)"
    prompt ALLOWED_BUCKETS "Allowed buckets" ""
    
    echo
    echo -e "${YELLOW}── Admin Authentication ──${NC}"
    prompt ADMIN_TOKEN "Admin API token" "$(openssl rand -hex 32)" true
    
    echo
    echo -e "${YELLOW}── TLS Configuration ──${NC}"
    if prompt_yes_no "Enable TLS for proxy?" "y"; then
        PROXY_TLS_ENABLED="true"
        prompt PROXY_TLS_CERT "TLS certificate path" "$CONFIG_DIR/proxy.crt"
        prompt PROXY_TLS_KEY "TLS key path" "$CONFIG_DIR/proxy.key"
        
        if [ ! -f "$PROXY_TLS_CERT" ]; then
            if prompt_yes_no "Generate self-signed certificate?" "y"; then
                GENERATE_CERT="true"
                prompt CERT_CN "Certificate Common Name (hostname)" "$(hostname -f)"
            fi
        fi
    else
        PROXY_TLS_ENABLED="false"
    fi
    
    echo
    echo -e "${YELLOW}── Memkey Server ──${NC}"
    echo "The memkey server holds the encryption key in memory only."
    echo "After deployment, you'll need to send the key using the admin tool."
    
    if prompt_yes_no "Enable memkey server TLS?" "y"; then
        MEMKEY_TLS_ENABLED="true"
        prompt MEMKEY_TLS_CERT "Memkey TLS certificate path" "$CONFIG_DIR/memkey.crt"
        prompt MEMKEY_TLS_KEY "Memkey TLS key path" "$CONFIG_DIR/memkey.key"
        
        if [ ! -f "$MEMKEY_TLS_CERT" ]; then
            if prompt_yes_no "Generate self-signed certificate for memkey?" "y"; then
                GENERATE_MEMKEY_CERT="true"
            fi
        fi
    else
        MEMKEY_TLS_ENABLED="false"
        warn "Running memkey without TLS is insecure!"
    fi
    
    # Generate memkey server identity
    info "Generating memkey server identity keypair..."
    MEMKEY_PRIVATE_KEY=$(openssl rand -hex 32)
    
    echo
    success "Configuration collected"
}

# Generate TLS certificates
generate_certificates() {
    if [ "$GENERATE_CERT" = "true" ]; then
        info "Generating self-signed proxy certificate..."
        openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
            -nodes -keyout "$PROXY_TLS_KEY" -out "$PROXY_TLS_CERT" \
            -subj "/CN=$CERT_CN" \
            -addext "subjectAltName=DNS:$CERT_CN,DNS:localhost,IP:127.0.0.1" \
            2>/dev/null
        chmod 600 "$PROXY_TLS_KEY"
        success "Proxy certificate generated"
    fi
    
    if [ "$GENERATE_MEMKEY_CERT" = "true" ]; then
        info "Generating self-signed memkey certificate..."
        openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
            -nodes -keyout "$MEMKEY_TLS_KEY" -out "$MEMKEY_TLS_CERT" \
            -subj "/CN=memkey.local" \
            -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
            2>/dev/null
        chmod 600 "$MEMKEY_TLS_KEY"
        success "Memkey certificate generated"
    fi
}

# Build binaries
build_binaries() {
    info "Building s3-crypt-proxy..."
    
    # Assuming the source is in the current directory or specified location
    local src_dir="${SRC_DIR:-$(dirname "$0")/..}"
    
    if [ ! -d "$src_dir/cmd" ]; then
        error "Source directory not found. Set SRC_DIR environment variable."
    fi
    
    cd "$src_dir"
    
    export PATH=$PATH:/usr/local/go/bin
    export CGO_ENABLED=0
    
    # Build main proxy
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/s3-crypt-proxy" ./cmd/s3-crypt-proxy
    
    # Build memkey server
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/memkey-server" ./cmd/memkey-server
    
    # Build memkey admin tool
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/memkey-admin" ./cmd/memkey-admin
    
    chmod +x "$INSTALL_DIR/bin/"*
    
    success "Binaries built"
}

# Write configuration files
write_config() {
    info "Writing configuration files..."
    
    # Main proxy config
    cat > "$CONFIG_DIR/config.yaml" << EOF
# S3-Crypt-Proxy Configuration
# Generated by deploy.sh on $(date)

proxy:
  listen_addr: "0.0.0.0:${PROXY_PORT}"
  tls_enabled: ${PROXY_TLS_ENABLED}
  tls_cert: "${PROXY_TLS_CERT}"
  tls_key: "${PROXY_TLS_KEY}"

admin:
  listen_addr: "127.0.0.1:${ADMIN_PORT}"
  token: "${ADMIN_TOKEN}"

backend:
  endpoint: "${S3_ENDPOINT}"
  region: "${S3_REGION}"
  access_key: "${S3_ACCESS_KEY}"
  secret_key: "${S3_SECRET_KEY}"
  path_style: ${S3_PATH_STYLE}
  skip_tls_verify: ${S3_SKIP_TLS}

client:
  access_key: "${CLIENT_ACCESS_KEY}"
  secret_key: "${CLIENT_SECRET_KEY}"

encryption:
  chunk_size: 4194304  # 4MB - matches PBS chunk size

# Allowed buckets (if empty, all buckets are allowed)
allowed_buckets:
$(if [ -n "$ALLOWED_BUCKETS" ]; then
    IFS=',' read -ra BUCKETS <<< "$ALLOWED_BUCKETS"
    for bucket in "${BUCKETS[@]}"; do
        bucket=$(echo "$bucket" | xargs)  # trim whitespace
        echo "  - \"$bucket\""
    done
fi)

# Key source: memkey server
key_source: "memkey"
memkey:
  # Unix socket for secure key transfer (recommended)
  socket_path: "/run/memkey/memkey.sock"
  # HTTP endpoint for status checks (fallback)
  endpoint: "http://127.0.0.1:${MEMKEY_PORT}"
  poll_interval: "5s"
EOF
    
    chmod 640 "$CONFIG_DIR/config.yaml"
    chown root:"$SERVICE_USER" "$CONFIG_DIR/config.yaml"
    
    # Memkey server config
    cat > "$CONFIG_DIR/memkey.yaml" << EOF
# Memkey Server Configuration
# Generated by deploy.sh on $(date)

server:
  listen_addr: "127.0.0.1:${MEMKEY_PORT}"
  tls_enabled: ${MEMKEY_TLS_ENABLED}
  tls_cert: "${MEMKEY_TLS_CERT}"
  tls_key: "${MEMKEY_TLS_KEY}"
  # Unix socket for secure local key transfer to proxy
  unix_socket_path: "/run/memkey/memkey.sock"

identity:
  # Server's Ed25519 private key (hex encoded)
  # The public key fingerprint will be logged on startup
  private_key: "${MEMKEY_PRIVATE_KEY}"

security:
  # Challenge validity duration
  challenge_timeout: "30s"
  # Max failed attempts before lockout
  max_failed_attempts: 5
  # Lockout duration
  lockout_duration: "5m"
EOF
    
    chmod 600 "$CONFIG_DIR/memkey.yaml"
    chown root:root "$CONFIG_DIR/memkey.yaml"
    
    success "Configuration files written"
}

# Create systemd services
create_services() {
    info "Creating systemd services..."
    
    # Memkey server service (starts first)
    cat > /etc/systemd/system/memkey-server.service << EOF
[Unit]
Description=S3-Crypt-Proxy Memkey Server
Documentation=https://github.com/example/s3-crypt-proxy
After=network.target

[Service]
Type=simple
User=root
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/bin/memkey-server -config ${CONFIG_DIR}/memkey.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Runtime directory for Unix socket
# Creates /run/memkey with permissions 0750 (root:s3crypt)
RuntimeDirectory=memkey
RuntimeDirectoryMode=0750

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Memory protection - key stays in memory
MemoryMax=64M
MemorySwapMax=0

[Install]
WantedBy=multi-user.target
EOF
    
    # Main proxy service
    cat > /etc/systemd/system/s3-crypt-proxy.service << EOF
[Unit]
Description=S3-Crypt-Proxy - Encryption Proxy for S3
Documentation=https://github.com/example/s3-crypt-proxy
After=network.target memkey-server.service
Wants=memkey-server.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/bin/s3-crypt-proxy -config ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
# AF_UNIX needed for memkey socket communication
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes

# Allow binding to privileged ports if needed
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    success "Systemd services created"
}

# Configure firewall
configure_firewall() {
    if command -v ufw &> /dev/null; then
        info "Configuring UFW firewall..."
        
        if prompt_yes_no "Allow proxy port $PROXY_PORT through firewall?" "y"; then
            ufw allow "$PROXY_PORT/tcp" comment "S3-Crypt-Proxy"
            success "Firewall rule added for port $PROXY_PORT"
        fi
        
        # Admin and memkey ports should only be accessible locally by default
        info "Admin ($ADMIN_PORT) and memkey ($MEMKEY_PORT) ports are bound to localhost only"
    fi
}

# Print summary
print_summary() {
    # Calculate server public key fingerprint
    local pubkey_fp
    pubkey_fp=$("$INSTALL_DIR/bin/memkey-server" -config "$CONFIG_DIR/memkey.yaml" -print-fingerprint 2>/dev/null || echo "Run 'memkey-server -print-fingerprint' to get this")
    
    echo
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    Deployment Complete!                        ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BLUE}Service Status:${NC}"
    echo "  Proxy:  systemctl status s3-crypt-proxy"
    echo "  Memkey: systemctl status memkey-server"
    echo
    echo -e "${BLUE}Start Services:${NC}"
    echo "  systemctl enable --now memkey-server"
    echo "  systemctl enable --now s3-crypt-proxy"
    echo
    echo -e "${BLUE}Important Paths:${NC}"
    echo "  Config:   $CONFIG_DIR/config.yaml"
    echo "  Memkey:   $CONFIG_DIR/memkey.yaml"
    echo "  Binaries: $INSTALL_DIR/bin/"
    echo "  Logs:     journalctl -u s3-crypt-proxy -f"
    echo
    echo -e "${BLUE}Client Configuration (for PBS):${NC}"
    if [ "$PROXY_TLS_ENABLED" = "true" ]; then
        echo "  Endpoint:   https://$(hostname -f):${PROXY_PORT}"
    else
        echo "  Endpoint:   http://$(hostname -f):${PROXY_PORT}"
    fi
    echo "  Access Key: ${CLIENT_ACCESS_KEY}"
    echo "  Secret Key: ${CLIENT_SECRET_KEY}"
    if [ -n "$ALLOWED_BUCKETS" ]; then
        echo "  Allowed Buckets: ${ALLOWED_BUCKETS}"
    fi
    echo
    echo -e "${BLUE}Key Transfer:${NC}"
    echo "  Unix Socket: /run/memkey/memkey.sock (proxy <-> memkey-server)"
    echo "  Admin Port:  ${MEMKEY_PORT} (memkey-admin -> memkey-server)"
    echo
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    IMPORTANT: Key Deployment                   ${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo
    echo "The encryption key must be sent to the memkey server after each reboot."
    echo "Use the memkey-admin tool on your local machine:"
    echo
    echo "  1. Copy the admin tool to your local machine:"
    echo "     scp root@$(hostname -f):${INSTALL_DIR}/bin/memkey-admin ./"
    echo
    echo "  2. Initialize the admin tool with server fingerprint:"
    echo "     ./memkey-admin init \\"
    if [ "$MEMKEY_TLS_ENABLED" = "true" ]; then
        echo "       --server https://$(hostname -f):${MEMKEY_PORT} \\"
    else
        echo "       --server http://$(hostname -f):${MEMKEY_PORT} \\"
    fi
    echo "       --fingerprint \"<fingerprint from server logs>\""
    echo
    echo "  3. Generate or import your encryption key:"
    echo "     ./memkey-admin key generate"
    echo "     # or"
    echo "     ./memkey-admin key import --file master.key"
    echo
    echo "  4. Send the key to the server:"
    echo "     ./memkey-admin key send"
    echo
    echo -e "${RED}Server Fingerprint (verify this in server logs):${NC}"
    echo "  Start memkey-server and check: journalctl -u memkey-server | grep fingerprint"
    echo
}

# Main execution
main() {
    echo
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           S3-Crypt-Proxy Deployment Script v1.0               ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo
    
    check_root
    check_ubuntu
    
    if ! prompt_yes_no "This will install s3-crypt-proxy on this system. Continue?" "y"; then
        exit 0
    fi
    
    install_dependencies
    create_user
    create_directories
    collect_config
    generate_certificates
    build_binaries
    write_config
    create_services
    configure_firewall
    print_summary
    
    echo
    if prompt_yes_no "Start services now?" "y"; then
        systemctl enable --now memkey-server
        sleep 2
        systemctl enable --now s3-crypt-proxy
        echo
        info "Checking service status..."
        systemctl status memkey-server --no-pager -l || true
        echo
        systemctl status s3-crypt-proxy --no-pager -l || true
    fi
    
    echo
    success "Deployment complete!"
}

main "$@"
