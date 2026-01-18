#!/bin/bash
# update.sh - Update s3-crypt-proxy and redeploy the encryption key
# This script updates the binaries and optionally sends the encryption key

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Defaults
INSTALL_DIR="/opt/s3-crypt-proxy"
CONFIG_DIR="/etc/s3-crypt-proxy"
SERVICE_USER="s3crypt"

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (use sudo)"
    fi
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

show_status() {
    echo
    echo -e "${BLUE}Current Service Status:${NC}"
    echo "----------------------------------------"
    
    if systemctl is-active --quiet memkey-server; then
        echo -e "Memkey Server: ${GREEN}RUNNING${NC}"
    else
        echo -e "Memkey Server: ${RED}STOPPED${NC}"
    fi
    
    if systemctl is-active --quiet s3-crypt-proxy; then
        echo -e "S3 Crypt Proxy: ${GREEN}RUNNING${NC}"
    else
        echo -e "S3 Crypt Proxy: ${RED}STOPPED${NC}"
    fi
    
    # Check if key is loaded
    if command -v curl &> /dev/null; then
        local memkey_port=$(grep -oP 'listen_addr:.*:\K\d+' "$CONFIG_DIR/memkey.yaml" 2>/dev/null || echo "7070")
        local status=$(curl -s "http://127.0.0.1:$memkey_port/status" 2>/dev/null)
        if [ -n "$status" ]; then
            local key_loaded=$(echo "$status" | grep -oP '"key_loaded":\s*\K(true|false)')
            if [ "$key_loaded" = "true" ]; then
                echo -e "Encryption Key: ${GREEN}LOADED${NC}"
            else
                echo -e "Encryption Key: ${YELLOW}NOT LOADED${NC}"
            fi
        fi
    fi
    
    echo "----------------------------------------"
    echo
}

build_binaries() {
    local src_dir="${SRC_DIR:-$(dirname "$0")/..}"
    
    if [ ! -d "$src_dir/cmd" ]; then
        error "Source directory not found. Set SRC_DIR environment variable."
    fi
    
    info "Building binaries from $src_dir..."
    
    cd "$src_dir"
    
    export PATH=$PATH:/usr/local/go/bin
    export CGO_ENABLED=0
    
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/s3-crypt-proxy.new" ./cmd/s3-crypt-proxy
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/memkey-server.new" ./cmd/memkey-server
    go build -ldflags="-s -w" -o "$INSTALL_DIR/bin/memkey-admin.new" ./cmd/memkey-admin
    
    success "Binaries built"
}

backup_binaries() {
    info "Backing up current binaries..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="$INSTALL_DIR/backup/$timestamp"
    
    mkdir -p "$backup_dir"
    
    for bin in s3-crypt-proxy memkey-server memkey-admin; do
        if [ -f "$INSTALL_DIR/bin/$bin" ]; then
            cp "$INSTALL_DIR/bin/$bin" "$backup_dir/"
        fi
    done
    
    success "Binaries backed up to $backup_dir"
}

update_binaries() {
    info "Installing new binaries..."
    
    for bin in s3-crypt-proxy memkey-server memkey-admin; do
        if [ -f "$INSTALL_DIR/bin/$bin.new" ]; then
            mv "$INSTALL_DIR/bin/$bin.new" "$INSTALL_DIR/bin/$bin"
            chmod +x "$INSTALL_DIR/bin/$bin"
        fi
    done
    
    success "Binaries updated"
}

restart_services() {
    info "Restarting services..."
    
    # Stop proxy first (it depends on memkey)
    if systemctl is-active --quiet s3-crypt-proxy; then
        systemctl stop s3-crypt-proxy
        info "Stopped s3-crypt-proxy"
    fi
    
    # Restart memkey server
    if systemctl is-active --quiet memkey-server; then
        systemctl restart memkey-server
        info "Restarted memkey-server"
    else
        systemctl start memkey-server
        info "Started memkey-server"
    fi
    
    # Wait for memkey to be ready
    sleep 2
    
    success "Services restarted"
}

start_proxy() {
    if ! systemctl is-active --quiet s3-crypt-proxy; then
        systemctl start s3-crypt-proxy
        info "Started s3-crypt-proxy"
    fi
}

get_memkey_fingerprint() {
    local memkey_port=$(grep -oP 'listen_addr:.*:\K\d+' "$CONFIG_DIR/memkey.yaml" 2>/dev/null || echo "7070")
    
    # Wait for memkey server to start
    local max_attempts=10
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        local status=$(curl -s "http://127.0.0.1:$memkey_port/status" 2>/dev/null)
        if [ -n "$status" ]; then
            echo "$status" | grep -oP '"server_fingerprint":\s*"\K[^"]+' 
            return 0
        fi
        sleep 1
        ((attempt++))
    done
    
    return 1
}

send_key_interactive() {
    local memkey_port=$(grep -oP 'listen_addr:.*:\K\d+' "$CONFIG_DIR/memkey.yaml" 2>/dev/null || echo "7070")
    
    echo
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    KEY DEPLOYMENT REQUIRED                     ${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo
    echo "The memkey server has been restarted and needs the encryption key."
    echo
    
    # Get and display fingerprint
    local fingerprint=$(get_memkey_fingerprint)
    if [ -n "$fingerprint" ]; then
        echo -e "${BLUE}Server Fingerprint:${NC}"
        echo "  $fingerprint"
        echo
        echo -e "${RED}IMPORTANT: Verify this fingerprint matches your records!${NC}"
        echo
    else
        warn "Could not retrieve server fingerprint. Check if memkey-server is running."
        echo "  journalctl -u memkey-server -n 20"
        echo
    fi
    
    echo "To send the encryption key, use the memkey-admin tool from your local machine:"
    echo
    echo "  1. Ensure memkey-admin is initialized with the correct fingerprint:"
    echo "     memkey-admin status"
    echo
    echo "  2. Send the key:"
    echo "     memkey-admin key send"
    echo
    
    if prompt_yes_no "Do you have memkey-admin configured locally and want to wait for key deployment?" "y"; then
        echo
        info "Waiting for key to be loaded..."
        echo "Run 'memkey-admin key send' from your local machine now."
        echo
        
        local max_wait=300  # 5 minutes
        local waited=0
        local interval=5
        
        while [ $waited -lt $max_wait ]; do
            local status=$(curl -s "http://127.0.0.1:$memkey_port/status" 2>/dev/null)
            local key_loaded=$(echo "$status" | grep -oP '"key_loaded":\s*\K(true|false)')
            
            if [ "$key_loaded" = "true" ]; then
                echo
                success "Encryption key loaded successfully!"
                
                # Start the proxy now that key is loaded
                start_proxy
                
                return 0
            fi
            
            echo -n "."
            sleep $interval
            ((waited += interval))
        done
        
        echo
        warn "Timeout waiting for key. You can send it later with 'memkey-admin key send'"
    fi
    
    echo
    info "The proxy will start automatically once the key is loaded."
    info "Or start it manually: systemctl start s3-crypt-proxy"
}

# Check if key is already loaded
check_key_loaded() {
    local memkey_port=$(grep -oP 'listen_addr:.*:\K\d+' "$CONFIG_DIR/memkey.yaml" 2>/dev/null || echo "7070")
    local status=$(curl -s "http://127.0.0.1:$memkey_port/status" 2>/dev/null)
    local key_loaded=$(echo "$status" | grep -oP '"key_loaded":\s*\K(true|false)')
    [ "$key_loaded" = "true" ]
}

main() {
    echo
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}              S3-Crypt-Proxy Update Script v1.0                ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo
    
    check_root
    
    # Check if this is a fresh system
    if [ ! -f "$INSTALL_DIR/bin/s3-crypt-proxy" ]; then
        error "s3-crypt-proxy not installed. Run deploy.sh first."
    fi
    
    show_status
    
    # Parse arguments
    local skip_build=false
    local skip_key=false
    local force=false
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --skip-build)
                skip_build=true
                ;;
            --skip-key)
                skip_key=true
                ;;
            --force|-f)
                force=true
                ;;
            --help|-h)
                echo "Usage: update.sh [options]"
                echo
                echo "Options:"
                echo "  --skip-build    Skip building (use pre-built binaries)"
                echo "  --skip-key      Skip key deployment prompt"
                echo "  --force, -f     Don't prompt for confirmation"
                echo "  --help, -h      Show this help"
                exit 0
                ;;
            *)
                warn "Unknown option: $1"
                ;;
        esac
        shift
    done
    
    if [ "$force" != "true" ]; then
        echo "This will:"
        echo "  1. Build new binaries (unless --skip-build)"
        echo "  2. Stop the services"
        echo "  3. Update the binaries"
        echo "  4. Restart services"
        echo "  5. Prompt for key deployment (unless --skip-key)"
        echo
        
        if ! prompt_yes_no "Continue with update?" "y"; then
            echo "Aborted."
            exit 0
        fi
    fi
    
    # Build
    if [ "$skip_build" != "true" ]; then
        build_binaries
    fi
    
    # Backup and update
    backup_binaries
    
    # Stop services and update
    restart_services
    update_binaries
    
    # Restart memkey server with new binary
    systemctl restart memkey-server
    sleep 2
    
    # Handle key deployment
    if [ "$skip_key" != "true" ]; then
        if ! check_key_loaded; then
            send_key_interactive
        else
            success "Key is already loaded"
            start_proxy
        fi
    else
        info "Skipping key deployment (--skip-key)"
        info "Remember to send the key: memkey-admin key send"
    fi
    
    echo
    show_status
    
    success "Update complete!"
}

main "$@"
