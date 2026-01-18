# S3-Crypt-Proxy

A stateless, transparent S3 encryption proxy designed for Proxmox Backup Server (PBS). Provides client-side encryption with authenticated encryption and tamper detection.

## Features

- **Stateless Design**: No local persistent state; all metadata stored encrypted in the backend
- **Strong Cryptography**: XChaCha20-Poly1305 with HKDF-derived nonces (impossible nonce reuse)
- **PBS Compatibility**: Full support for all S3 operations required by Proxmox Backup Server
- **Separation of Concerns**: Client authentication separate from backend credentials
- **Operational Visibility**: Prometheus metrics and live WebUI dashboard
- **Secure Key Management**: Memory-only key storage with challenge-response delivery protocol
- **Perfect Forward Secrecy**: X25519 ephemeral keys for key transmission

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│     PBS     │────▶│  s3-crypt-proxy │────▶│  S3 Backend │
│   Client    │     │   (encrypts)    │     │ (encrypted) │
└─────────────┘     └────────┬────────┘     └─────────────┘
                             │
                    Unix socket (/run/memkey/memkey.sock)
                             │
                    ┌────────▼────────┐
                    │  memkey-server  │◀──── HTTPS (admin protocol)
                    │ (holds key in   │
                    │    memory)      │
                    └────────▲────────┘
                             │
                    ┌────────┴────────┐
                    │  memkey-admin   │
                    │ (sends key via  │
                    │  secure channel)│
                    └─────────────────┘
```

**Key Transfer Security:**
- Proxy fetches the encryption key via **Unix socket** (filesystem permissions)
- Admin delivers key via **HTTPS** with challenge-response authentication
- The `/key/raw` endpoint is only available on the Unix socket, not HTTP

## Quick Start

### Option 1: Automated Deployment (Ubuntu 24 LTS)

For fresh server deployment:

```bash
# Clone the repository
git clone https://github.com/example/s3-crypt-proxy.git
cd s3-crypt-proxy

# Run interactive deployment
sudo ./deploy/deploy.sh
```

The deployment script will:
1. Install dependencies (Go, etc.)
2. Prompt for S3 backend credentials
3. Generate client credentials for PBS
4. Create systemd services
5. Optionally generate TLS certificates

### Option 2: Manual Build

```bash
# Build all binaries
go build -o bin/s3-crypt-proxy ./cmd/s3-crypt-proxy
go build -o bin/memkey-server ./cmd/memkey-server
go build -o bin/memkey-admin ./cmd/memkey-admin
```

## Configuration

### Proxy Configuration (`config.yaml`)

```yaml
listen_addr: "0.0.0.0:8080"
admin_listen_addr: "127.0.0.1:8081"

tls:
  cert_file: "/etc/s3-crypt-proxy/proxy.crt"
  key_file: "/etc/s3-crypt-proxy/proxy.key"

admin:
  token: "your-admin-token"

backend:
  endpoint: "https://s3.amazonaws.com"
  region: "us-east-1"
  access_key: "AKIAIOSFODNN7EXAMPLE"
  secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  path_style: false        # Set true for MinIO
  insecure_skip_verify: false

client:
  access_key: "proxy-client-key"
  secret_key: "proxy-client-secret"

encryption:
  chunk_size: 4194304  # 4MB

# Restrict bucket access (recommended)
allowed_buckets:
  - "my-pbs-bucket"

# Key source: memkey server
memkey:
  socket_path: "/run/memkey/memkey.sock"  # Unix socket (secure)
  endpoint: "http://127.0.0.1:7070"       # HTTP for status checks
  poll_interval: "5s"
```

### Memkey Server Configuration (`memkey.yaml`)

```yaml
server:
  listen_addr: "127.0.0.1:7070"
  tls_enabled: true
  tls_cert: "/etc/s3-crypt-proxy/memkey.crt"
  tls_key: "/etc/s3-crypt-proxy/memkey.key"
  # Unix socket for secure local key transfer to proxy
  unix_socket_path: "/run/memkey/memkey.sock"

identity:
  # Ed25519 seed (hex). Generate with: memkey-server -generate-identity
  private_key: "your-64-char-hex-seed"

security:
  challenge_timeout: "30s"
  max_failed_attempts: 5
  lockout_duration: "5m"
```

### Environment Variables

All configuration can be set via environment variables:

| Variable | Description |
|----------|-------------|
| `S3CP_LISTEN_ADDR` | Proxy listen address |
| `S3CP_ADMIN_LISTEN_ADDR` | Admin API address |
| `S3CP_BACKEND_ENDPOINT` | S3 backend URL |
| `S3CP_BACKEND_REGION` | S3 region |
| `S3CP_BACKEND_ACCESS_KEY` | Backend access key |
| `S3CP_BACKEND_SECRET_KEY` | Backend secret key |
| `S3CP_BACKEND_PATH_STYLE` | Use path-style URLs |
| `S3CP_BACKEND_INSECURE` | Skip TLS verification |
| `S3CP_CLIENT_ACCESS_KEY` | Client access key |
| `S3CP_CLIENT_SECRET_KEY` | Client secret key |
| `S3CP_ADMIN_TOKEN` | Admin API bearer token |
| `S3CP_ALLOWED_BUCKETS` | Comma-separated allowed buckets |
| `S3CP_MEMKEY_SOCKET` | Memkey Unix socket path |
| `S3CP_MEMKEY_ENDPOINT` | Memkey HTTP endpoint |
| `S3CP_LOG_LEVEL` | Log level (debug, info, warn, error) |

## Bucket Access Control

The `allowed_buckets` configuration restricts which S3 buckets clients can access:

```yaml
allowed_buckets:
  - "pbs-backup-bucket"
  - "pbs-archive-bucket"
```

When configured:
- **ListBuckets** returns only the allowed buckets (no backend call needed)
- **All other operations** return 403 Forbidden for non-allowed buckets
- This avoids needing ListBuckets permission on the backend

If `allowed_buckets` is empty or not set, all buckets are accessible (not recommended for production).

## Key Management

The encryption key is never stored on disk. It's held only in memory by the memkey-server and must be delivered after each server restart.

### Initial Setup (Admin Workstation)

1. **Get the server fingerprint** from server logs after starting memkey-server:
   ```
   journalctl -u memkey-server | grep "SERVER FINGERPRINT"
   ```

2. **Initialize the admin tool** with the verified fingerprint:
   ```bash
   ./memkey-admin init \
     --server https://your-server:7070 \
     --fingerprint "abc123...64-hex-chars..."
   ```

3. **Generate or import the master key**:
   ```bash
   # Generate new key
   ./memkey-admin key generate

   # Or import existing key
   ./memkey-admin key import --file master.key
   ```

4. **Send the key to the server**:
   ```bash
   ./memkey-admin key send
   ```

### After Server Restart

```bash
# Check server status
./memkey-admin status

# Send the key
./memkey-admin key send
```

### Key Security Protocol

The key delivery uses a secure challenge-response protocol:

1. **Challenge Request**: Admin requests a challenge from the server
2. **Server Signs Challenge**: Server signs (challenge || timestamp) with Ed25519
3. **Admin Verifies Identity**: Admin verifies signature against expected fingerprint
4. **Ephemeral Key Exchange**: Admin generates ephemeral X25519 keypair (PFS)
5. **Key Encryption**: Master key encrypted with XChaCha20-Poly1305 using derived shared secret
6. **Secure Delivery**: Encrypted key sent to server
7. **Server Decrypts**: Server derives same shared secret and decrypts

This provides:
- **Server authentication** via Ed25519 signatures
- **Perfect Forward Secrecy** via ephemeral X25519 keys
- **Replay protection** via single-use challenges
- **Man-in-the-middle protection** via fingerprint verification

## Systemd Services

### Start Services

```bash
# Start memkey server first
sudo systemctl enable --now memkey-server

# Then start proxy (after key is loaded)
sudo systemctl enable --now s3-crypt-proxy
```

### Check Status

```bash
sudo systemctl status memkey-server
sudo systemctl status s3-crypt-proxy

# View logs
journalctl -u memkey-server -f
journalctl -u s3-crypt-proxy -f
```

## Updating

Use the update script to update binaries and redeploy the key:

```bash
sudo ./deploy/update.sh
```

Options:
- `--skip-build`: Use pre-built binaries
- `--skip-key`: Don't prompt for key deployment
- `--force`: Don't ask for confirmation

## PBS Configuration

Configure Proxmox Backup Server to use the proxy:

```
# In PBS datastore configuration
s3:
  endpoint: https://proxy-server:8080
  access-key: proxy-client-key
  secret-key: proxy-client-secret
  bucket: your-bucket-name
  path-style: true
```

## API Endpoints

### S3 Proxy (default: :8080)

Supports all PBS-required S3 operations:
- HeadBucket, ListBuckets
- ListObjectsV2
- HeadObject, GetObject, PutObject
- DeleteObject, DeleteObjects
- CopyObject

Special handling:
- `If-None-Match: *` for PBS's upload_no_replace

### Admin API (default: :9090)

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/healthz` | GET | No | Health check |
| `/readyz` | GET | No | Readiness (503 if no key) |
| `/metrics` | GET | No | Prometheus metrics |
| `/` | GET | No | Live dashboard WebUI |
| `/api/v1/key/status` | GET | Bearer | Key status |

### Memkey Server (default: :7070)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/challenge` | GET | Request authentication challenge |
| `/key` | POST | Deliver encrypted master key |
| `/status` | GET | Server status and fingerprint |
| `/health` | GET | Health check |

## Cryptographic Design

### Cipher
- **Algorithm**: XChaCha20-Poly1305 (AEAD)
- **Key Size**: 256 bits
- **Nonce Size**: 192 bits (extended nonce)

### Nonce Generation

Each encryption generates a fresh 16-byte random salt. The nonce is derived:

```
Nonce = HKDF-SHA256(salt || object_key || chunk_index)
```

This makes nonce reuse **cryptographically impossible**.

### Key Hierarchy

```
Master Key (delivered via memkey protocol)
    ├── Object Encryption Key (HKDF)
    ├── Metadata Encryption Key (HKDF)
    └── Key Verification Token (HKDF)
```

### Encrypted Object Format

```
[Header 34B][Salt 16B][MetaLen 4B][Encrypted Metadata][Encrypted Content]
```

Each section includes a Poly1305 authentication tag for tamper detection.

## Security Considerations

**Protected against:**
- Backend storage provider reading data
- Backend storage tampering (detected via Poly1305)
- Replay attacks (unique nonces, single-use challenges)
- Key interception (PFS, server authentication)
- Brute force key delivery (lockout after failed attempts)

**Not protected against:**
- Proxy server compromise (has key in memory)
- Client credential theft
- Traffic analysis (object count/sizes visible)
- Admin workstation compromise

**Best Practices:**
- Verify server fingerprint through out-of-band channel
- Store master key backup securely offline
- Use TLS for all network communication
- Restrict memkey-server to localhost or private network
- Rotate admin workstation key periodically
- Configure `allowed_buckets` to restrict access
- Use Unix socket for proxy-memkey communication (default)

## Prometheus Metrics

Available at `/metrics`:

```
s3_crypt_proxy_requests_total{method, operation, status}
s3_crypt_proxy_bytes_encrypted_total
s3_crypt_proxy_bytes_decrypted_total
s3_crypt_proxy_request_duration_seconds{operation}
s3_crypt_proxy_key_loaded
s3_crypt_proxy_active_requests
s3_crypt_proxy_encryption_errors_total{type}
```

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run benchmarks
go test ./internal/memkey/... -bench=. -benchmem
go test ./internal/crypto/... -bench=. -benchmem
```

## Performance

Benchmarks on AMD Ryzen Threadripper PRO 7995WX:

| Operation | Throughput |
|-----------|------------|
| Encryption | ~1.5 GB/s |
| Decryption | ~2.8 GB/s |
| Challenge Generation | ~9,400/s |
| Key Delivery (full protocol) | ~3,800/s |

## Troubleshooting

### Key not loaded after restart

```bash
# Check memkey-server status
./memkey-admin status

# Send key
./memkey-admin key send
```

### Fingerprint mismatch error

The server identity may have changed. Verify the new fingerprint from server logs and re-initialize:

```bash
# Get new fingerprint from server
journalctl -u memkey-server | grep FINGERPRINT

# Re-initialize admin tool
./memkey-admin init --server https://... --fingerprint "new-fingerprint"
```

### Locked out from memkey-server

Wait for lockout to expire (default 5 minutes) or restart memkey-server.

### Proxy returns 503 Service Unavailable

The encryption key is not loaded. Send it via memkey-admin:

```bash
./memkey-admin key send
```

## Directory Structure

```
s3-crypt-proxy/
├── cmd/
│   ├── s3-crypt-proxy/     # Main proxy binary
│   ├── memkey-server/      # Key storage server
│   └── memkey-admin/       # Admin CLI tool
├── deploy/
│   ├── deploy.sh           # Fresh installation script
│   └── update.sh           # Update script
├── internal/
│   ├── admin/              # Admin API handlers
│   ├── auth/               # Authentication
│   ├── config/             # Configuration loading
│   ├── crypto/             # Encryption/decryption
│   ├── memkey/             # Key management protocol
│   ├── metrics/            # Prometheus metrics
│   ├── proxy/              # S3 proxy handlers
│   ├── s3client/           # Backend S3 client
│   └── testutil/           # Test utilities
└── spec.md                 # Detailed specification
```

## License

MIT License
