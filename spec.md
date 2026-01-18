# S3-Crypt-Proxy Specification

## Overview

S3-Crypt-Proxy is a stateless, transparent encryption proxy for S3-compatible storage backends. It is specifically designed to support Proxmox Backup Server (PBS) while providing client-side encryption with authenticated encryption and tamper detection.

## Design Goals

1. **Stateless Operation**: No local persistent state; all metadata stored encrypted in the backend
2. **Strong Cryptography**: Authenticated encryption with impossible nonce reuse
3. **PBS Compatibility**: Full support for all S3 operations required by Proxmox Backup Server
4. **Separation of Concerns**: Client authentication separate from backend credentials
5. **Operational Visibility**: Prometheus metrics and live WebUI for monitoring
6. **Key Security**: Encryption keys held only in memory, injected via secure API

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  PBS Client     │────▶│  S3-Crypt-Proxy      │────▶│  S3 Backend     │
│  (with creds)   │◀────│  (encryption layer)  │◀────│  (AWS/Minio/etc)│
└─────────────────┘     └──────────────────────┘     └─────────────────┘
                               │
                        ┌──────┴──────┐
                        │  Admin API  │
                        │  /api/v1/*  │
                        └─────────────┘
```

## Cryptographic Design

### Cipher Selection

- **Algorithm**: XChaCha20-Poly1305 (AEAD)
- **Key Size**: 256 bits
- **Nonce Size**: 192 bits (24 bytes) - extended nonce for safe random generation
- **Tag Size**: 128 bits (16 bytes)

### Why XChaCha20-Poly1305?

1. **192-bit nonce**: Safe to generate randomly without birthday-bound concerns
   - With 2^96 random nonces, collision probability is ~2^-96 (negligible)
   - Standard ChaCha20's 96-bit nonce has ~2^-32 collision at 2^32 messages
2. **Authenticated**: Poly1305 MAC provides integrity and authenticity
3. **No padding oracle**: Stream cipher, no padding required
4. **Hardware-independent performance**: Fast on all platforms
5. **Misuse resistance**: Extended nonce makes random generation safe

### Nonce Generation Strategy

To make nonce reuse **cryptographically impossible**:

```
Nonce (24 bytes) = HKDF-SHA256(
    IKM = master_key || object_key || version_counter,
    salt = random_salt (stored with ciphertext),
    info = "s3-crypt-proxy-nonce-v1"
)[0:24]
```

For each encryption:
1. Generate 16 bytes of cryptographic random data (salt)
2. Derive nonce using HKDF with: master key, full object path, and a version counter
3. The salt is prepended to ciphertext (not secret, but unique per encryption)

This ensures:
- Same object re-encrypted gets different salt → different nonce
- Different objects with same content get different nonces
- Version counter prevents reuse on rapid re-uploads

### Key Hierarchy

```
Master Key (256-bit, user-provided)
    │
    ├──▶ HKDF(info="object-encryption") ──▶ Object Encryption Key (per-bucket)
    │
    ├──▶ HKDF(info="metadata-encryption") ──▶ Metadata Encryption Key
    │
    └──▶ HKDF(info="key-verification") ──▶ Key Verification Token
```

### Encrypted Object Format

```
┌────────────────────────────────────────────────────────────────┐
│  Header (34 bytes)                                              │
│  ┌─────────────┬──────────────┬───────────────────────────────┐│
│  │ Magic (4B)  │ Version (2B) │ Flags (4B) │ Reserved (8B)    ││
│  │ "SCPX"      │ 0x0001       │            │                  ││
│  └─────────────┴──────────────┴───────────────────────────────┘│
├────────────────────────────────────────────────────────────────┤
│  Salt (16 bytes) - random, used for nonce derivation           │
├────────────────────────────────────────────────────────────────┤
│  Encrypted Metadata Length (4 bytes, big-endian)               │
├────────────────────────────────────────────────────────────────┤
│  Encrypted Metadata (variable)                                  │
│  ┌────────────────────────────────────────────────────────────┐│
│  │ Original Content-Type, Content-Length, ETag, custom headers ││
│  │ Encrypted with XChaCha20-Poly1305 + Poly1305 tag (16B)     ││
│  └────────────────────────────────────────────────────────────┘│
├────────────────────────────────────────────────────────────────┤
│  Encrypted Content                                              │
│  ┌────────────────────────────────────────────────────────────┐│
│  │ Original object data                                        ││
│  │ Encrypted with XChaCha20-Poly1305 + Poly1305 tag (16B)     ││
│  └────────────────────────────────────────────────────────────┘│
└────────────────────────────────────────────────────────────────┘
```

### Content Encryption Details

For objects larger than 64MB, content is encrypted in chunks:

- **Chunk size**: 4MB (configurable, max 64MB)
- Each chunk has its own derived nonce: `HKDF(salt || chunk_index)`
- Allows streaming encryption/decryption
- Each chunk independently authenticated

### Tamper Detection

1. **Per-chunk authentication**: Poly1305 tag on each chunk
2. **Metadata authentication**: Separate tag for metadata block
3. **Header integrity**: Covered by metadata encryption AAD
4. **Key verification**: On startup/key-load, verify against stored token

## Proxy State File

Stored at `_objcryptproxy___.json` in each bucket (encrypted):

```json
{
  "version": 1,
  "created_at": "2024-01-15T10:30:00Z",
  "key_verification_token": "base64-encoded-token",
  "bucket_id": "uuid-v4",
  "settings": {
    "chunk_size": 4194304,
    "compression": "none"
  }
}
```

This file:
- Is encrypted with the metadata key
- Verifies the correct master key is being used
- Stores bucket-specific settings
- Created on first write operation to bucket

## S3 API Support

### Required Operations (PBS Compatibility)

| Operation | Support | Notes |
|-----------|---------|-------|
| HeadBucket | Full | Pass-through with credential translation |
| ListBuckets | Full | Pass-through |
| ListObjectsV2 | Full | Object sizes adjusted for encryption overhead |
| HeadObject | Full | Decrypt metadata, return original headers |
| GetObject | Full | Streaming decryption |
| PutObject | Full | Streaming encryption |
| DeleteObject | Full | Pass-through |
| DeleteObjects | Full | Pass-through |
| CopyObject | Full | Re-encrypt (download + upload) |

### Request Flow

#### PutObject
```
1. Client sends PUT with plaintext body
2. Proxy authenticates client request
3. Generate random salt
4. Derive nonce from salt + object key
5. Encrypt metadata (Content-Type, original size, etc.)
6. Stream-encrypt body in chunks
7. Upload to backend with backend credentials
8. Return success with original ETag (encrypted ETag stored in metadata)
```

#### GetObject
```
1. Client sends GET request
2. Proxy authenticates client request
3. Fetch encrypted object from backend
4. Parse header, extract salt
5. Derive nonce, decrypt metadata
6. Verify Poly1305 tags
7. Stream-decrypt body
8. Return plaintext with original headers
```

## Authentication

### Client Authentication

Clients authenticate to the proxy using AWS Signature V4:
- Access Key ID: Configured in proxy
- Secret Access Key: Configured in proxy
- Completely separate from backend credentials

### Backend Authentication

Proxy authenticates to S3 backend:
- Uses separate access key/secret
- Configured via environment or config file
- Never exposed to clients

### Admin API Authentication

For key management and metrics:
- Bearer token authentication
- Token provided via environment variable
- Rate-limited endpoints

## Admin API Endpoints

### Key Management

```
POST /api/v1/key/load
Content-Type: application/json
Authorization: Bearer <admin-token>

{
  "master_key": "base64-encoded-256-bit-key"
}

Response: 200 OK
{
  "status": "loaded",
  "key_id": "sha256-fingerprint-first-8-chars"
}
```

```
DELETE /api/v1/key
Authorization: Bearer <admin-token>

Response: 200 OK
{
  "status": "cleared"
}
```

```
GET /api/v1/key/status
Authorization: Bearer <admin-token>

Response: 200 OK
{
  "loaded": true,
  "key_id": "abc12345",
  "loaded_at": "2024-01-15T10:30:00Z"
}
```

### Health & Metrics

```
GET /healthz
Response: 200 OK (no auth required)

GET /readyz
Response: 200 OK if key loaded, 503 otherwise

GET /metrics
Response: Prometheus format metrics

GET /api/v1/metrics/live
Response: HTML page with live metrics WebUI
```

## Metrics

### Prometheus Metrics

```
# Counters
s3_crypt_proxy_requests_total{method, operation, status}
s3_crypt_proxy_bytes_encrypted_total
s3_crypt_proxy_bytes_decrypted_total
s3_crypt_proxy_encryption_errors_total{type}
s3_crypt_proxy_auth_failures_total{reason}

# Histograms
s3_crypt_proxy_request_duration_seconds{operation}
s3_crypt_proxy_encryption_duration_seconds{operation}

# Gauges
s3_crypt_proxy_key_loaded
s3_crypt_proxy_active_requests
s3_crypt_proxy_backend_connection_pool_size
```

### Live WebUI

Real-time dashboard showing:
- Request rate (graph)
- Encryption/decryption throughput
- Error rates
- Key status
- Active connections
- Latency percentiles

## Configuration

### Environment Variables

```bash
# Required
S3CP_ADMIN_TOKEN=<admin-api-bearer-token>
S3CP_BACKEND_ENDPOINT=https://s3.amazonaws.com
S3CP_BACKEND_ACCESS_KEY=<backend-access-key>
S3CP_BACKEND_SECRET_KEY=<backend-secret-key>
S3CP_BACKEND_REGION=us-east-1

# Client credentials (what PBS will use)
S3CP_CLIENT_ACCESS_KEY=<client-access-key>
S3CP_CLIENT_SECRET_KEY=<client-secret-key>

# Optional
S3CP_LISTEN_ADDR=:8080
S3CP_ADMIN_LISTEN_ADDR=:8081
S3CP_BACKEND_PATH_STYLE=true
S3CP_CHUNK_SIZE=4194304
S3CP_LOG_LEVEL=info
S3CP_TLS_CERT=
S3CP_TLS_KEY=
```

### Config File (alternative)

```yaml
listen_addr: ":8080"
admin_listen_addr: ":8081"

backend:
  endpoint: "https://s3.amazonaws.com"
  region: "us-east-1"
  access_key: "${S3CP_BACKEND_ACCESS_KEY}"
  secret_key: "${S3CP_BACKEND_SECRET_KEY}"
  path_style: false

client:
  access_key: "${S3CP_CLIENT_ACCESS_KEY}"
  secret_key: "${S3CP_CLIENT_SECRET_KEY}"

encryption:
  chunk_size: 4194304  # 4MB

admin:
  token: "${S3CP_ADMIN_TOKEN}"

tls:
  cert_file: ""
  key_file: ""
```

## Security Considerations

### Threat Model

**Protected against:**
- Backend storage provider reading data
- Backend storage tampering (detected)
- Network eavesdropping (with TLS)
- Replay attacks (unique nonces)
- Key reuse across objects

**Not protected against:**
- Proxy server compromise (has key in memory)
- Client credential theft
- Denial of service
- Traffic analysis (object count, sizes visible with overhead)

### Key Management Best Practices

1. Load key only after proxy starts via admin API
2. Use hardware security module (HSM) for key storage externally
3. Rotate keys periodically (requires re-encryption migration)
4. Monitor key load events
5. Clear key and restart on suspected compromise

### Nonce Reuse Prevention

The design makes nonce reuse **computationally infeasible**:

1. 16-byte random salt per encryption (128 bits of randomness)
2. Salt + object path + version in nonce derivation
3. Even re-uploading identical content to same path → different salt → different nonce
4. Birthday bound at 2^64 encryptions with same key (effectively infinite)

## Error Handling

### Encryption Errors
- Return 500 Internal Server Error
- Log detailed error (not exposed to client)
- Increment error counter

### Decryption/Authentication Errors
- **Tag mismatch**: Return 500, log "integrity check failed"
- **Wrong key**: Return 500, log "decryption failed"
- **Corrupted header**: Return 500, log "invalid encrypted object format"

### Backend Errors
- Pass through status codes
- Add `X-S3CP-Error: backend` header
- Log backend response details

## Implementation Notes

### Streaming Design

Both encryption and decryption are streaming:
- Memory usage bounded by chunk size
- No need to buffer entire object
- Suitable for large PBS backup chunks (up to 4MB typical, can be larger)

### Concurrency

- Thread-safe key storage (sync.RWMutex)
- Connection pooling for backend
- Context-based cancellation
- Graceful shutdown support

### Testing

- Unit tests for crypto primitives
- Integration tests with MinIO
- Fuzz testing for parser robustness
- Benchmark tests for throughput

## Version History

- **v1.0.0**: Initial release with PBS support
