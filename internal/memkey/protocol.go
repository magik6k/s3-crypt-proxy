// Package memkey implements a secure challenge-response protocol for delivering
// encryption keys to the s3-crypt-proxy server.
//
// Protocol Overview:
// 1. Server generates Ed25519 identity keypair on first start (persisted)
// 2. Server logs its public key fingerprint on every startup
// 3. Admin tool has server's expected fingerprint in local config
// 4. Key delivery uses X25519 ephemeral keys for Perfect Forward Secrecy
//
// Protocol Flow:
// 1. Admin requests challenge: GET /challenge
// 2. Server returns: {challenge, server_pubkey, timestamp, signature}
// 3. Admin verifies signature matches expected server fingerprint
// 4. Admin generates ephemeral X25519 keypair
// 5. Admin derives shared secret: ECDH(ephemeral_priv, server_x25519_pub)
// 6. Admin encrypts key: XChaCha20-Poly1305(shared_secret, nonce, master_key)
// 7. Admin sends: POST /key {challenge, ephemeral_pubkey, encrypted_key, nonce}
// 8. Server derives same shared secret and decrypts
// 9. Server verifies and stores key in memory
package memkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// ChallengeSize is the size of the random challenge in bytes
	ChallengeSize = 32

	// ChallengeTimeout is how long a challenge remains valid
	ChallengeTimeout = 30 * time.Second

	// NonceSize for XChaCha20-Poly1305
	NonceSize = 24

	// MasterKeySize is the expected size of the master encryption key
	MasterKeySize = 32

	// MaxFailedAttempts before lockout
	MaxFailedAttempts = 5

	// LockoutDuration after max failed attempts
	LockoutDuration = 5 * time.Minute
)

var (
	ErrInvalidChallenge    = errors.New("invalid or expired challenge")
	ErrInvalidSignature    = errors.New("server signature verification failed")
	ErrFingerprintMismatch = errors.New("server fingerprint does not match expected")
	ErrDecryptionFailed    = errors.New("failed to decrypt master key")
	ErrInvalidKeySize      = errors.New("invalid master key size")
	ErrKeyAlreadyLoaded    = errors.New("master key already loaded")
	ErrLockedOut           = errors.New("too many failed attempts, try again later")
	ErrNoChallenge         = errors.New("no active challenge")
)

// ChallengeRequest is sent by the admin to request a challenge
type ChallengeRequest struct {
	// Empty for now, could add client version info
}

// ChallengeResponse contains the server's challenge
type ChallengeResponse struct {
	// Challenge is a random value the client must include in key delivery
	Challenge string `json:"challenge"`

	// ServerPubKey is the server's Ed25519 public key (base64)
	ServerPubKey string `json:"server_pubkey"`

	// ServerX25519PubKey is the server's X25519 public key for key exchange (base64)
	ServerX25519PubKey string `json:"server_x25519_pubkey"`

	// Timestamp when challenge was created (Unix seconds)
	Timestamp int64 `json:"timestamp"`

	// Signature over (challenge || timestamp) using server's Ed25519 key
	Signature string `json:"signature"`
}

// KeyDeliveryRequest contains the encrypted master key
type KeyDeliveryRequest struct {
	// Challenge from the ChallengeResponse
	Challenge string `json:"challenge"`

	// EphemeralPubKey is the client's ephemeral X25519 public key (base64)
	EphemeralPubKey string `json:"ephemeral_pubkey"`

	// EncryptedKey is the XChaCha20-Poly1305 encrypted master key (base64)
	EncryptedKey string `json:"encrypted_key"`

	// Nonce used for encryption (base64)
	Nonce string `json:"nonce"`
}

// KeyDeliveryResponse confirms key delivery
type KeyDeliveryResponse struct {
	// Success indicates if the key was accepted
	Success bool `json:"success"`

	// Message provides additional information
	Message string `json:"message"`

	// KeyFingerprint is SHA256 of the loaded key (first 8 bytes, hex)
	// Allows admin to verify correct key was loaded
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

// StatusResponse returns server status
type StatusResponse struct {
	// KeyLoaded indicates if a master key is present
	KeyLoaded bool `json:"key_loaded"`

	// KeyLoadedAt is when the key was loaded (Unix timestamp)
	KeyLoadedAt int64 `json:"key_loaded_at,omitempty"`

	// ServerFingerprint is the server's identity fingerprint
	ServerFingerprint string `json:"server_fingerprint"`

	// Uptime in seconds
	Uptime int64 `json:"uptime"`

	// LockedOut indicates if the server is in lockout mode
	LockedOut bool `json:"locked_out"`

	// LockoutEndsAt is when lockout ends (Unix timestamp)
	LockoutEndsAt int64 `json:"lockout_ends_at,omitempty"`
}

// ServerIdentity holds the server's cryptographic identity
type ServerIdentity struct {
	// Ed25519 keys for signing
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey

	// X25519 keys derived from Ed25519 for key exchange
	X25519Private []byte
	X25519Public  []byte
}

// NewServerIdentity creates a new server identity
func NewServerIdentity() (*ServerIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	return newIdentityFromEd25519(priv, pub)
}

// LoadServerIdentity loads identity from a hex-encoded Ed25519 seed
func LoadServerIdentity(seedHex string) (*ServerIdentity, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fmt.Errorf("invalid seed hex: %w", err)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: expected %d, got %d", ed25519.SeedSize, len(seed))
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return newIdentityFromEd25519(priv, pub)
}

func newIdentityFromEd25519(priv ed25519.PrivateKey, pub ed25519.PublicKey) (*ServerIdentity, error) {
	// Derive X25519 keys from Ed25519
	// The Ed25519 private key seed can be used to derive X25519 private key
	seed := priv.Seed()
	h := sha256.Sum256(seed)
	x25519Priv := h[:]

	// Clamp the private key as per X25519 spec
	x25519Priv[0] &= 248
	x25519Priv[31] &= 127
	x25519Priv[31] |= 64

	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive X25519 public key: %w", err)
	}

	return &ServerIdentity{
		PrivateKey:    priv,
		PublicKey:     pub,
		X25519Private: x25519Priv,
		X25519Public:  x25519Pub,
	}, nil
}

// Fingerprint returns the SHA256 fingerprint of the public key (hex encoded)
func (si *ServerIdentity) Fingerprint() string {
	h := sha256.Sum256(si.PublicKey)
	return hex.EncodeToString(h[:])
}

// ShortFingerprint returns first 16 hex chars for display
func (si *ServerIdentity) ShortFingerprint() string {
	return si.Fingerprint()[:16]
}

// Seed returns the Ed25519 seed for persistence (hex encoded)
func (si *ServerIdentity) Seed() string {
	return hex.EncodeToString(si.PrivateKey.Seed())
}

// Sign signs data with the server's Ed25519 key
func (si *ServerIdentity) Sign(data []byte) []byte {
	return ed25519.Sign(si.PrivateKey, data)
}

// activeChallenge tracks a pending challenge
type activeChallenge struct {
	challenge []byte
	timestamp time.Time
	used      bool
}

// Server implements the memkey server logic
type Server struct {
	mu sync.RWMutex

	identity  *ServerIdentity
	startTime time.Time

	// Active challenges (keyed by challenge hex)
	challenges map[string]*activeChallenge

	// Master key storage
	masterKey    []byte
	keyLoadedAt  time.Time
	keyLoadCount int64

	// Security state
	failedAttempts int
	lockoutUntil   time.Time

	// Configuration
	challengeTimeout  time.Duration
	maxFailedAttempts int
	lockoutDuration   time.Duration
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Identity          *ServerIdentity
	ChallengeTimeout  time.Duration
	MaxFailedAttempts int
	LockoutDuration   time.Duration
}

// NewServer creates a new memkey server
func NewServer(cfg *ServerConfig) *Server {
	if cfg.ChallengeTimeout == 0 {
		cfg.ChallengeTimeout = ChallengeTimeout
	}
	if cfg.MaxFailedAttempts == 0 {
		cfg.MaxFailedAttempts = MaxFailedAttempts
	}
	if cfg.LockoutDuration == 0 {
		cfg.LockoutDuration = LockoutDuration
	}

	return &Server{
		identity:          cfg.Identity,
		startTime:         time.Now(),
		challenges:        make(map[string]*activeChallenge),
		challengeTimeout:  cfg.ChallengeTimeout,
		maxFailedAttempts: cfg.MaxFailedAttempts,
		lockoutDuration:   cfg.LockoutDuration,
	}
}

// GenerateChallenge creates a new challenge for key delivery
func (s *Server) GenerateChallenge() (*ChallengeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check lockout
	if time.Now().Before(s.lockoutUntil) {
		return nil, ErrLockedOut
	}

	// Clean old challenges
	s.cleanExpiredChallenges()

	// Generate challenge
	challenge := make([]byte, ChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	timestamp := time.Now()

	// Create signature over challenge || timestamp
	signData := make([]byte, len(challenge)+8)
	copy(signData, challenge)
	timestampBytes := timestamp.Unix()
	for i := 0; i < 8; i++ {
		signData[len(challenge)+i] = byte(timestampBytes >> (56 - i*8))
	}

	signature := s.identity.Sign(signData)

	// Store challenge
	challengeHex := hex.EncodeToString(challenge)
	s.challenges[challengeHex] = &activeChallenge{
		challenge: challenge,
		timestamp: timestamp,
		used:      false,
	}

	return &ChallengeResponse{
		Challenge:          base64.StdEncoding.EncodeToString(challenge),
		ServerPubKey:       base64.StdEncoding.EncodeToString(s.identity.PublicKey),
		ServerX25519PubKey: base64.StdEncoding.EncodeToString(s.identity.X25519Public),
		Timestamp:          timestamp.Unix(),
		Signature:          base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// DeliverKey processes a key delivery request
func (s *Server) DeliverKey(req *KeyDeliveryRequest) (*KeyDeliveryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check lockout
	if time.Now().Before(s.lockoutUntil) {
		return nil, ErrLockedOut
	}

	// Validate and consume challenge
	challenge, err := base64.StdEncoding.DecodeString(req.Challenge)
	if err != nil {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("invalid challenge encoding: %w", err)
	}

	challengeHex := hex.EncodeToString(challenge)
	ac, exists := s.challenges[challengeHex]
	if !exists {
		s.recordFailedAttempt()
		return nil, ErrInvalidChallenge
	}

	if ac.used {
		s.recordFailedAttempt()
		return nil, ErrInvalidChallenge
	}

	if time.Since(ac.timestamp) > s.challengeTimeout {
		delete(s.challenges, challengeHex)
		s.recordFailedAttempt()
		return nil, ErrInvalidChallenge
	}

	// Mark challenge as used
	ac.used = true
	delete(s.challenges, challengeHex)

	// Decode ephemeral public key
	ephemeralPub, err := base64.StdEncoding.DecodeString(req.EphemeralPubKey)
	if err != nil {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("invalid ephemeral pubkey encoding: %w", err)
	}

	if len(ephemeralPub) != 32 {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("invalid ephemeral pubkey size")
	}

	// Derive shared secret
	sharedSecret, err := curve25519.X25519(s.identity.X25519Private, ephemeralPub)
	if err != nil {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive encryption key using HKDF
	encKey := deriveEncryptionKey(sharedSecret, challenge)

	// Decode nonce and ciphertext
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("invalid nonce encoding: %w", err)
	}

	if len(nonce) != NonceSize {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("invalid nonce size")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.EncryptedKey)
	if err != nil {
		s.recordFailedAttempt()
		return nil, fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	// Decrypt master key
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// AAD includes the challenge for binding
	masterKey, err := aead.Open(nil, nonce, ciphertext, challenge)
	if err != nil {
		s.recordFailedAttempt()
		return nil, ErrDecryptionFailed
	}

	if len(masterKey) != MasterKeySize {
		s.recordFailedAttempt()
		return nil, ErrInvalidKeySize
	}

	// Store the key
	s.masterKey = make([]byte, MasterKeySize)
	copy(s.masterKey, masterKey)
	s.keyLoadedAt = time.Now()
	s.keyLoadCount++
	s.failedAttempts = 0 // Reset on success

	// Calculate key fingerprint
	keyHash := sha256.Sum256(masterKey)
	fingerprint := hex.EncodeToString(keyHash[:8])

	return &KeyDeliveryResponse{
		Success:        true,
		Message:        "Master key loaded successfully",
		KeyFingerprint: fingerprint,
	}, nil
}

// GetKey returns the master key if loaded
func (s *Server) GetKey() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.masterKey == nil {
		return nil, errors.New("key not loaded")
	}

	key := make([]byte, len(s.masterKey))
	copy(key, s.masterKey)
	return key, nil
}

// Status returns the server status
func (s *Server) Status() *StatusResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := &StatusResponse{
		KeyLoaded:         s.masterKey != nil,
		ServerFingerprint: s.identity.Fingerprint(),
		Uptime:            int64(time.Since(s.startTime).Seconds()),
	}

	if s.masterKey != nil {
		resp.KeyLoadedAt = s.keyLoadedAt.Unix()
	}

	if time.Now().Before(s.lockoutUntil) {
		resp.LockedOut = true
		resp.LockoutEndsAt = s.lockoutUntil.Unix()
	}

	return resp
}

// ClearKey removes the master key from memory
func (s *Server) ClearKey() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.masterKey != nil {
		// Securely zero the key
		for i := range s.masterKey {
			s.masterKey[i] = 0
		}
		s.masterKey = nil
	}
}

// Identity returns the server's identity
func (s *Server) Identity() *ServerIdentity {
	return s.identity
}

func (s *Server) recordFailedAttempt() {
	s.failedAttempts++
	if s.failedAttempts >= s.maxFailedAttempts {
		s.lockoutUntil = time.Now().Add(s.lockoutDuration)
		s.failedAttempts = 0
	}
}

func (s *Server) cleanExpiredChallenges() {
	now := time.Now()
	for k, v := range s.challenges {
		if now.Sub(v.timestamp) > s.challengeTimeout {
			delete(s.challenges, k)
		}
	}
}

// Client implements the admin client logic
type Client struct {
	expectedFingerprint string
}

// NewClient creates a new memkey client
func NewClient(expectedFingerprint string) *Client {
	return &Client{
		expectedFingerprint: expectedFingerprint,
	}
}

// VerifyChallenge verifies a challenge response from the server
func (c *Client) VerifyChallenge(resp *ChallengeResponse) error {
	// Decode server public key
	serverPubKey, err := base64.StdEncoding.DecodeString(resp.ServerPubKey)
	if err != nil {
		return fmt.Errorf("invalid server pubkey encoding: %w", err)
	}

	if len(serverPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid server pubkey size")
	}

	// Verify fingerprint
	h := sha256.Sum256(serverPubKey)
	actualFingerprint := hex.EncodeToString(h[:])

	if subtle.ConstantTimeCompare([]byte(actualFingerprint), []byte(c.expectedFingerprint)) != 1 {
		return ErrFingerprintMismatch
	}

	// Verify signature
	challenge, err := base64.StdEncoding.DecodeString(resp.Challenge)
	if err != nil {
		return fmt.Errorf("invalid challenge encoding: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Reconstruct signed data
	signData := make([]byte, len(challenge)+8)
	copy(signData, challenge)
	for i := 0; i < 8; i++ {
		signData[len(challenge)+i] = byte(resp.Timestamp >> (56 - i*8))
	}

	if !ed25519.Verify(serverPubKey, signData, signature) {
		return ErrInvalidSignature
	}

	return nil
}

// PrepareKeyDelivery creates a key delivery request
func (c *Client) PrepareKeyDelivery(challengeResp *ChallengeResponse, masterKey []byte) (*KeyDeliveryRequest, error) {
	if len(masterKey) != MasterKeySize {
		return nil, ErrInvalidKeySize
	}

	// Decode server's X25519 public key
	serverX25519Pub, err := base64.StdEncoding.DecodeString(challengeResp.ServerX25519PubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server X25519 pubkey: %w", err)
	}

	// Generate ephemeral X25519 keypair
	ephemeralPriv := make([]byte, 32)
	if _, err := rand.Read(ephemeralPriv); err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Clamp
	ephemeralPriv[0] &= 248
	ephemeralPriv[31] &= 127
	ephemeralPriv[31] |= 64

	ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ephemeral pubkey: %w", err)
	}

	// Derive shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPriv, serverX25519Pub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Decode challenge for key derivation
	challenge, err := base64.StdEncoding.DecodeString(challengeResp.Challenge)
	if err != nil {
		return nil, fmt.Errorf("invalid challenge: %w", err)
	}

	// Derive encryption key
	encKey := deriveEncryptionKey(sharedSecret, challenge)

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt master key
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// AAD includes challenge for binding
	// #nosec G407 - nonce is randomly generated above, not hardcoded
	ciphertext := aead.Seal(nil, nonce, masterKey, challenge)

	// Zero ephemeral private key
	for i := range ephemeralPriv {
		ephemeralPriv[i] = 0
	}

	return &KeyDeliveryRequest{
		Challenge:       challengeResp.Challenge,
		EphemeralPubKey: base64.StdEncoding.EncodeToString(ephemeralPub),
		EncryptedKey:    base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:           base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// deriveEncryptionKey derives an encryption key from shared secret and challenge
func deriveEncryptionKey(sharedSecret, challenge []byte) []byte {
	// Use HKDF with challenge as salt
	h := hkdf.New(sha256.New, sharedSecret, challenge, []byte("memkey-v1"))
	key := make([]byte, 32)
	_, _ = h.Read(key) // HKDF Read always succeeds for valid output size
	return key
}

// CalculateKeyFingerprint returns the fingerprint of a master key
func CalculateKeyFingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return hex.EncodeToString(h[:8])
}

// MarshalJSON helpers for wire format
func (r *ChallengeResponse) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalChallengeResponse(data []byte) (*ChallengeResponse, error) {
	var r ChallengeResponse
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *KeyDeliveryRequest) Marshal() ([]byte, error) {
	return json.Marshal(r)
}

func UnmarshalKeyDeliveryRequest(data []byte) (*KeyDeliveryRequest, error) {
	var r KeyDeliveryRequest
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
