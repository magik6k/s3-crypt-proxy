// Package crypto provides encryption primitives for s3-crypt-proxy.
// Uses XChaCha20-Poly1305 with HKDF-derived nonces to prevent nonce reuse.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// MasterKeySize is the required size of the master encryption key (256 bits)
	MasterKeySize = 32

	// SaltSize is the size of the random salt used for nonce derivation
	SaltSize = 16

	// NonceSize is the XChaCha20-Poly1305 nonce size (192 bits)
	NonceSize = chacha20poly1305.NonceSizeX

	// TagSize is the Poly1305 authentication tag size
	TagSize = chacha20poly1305.Overhead

	// DefaultChunkSize is the default encryption chunk size (4MB)
	DefaultChunkSize = 4 * 1024 * 1024

	// MaxChunkSize is the maximum allowed chunk size (64MB)
	MaxChunkSize = 64 * 1024 * 1024

	// HeaderMagic identifies encrypted objects
	HeaderMagic = "SCPX"

	// HeaderVersion is the current format version
	HeaderVersion = uint16(1)

	// HeaderSize is the fixed header size
	HeaderSize = 34

	// EncryptedMetadataLengthSize is the size of the metadata length field
	EncryptedMetadataLengthSize = 4
)

// HKDF info strings for key derivation
const (
	infoObjectEncryption   = "s3-crypt-proxy-object-v1"
	infoMetadataEncryption = "s3-crypt-proxy-metadata-v1"
	infoKeyVerification    = "s3-crypt-proxy-verify-v1"
	infoNonceDerivation    = "s3-crypt-proxy-nonce-v1"
)

var (
	// ErrKeyNotLoaded indicates no master key has been loaded
	ErrKeyNotLoaded = errors.New("master key not loaded")

	// ErrInvalidKeySize indicates the provided key is the wrong size
	ErrInvalidKeySize = errors.New("invalid key size: must be 32 bytes")

	// ErrInvalidHeader indicates the encrypted object has an invalid header
	ErrInvalidHeader = errors.New("invalid encrypted object header")

	// ErrAuthenticationFailed indicates the ciphertext authentication failed
	ErrAuthenticationFailed = errors.New("authentication failed: data may be tampered")

	// ErrUnsupportedVersion indicates the encrypted object uses an unsupported version
	ErrUnsupportedVersion = errors.New("unsupported encryption format version")
)

// KeyManager handles the master encryption key lifecycle.
// It is safe for concurrent use.
type KeyManager struct {
	mu          sync.RWMutex
	masterKey   []byte
	objectKey   []byte
	metadataKey []byte
	verifyToken []byte
	keyID       string
	loadedAt    time.Time
	loaded      atomic.Bool
}

// NewKeyManager creates a new key manager instance.
func NewKeyManager() *KeyManager {
	return &KeyManager{}
}

// LoadKey loads a master key and derives all sub-keys.
// The key must be exactly 32 bytes (256 bits).
func (km *KeyManager) LoadKey(masterKey []byte) error {
	if len(masterKey) != MasterKeySize {
		return ErrInvalidKeySize
	}

	km.mu.Lock()
	defer km.mu.Unlock()

	// Derive sub-keys using HKDF
	objectKey, err := deriveKey(masterKey, nil, infoObjectEncryption, MasterKeySize)
	if err != nil {
		return fmt.Errorf("failed to derive object key: %w", err)
	}

	metadataKey, err := deriveKey(masterKey, nil, infoMetadataEncryption, MasterKeySize)
	if err != nil {
		return fmt.Errorf("failed to derive metadata key: %w", err)
	}

	verifyToken, err := deriveKey(masterKey, nil, infoKeyVerification, 32)
	if err != nil {
		return fmt.Errorf("failed to derive verification token: %w", err)
	}

	// Store keys
	km.masterKey = make([]byte, MasterKeySize)
	copy(km.masterKey, masterKey)
	km.objectKey = objectKey
	km.metadataKey = metadataKey
	km.verifyToken = verifyToken

	// Generate key ID (first 8 chars of SHA256)
	hash := sha256.Sum256(masterKey)
	km.keyID = fmt.Sprintf("%x", hash[:4])

	km.loadedAt = time.Now()
	km.loaded.Store(true)

	return nil
}

// ClearKey securely clears the master key from memory.
func (km *KeyManager) ClearKey() {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Zero out all key material
	if km.masterKey != nil {
		for i := range km.masterKey {
			km.masterKey[i] = 0
		}
		km.masterKey = nil
	}
	if km.objectKey != nil {
		for i := range km.objectKey {
			km.objectKey[i] = 0
		}
		km.objectKey = nil
	}
	if km.metadataKey != nil {
		for i := range km.metadataKey {
			km.metadataKey[i] = 0
		}
		km.metadataKey = nil
	}
	if km.verifyToken != nil {
		for i := range km.verifyToken {
			km.verifyToken[i] = 0
		}
		km.verifyToken = nil
	}

	km.keyID = ""
	km.loadedAt = time.Time{}
	km.loaded.Store(false)
}

// IsLoaded returns true if a master key is currently loaded.
func (km *KeyManager) IsLoaded() bool {
	return km.loaded.Load()
}

// KeyID returns the short identifier of the loaded key.
func (km *KeyManager) KeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// LoadedAt returns when the key was loaded.
func (km *KeyManager) LoadedAt() time.Time {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.loadedAt
}

// VerificationToken returns the key verification token.
// Used to verify the correct key is being used for a bucket.
func (km *KeyManager) VerificationToken() ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if !km.loaded.Load() {
		return nil, ErrKeyNotLoaded
	}

	token := make([]byte, len(km.verifyToken))
	copy(token, km.verifyToken)
	return token, nil
}

// Encryptor provides encryption operations.
type Encryptor struct {
	km        *KeyManager
	chunkSize int
}

// NewEncryptor creates a new encryptor with the given key manager.
func NewEncryptor(km *KeyManager, chunkSize int) *Encryptor {
	if chunkSize <= 0 || chunkSize > MaxChunkSize {
		chunkSize = DefaultChunkSize
	}
	return &Encryptor{
		km:        km,
		chunkSize: chunkSize,
	}
}

// Header represents the encrypted object header.
type Header struct {
	Magic    [4]byte
	Version  uint16
	Flags    uint32
	Reserved [8]byte
}

// ObjectMetadata contains the encrypted object's original metadata.
type ObjectMetadata struct {
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	ETag          string            `json:"etag,omitempty"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

// EncryptedObject represents a fully encrypted object ready for storage.
type EncryptedObject struct {
	Header            Header
	Salt              []byte
	EncryptedMetadata []byte
	EncryptedContent  []byte
}

// Encrypt encrypts data for the given object key.
// Returns the encrypted data with header, salt, metadata, and content.
func (e *Encryptor) Encrypt(objectKey string, plaintext []byte, metadata *ObjectMetadata) ([]byte, error) {
	if !e.km.IsLoaded() {
		return nil, ErrKeyNotLoaded
	}

	e.km.mu.RLock()
	objKey := e.km.objectKey
	metaKey := e.km.metadataKey
	e.km.mu.RUnlock()

	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive nonces
	metaNonce, err := deriveNonce(salt, objectKey, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive metadata nonce: %w", err)
	}

	contentNonce, err := deriveNonce(salt, objectKey, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to derive content nonce: %w", err)
	}

	// Encrypt metadata
	metadataJSON, err := encodeMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encode metadata: %w", err)
	}

	metaCipher, err := chacha20poly1305.NewX(metaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata cipher: %w", err)
	}

	// AAD includes the header for binding
	header := Header{
		Version: HeaderVersion,
	}
	copy(header.Magic[:], HeaderMagic)

	headerBytes := encodeHeader(&header)
	encryptedMeta := metaCipher.Seal(nil, metaNonce, metadataJSON, headerBytes)

	// Encrypt content
	contentCipher, err := chacha20poly1305.NewX(objKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create content cipher: %w", err)
	}

	// AAD for content includes salt + chunk index (1) for consistency with streaming
	chunkIndex := uint64(1)
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, chunkIndex)
	aad = append(salt, aad...)
	encryptedContent := contentCipher.Seal(nil, contentNonce, plaintext, aad)

	// Assemble final output
	metaLenBytes := make([]byte, EncryptedMetadataLengthSize)
	binary.BigEndian.PutUint32(metaLenBytes, uint32(len(encryptedMeta)))

	totalSize := HeaderSize + SaltSize + EncryptedMetadataLengthSize + len(encryptedMeta) + len(encryptedContent)
	output := make([]byte, 0, totalSize)
	output = append(output, headerBytes...)
	output = append(output, salt...)
	output = append(output, metaLenBytes...)
	output = append(output, encryptedMeta...)
	output = append(output, encryptedContent...)

	return output, nil
}

// Decrypt decrypts an encrypted object.
// Returns the plaintext and original metadata.
func (e *Encryptor) Decrypt(objectKey string, ciphertext []byte) ([]byte, *ObjectMetadata, error) {
	if !e.km.IsLoaded() {
		return nil, nil, ErrKeyNotLoaded
	}

	if len(ciphertext) < HeaderSize+SaltSize+EncryptedMetadataLengthSize {
		return nil, nil, ErrInvalidHeader
	}

	e.km.mu.RLock()
	objKey := e.km.objectKey
	metaKey := e.km.metadataKey
	e.km.mu.RUnlock()

	// Parse header
	headerBytes := ciphertext[:HeaderSize]
	header, err := decodeHeader(headerBytes)
	if err != nil {
		return nil, nil, err
	}

	if string(header.Magic[:]) != HeaderMagic {
		return nil, nil, ErrInvalidHeader
	}

	if header.Version != HeaderVersion {
		return nil, nil, ErrUnsupportedVersion
	}

	// Extract salt
	offset := HeaderSize
	salt := ciphertext[offset : offset+SaltSize]
	offset += SaltSize

	// Extract encrypted metadata length
	metaLen := binary.BigEndian.Uint32(ciphertext[offset : offset+EncryptedMetadataLengthSize])
	offset += EncryptedMetadataLengthSize

	if int(metaLen) > len(ciphertext)-offset {
		return nil, nil, ErrInvalidHeader
	}

	// Extract encrypted metadata and content
	encryptedMeta := ciphertext[offset : offset+int(metaLen)]
	offset += int(metaLen)
	encryptedContent := ciphertext[offset:]

	// Derive nonces
	metaNonce, err := deriveNonce(salt, objectKey, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive metadata nonce: %w", err)
	}

	contentNonce, err := deriveNonce(salt, objectKey, 1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive content nonce: %w", err)
	}

	// Decrypt metadata
	metaCipher, err := chacha20poly1305.NewX(metaKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create metadata cipher: %w", err)
	}

	metadataJSON, err := metaCipher.Open(nil, metaNonce, encryptedMeta, headerBytes)
	if err != nil {
		return nil, nil, ErrAuthenticationFailed
	}

	metadata, err := decodeMetadata(metadataJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	// Decrypt content
	contentCipher, err := chacha20poly1305.NewX(objKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create content cipher: %w", err)
	}

	// AAD for content includes salt + chunk index (1) for consistency with streaming
	chunkIndex := uint64(1)
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, chunkIndex)
	aad = append(salt, aad...)

	plaintext, err := contentCipher.Open(nil, contentNonce, encryptedContent, aad)
	if err != nil {
		return nil, nil, ErrAuthenticationFailed
	}

	return plaintext, metadata, nil
}

// CalculateEncryptedSize returns the encrypted size for a given plaintext size.
func CalculateEncryptedSize(plaintextSize int64, metadataSize int) int64 {
	// Header + Salt + MetaLen + EncryptedMeta (with tag) + EncryptedContent (with tag)
	return int64(HeaderSize) +
		int64(SaltSize) +
		int64(EncryptedMetadataLengthSize) +
		int64(metadataSize) + int64(TagSize) +
		plaintextSize + int64(TagSize)
}

// CalculatePlaintextSize returns the original size from encrypted size and metadata size.
func CalculatePlaintextSize(encryptedSize int64, metadataSize int) int64 {
	overhead := int64(HeaderSize) +
		int64(SaltSize) +
		int64(EncryptedMetadataLengthSize) +
		int64(metadataSize) + int64(TagSize) +
		int64(TagSize)
	return encryptedSize - overhead
}

// deriveKey derives a key using HKDF-SHA256.
func deriveKey(secret, salt []byte, info string, length int) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, salt, []byte(info))
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// deriveNonce derives a unique nonce using HKDF.
func deriveNonce(salt []byte, objectKey string, index uint64) ([]byte, error) {
	// Combine salt, object key, and index for uniqueness
	indexBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(indexBytes, index)

	info := append([]byte(infoNonceDerivation), []byte(objectKey)...)
	info = append(info, indexBytes...)

	reader := hkdf.New(sha256.New, salt, nil, info)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// encodeHeader encodes the header to bytes.
func encodeHeader(h *Header) []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:4], h.Magic[:])
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint32(buf[6:10], h.Flags)
	copy(buf[10:18], h.Reserved[:])
	// Remaining 16 bytes are reserved/padding
	return buf
}

// decodeHeader decodes the header from bytes.
func decodeHeader(buf []byte) (*Header, error) {
	if len(buf) < HeaderSize {
		return nil, ErrInvalidHeader
	}

	h := &Header{
		Version: binary.BigEndian.Uint16(buf[4:6]),
		Flags:   binary.BigEndian.Uint32(buf[6:10]),
	}
	copy(h.Magic[:], buf[0:4])
	copy(h.Reserved[:], buf[10:18])

	return h, nil
}
