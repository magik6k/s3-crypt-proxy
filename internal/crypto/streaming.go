package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// StreamingEncryptor provides streaming encryption for large objects.
// Each chunk is independently encrypted with its own derived nonce.
type StreamingEncryptor struct {
	km         *KeyManager
	chunkSize  int
	objectKey  string
	salt       []byte
	cipher     cipher.AEAD
	chunkIndex uint64
	header     []byte
	metadata   []byte
	headerSent bool
}

// NewStreamingEncryptor creates a streaming encryptor for the given object.
func NewStreamingEncryptor(km *KeyManager, objectKey string, metadata *ObjectMetadata, chunkSize int) (*StreamingEncryptor, error) {
	if !km.IsLoaded() {
		return nil, ErrKeyNotLoaded
	}

	if chunkSize <= 0 || chunkSize > MaxChunkSize {
		chunkSize = DefaultChunkSize
	}

	km.mu.RLock()
	objKey := km.objectKey
	metaKey := km.metadataKey
	km.mu.RUnlock()

	// Generate random salt
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create ciphers
	contentCipher, err := chacha20poly1305.NewX(objKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create content cipher: %w", err)
	}

	metaCipher, err := chacha20poly1305.NewX(metaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata cipher: %w", err)
	}

	// Build header
	header := Header{
		Version: HeaderVersion,
	}
	copy(header.Magic[:], HeaderMagic)
	headerBytes := encodeHeader(&header)

	// Encrypt metadata
	metadataJSON, err := encodeMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to encode metadata: %w", err)
	}

	metaNonce, err := deriveNonce(salt, objectKey, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to derive metadata nonce: %w", err)
	}

	encryptedMeta := metaCipher.Seal(nil, metaNonce, metadataJSON, headerBytes)

	// Build complete header section
	metaLenBytes := make([]byte, EncryptedMetadataLengthSize)
	binary.BigEndian.PutUint32(metaLenBytes, uint32(len(encryptedMeta)))

	fullHeader := make([]byte, 0, HeaderSize+SaltSize+EncryptedMetadataLengthSize+len(encryptedMeta))
	fullHeader = append(fullHeader, headerBytes...)
	fullHeader = append(fullHeader, salt...)
	fullHeader = append(fullHeader, metaLenBytes...)
	fullHeader = append(fullHeader, encryptedMeta...)

	return &StreamingEncryptor{
		km:         km,
		chunkSize:  chunkSize,
		objectKey:  objectKey,
		salt:       salt,
		cipher:     contentCipher,
		chunkIndex: 1, // 0 is used for metadata
		header:     fullHeader,
		metadata:   encryptedMeta,
		headerSent: false,
	}, nil
}

// HeaderSize returns the size of the header section (includes encrypted metadata).
func (se *StreamingEncryptor) HeaderSize() int {
	return len(se.header)
}

// EncryptChunk encrypts a single chunk of data.
// Returns the encrypted chunk with authentication tag.
func (se *StreamingEncryptor) EncryptChunk(plaintext []byte) ([]byte, error) {
	nonce, err := deriveNonce(se.salt, se.objectKey, se.chunkIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive chunk nonce: %w", err)
	}

	// AAD includes chunk index for ordering protection
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, se.chunkIndex)
	aad = append(se.salt, aad...)

	ciphertext := se.cipher.Seal(nil, nonce, plaintext, aad)
	se.chunkIndex++

	return ciphertext, nil
}

// GetHeader returns the full header section to be written first.
func (se *StreamingEncryptor) GetHeader() []byte {
	se.headerSent = true
	return se.header
}

// StreamingDecryptor provides streaming decryption for large objects.
type StreamingDecryptor struct {
	km         *KeyManager
	objectKey  string
	salt       []byte
	cipher     cipher.AEAD
	chunkIndex uint64
	metadata   *ObjectMetadata
	chunkSize  int
}

// NewStreamingDecryptor creates a streaming decryptor.
// The header section must be read first using ReadHeader.
func NewStreamingDecryptor(km *KeyManager, objectKey string, chunkSize int) (*StreamingDecryptor, error) {
	if !km.IsLoaded() {
		return nil, ErrKeyNotLoaded
	}

	if chunkSize <= 0 || chunkSize > MaxChunkSize {
		chunkSize = DefaultChunkSize
	}

	return &StreamingDecryptor{
		km:         km,
		objectKey:  objectKey,
		chunkIndex: 1, // 0 is for metadata
		chunkSize:  chunkSize,
	}, nil
}

// ReadHeader reads and decrypts the header section.
// Returns the metadata and the number of bytes consumed from the reader.
func (sd *StreamingDecryptor) ReadHeader(r io.Reader) (*ObjectMetadata, int, error) {
	sd.km.mu.RLock()
	objKey := sd.km.objectKey
	metaKey := sd.km.metadataKey
	sd.km.mu.RUnlock()

	// Read fixed header
	headerBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, 0, fmt.Errorf("failed to read header: %w", err)
	}

	header, err := decodeHeader(headerBuf)
	if err != nil {
		return nil, 0, err
	}

	if string(header.Magic[:]) != HeaderMagic {
		return nil, 0, ErrInvalidHeader
	}

	if header.Version != HeaderVersion {
		return nil, 0, ErrUnsupportedVersion
	}

	// Read salt
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, 0, fmt.Errorf("failed to read salt: %w", err)
	}
	sd.salt = salt

	// Read metadata length
	metaLenBuf := make([]byte, EncryptedMetadataLengthSize)
	if _, err := io.ReadFull(r, metaLenBuf); err != nil {
		return nil, 0, fmt.Errorf("failed to read metadata length: %w", err)
	}
	metaLen := binary.BigEndian.Uint32(metaLenBuf)

	// Sanity check metadata length (max 1MB)
	if metaLen > 1024*1024 {
		return nil, 0, fmt.Errorf("metadata too large: %d bytes", metaLen)
	}

	// Read encrypted metadata
	encryptedMeta := make([]byte, metaLen)
	if _, err := io.ReadFull(r, encryptedMeta); err != nil {
		return nil, 0, fmt.Errorf("failed to read encrypted metadata: %w", err)
	}

	// Create metadata cipher and decrypt
	metaCipher, err := chacha20poly1305.NewX(metaKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create metadata cipher: %w", err)
	}

	metaNonce, err := deriveNonce(salt, sd.objectKey, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to derive metadata nonce: %w", err)
	}

	metadataJSON, err := metaCipher.Open(nil, metaNonce, encryptedMeta, headerBuf)
	if err != nil {
		return nil, 0, ErrAuthenticationFailed
	}

	metadata, err := decodeMetadata(metadataJSON)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decode metadata: %w", err)
	}
	sd.metadata = metadata

	// Create content cipher
	sd.cipher, err = chacha20poly1305.NewX(objKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create content cipher: %w", err)
	}

	bytesRead := HeaderSize + SaltSize + EncryptedMetadataLengthSize + int(metaLen)
	return metadata, bytesRead, nil
}

// DecryptChunk decrypts a single encrypted chunk.
func (sd *StreamingDecryptor) DecryptChunk(ciphertext []byte) ([]byte, error) {
	if sd.cipher == nil {
		return nil, fmt.Errorf("header not read yet")
	}

	nonce, err := deriveNonce(sd.salt, sd.objectKey, sd.chunkIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive chunk nonce: %w", err)
	}

	// AAD includes chunk index for ordering protection
	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, sd.chunkIndex)
	aad = append(sd.salt, aad...)

	plaintext, err := sd.cipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	sd.chunkIndex++
	return plaintext, nil
}

// Metadata returns the decrypted metadata (after ReadHeader is called).
func (sd *StreamingDecryptor) Metadata() *ObjectMetadata {
	return sd.metadata
}

// EncryptReader wraps a reader and encrypts its contents.
type EncryptReader struct {
	source    io.Reader
	encryptor *StreamingEncryptor
	buffer    bytes.Buffer
	chunkBuf  []byte
	done      bool
	err       error
}

// NewEncryptReader creates a reader that encrypts data on the fly.
func NewEncryptReader(source io.Reader, km *KeyManager, objectKey string, metadata *ObjectMetadata, chunkSize int) (*EncryptReader, error) {
	enc, err := NewStreamingEncryptor(km, objectKey, metadata, chunkSize)
	if err != nil {
		return nil, err
	}

	er := &EncryptReader{
		source:    source,
		encryptor: enc,
		chunkBuf:  make([]byte, chunkSize),
	}

	// Pre-fill buffer with header
	er.buffer.Write(enc.GetHeader())

	return er, nil
}

// Read implements io.Reader.
func (er *EncryptReader) Read(p []byte) (int, error) {
	if er.err != nil {
		return 0, er.err
	}

	// Return buffered data first
	if er.buffer.Len() > 0 {
		return er.buffer.Read(p)
	}

	if er.done {
		return 0, io.EOF
	}

	// Read next chunk from source
	n, err := io.ReadFull(er.source, er.chunkBuf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		er.done = true
		if n == 0 {
			return 0, io.EOF
		}
	} else if err != nil {
		er.err = err
		return 0, err
	}

	// Encrypt the chunk
	encrypted, err := er.encryptor.EncryptChunk(er.chunkBuf[:n])
	if err != nil {
		er.err = err
		return 0, err
	}

	er.buffer.Write(encrypted)
	return er.buffer.Read(p)
}

// DecryptReader wraps a reader and decrypts its contents.
type DecryptReader struct {
	source    io.Reader
	decryptor *StreamingDecryptor
	buffer    bytes.Buffer
	chunkBuf  []byte
	chunkSize int
	done      bool
	err       error
	metadata  *ObjectMetadata
}

// NewDecryptReader creates a reader that decrypts data on the fly.
// It reads the header first to get metadata.
func NewDecryptReader(source io.Reader, km *KeyManager, objectKey string, chunkSize int) (*DecryptReader, error) {
	dec, err := NewStreamingDecryptor(km, objectKey, chunkSize)
	if err != nil {
		return nil, err
	}

	// Read header
	metadata, _, err := dec.ReadHeader(source)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Encrypted chunk size includes the tag
	encryptedChunkSize := chunkSize + TagSize

	return &DecryptReader{
		source:    source,
		decryptor: dec,
		chunkBuf:  make([]byte, encryptedChunkSize),
		chunkSize: chunkSize,
		metadata:  metadata,
	}, nil
}

// Read implements io.Reader.
func (dr *DecryptReader) Read(p []byte) (int, error) {
	if dr.err != nil {
		return 0, dr.err
	}

	// Return buffered data first
	if dr.buffer.Len() > 0 {
		return dr.buffer.Read(p)
	}

	if dr.done {
		return 0, io.EOF
	}

	// Read next encrypted chunk
	encryptedChunkSize := dr.chunkSize + TagSize
	n, err := io.ReadFull(dr.source, dr.chunkBuf[:encryptedChunkSize])
	if err == io.EOF {
		dr.done = true
		return 0, io.EOF
	} else if err == io.ErrUnexpectedEOF {
		// Last chunk may be smaller
		dr.done = true
		if n == 0 {
			return 0, io.EOF
		}
	} else if err != nil {
		dr.err = err
		return 0, err
	}

	// Decrypt the chunk
	plaintext, err := dr.decryptor.DecryptChunk(dr.chunkBuf[:n])
	if err != nil {
		dr.err = err
		return 0, err
	}

	dr.buffer.Write(plaintext)
	return dr.buffer.Read(p)
}

// Metadata returns the decrypted object metadata.
func (dr *DecryptReader) Metadata() *ObjectMetadata {
	return dr.metadata
}
