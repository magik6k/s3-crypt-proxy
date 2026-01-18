package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/s3-crypt-proxy/internal/crypto"
	"github.com/s3-crypt-proxy/internal/s3client"
)

const (
	// StateFileName is the name of the proxy state file stored in each bucket
	StateFileName = "_objcryptproxy___.json"
)

// BucketState holds the encrypted proxy state for a bucket.
type BucketState struct {
	Version              int            `json:"version"`
	CreatedAt            time.Time      `json:"created_at"`
	KeyVerificationToken string         `json:"key_verification_token"`
	BucketID             string         `json:"bucket_id"`
	Settings             BucketSettings `json:"settings"`
}

// BucketSettings holds bucket-specific encryption settings.
type BucketSettings struct {
	ChunkSize   int    `json:"chunk_size"`
	Compression string `json:"compression"`
}

// StateManager manages the encrypted proxy state files.
type StateManager struct {
	backend   *s3client.Client
	km        *crypto.KeyManager
	encryptor *crypto.Encryptor
}

// NewStateManager creates a new state manager.
func NewStateManager(backend *s3client.Client, km *crypto.KeyManager, chunkSize int) *StateManager {
	return &StateManager{
		backend:   backend,
		km:        km,
		encryptor: crypto.NewEncryptor(km, chunkSize),
	}
}

// EnsureInitialized ensures the bucket has been initialized with a state file.
// If the state file exists, it verifies the key is correct.
// If not, it creates a new state file.
func (sm *StateManager) EnsureInitialized(ctx context.Context, bucket string, chunkSize int) error {
	// Try to read existing state
	state, err := sm.ReadState(ctx, bucket)
	if err != nil {
		return fmt.Errorf("failed to read state: %w", err)
	}

	if state != nil {
		// Verify key matches
		verifyToken, err := sm.km.VerificationToken()
		if err != nil {
			return err
		}

		if state.KeyVerificationToken != string(verifyToken) {
			return fmt.Errorf("key verification failed: wrong encryption key for this bucket")
		}

		return nil
	}

	// Create new state
	verifyToken, err := sm.km.VerificationToken()
	if err != nil {
		return err
	}

	newState := &BucketState{
		Version:              1,
		CreatedAt:            time.Now(),
		KeyVerificationToken: string(verifyToken),
		BucketID:             generateBucketID(),
		Settings: BucketSettings{
			ChunkSize:   chunkSize,
			Compression: "none",
		},
	}

	if err := sm.WriteState(ctx, bucket, newState); err != nil {
		return fmt.Errorf("failed to write state: %w", err)
	}

	return nil
}

// ReadState reads and decrypts the bucket state file.
func (sm *StateManager) ReadState(ctx context.Context, bucket string) (*BucketState, error) {
	output, err := sm.backend.GetObject(ctx, bucket, StateFileName)
	if err != nil {
		return nil, err
	}

	if output == nil {
		// State file doesn't exist yet
		return nil, nil
	}

	defer output.Body.Close()

	// Read encrypted state
	encryptedData, err := readAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	// Decrypt
	plaintext, _, err := sm.encryptor.Decrypt(StateFileName, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt state file: %w", err)
	}

	// Parse JSON
	var state BucketState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return nil, fmt.Errorf("failed to parse state file: %w", err)
	}

	return &state, nil
}

// WriteState encrypts and writes the bucket state file.
func (sm *StateManager) WriteState(ctx context.Context, bucket string, state *BucketState) error {
	// Serialize to JSON
	plaintext, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize state: %w", err)
	}

	// Encrypt
	metadata := &crypto.ObjectMetadata{
		ContentType:   "application/json",
		ContentLength: int64(len(plaintext)),
	}

	encrypted, err := sm.encryptor.Encrypt(StateFileName, plaintext, metadata)
	if err != nil {
		return fmt.Errorf("failed to encrypt state: %w", err)
	}

	// Write to backend
	input := &s3client.PutObjectInput{
		Bucket:        bucket,
		Key:           StateFileName,
		Body:          bytes.NewReader(encrypted),
		ContentLength: int64(len(encrypted)),
		ContentType:   "application/octet-stream",
	}

	_, err = sm.backend.PutObject(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	return nil
}

// VerifyKey checks if the current key matches the bucket's state file.
func (sm *StateManager) VerifyKey(ctx context.Context, bucket string) error {
	state, err := sm.ReadState(ctx, bucket)
	if err != nil {
		return err
	}

	if state == nil {
		// No state file - bucket not initialized
		return nil
	}

	verifyToken, err := sm.km.VerificationToken()
	if err != nil {
		return err
	}

	if state.KeyVerificationToken != string(verifyToken) {
		return fmt.Errorf("key verification failed")
	}

	return nil
}

func generateBucketID() string {
	// Generate a simple unique ID
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.(interface{ Read([]byte) (int, error) }))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
