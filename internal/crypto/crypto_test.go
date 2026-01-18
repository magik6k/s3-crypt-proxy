package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestKeyManager(t *testing.T) {
	km := NewKeyManager()

	// Test initial state
	if km.IsLoaded() {
		t.Error("key should not be loaded initially")
	}

	// Test loading invalid key size
	if err := km.LoadKey([]byte("short")); err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}

	// Generate valid key
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// Load key
	if err := km.LoadKey(key); err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	if !km.IsLoaded() {
		t.Error("key should be loaded")
	}

	keyID := km.KeyID()
	if keyID == "" {
		t.Error("key ID should not be empty")
	}

	// Get verification token
	token, err := km.VerificationToken()
	if err != nil {
		t.Fatalf("failed to get verification token: %v", err)
	}
	if len(token) != 32 {
		t.Errorf("expected 32-byte token, got %d bytes", len(token))
	}

	// Clear key
	km.ClearKey()

	if km.IsLoaded() {
		t.Error("key should not be loaded after clear")
	}

	if _, err := km.VerificationToken(); err != ErrKeyNotLoaded {
		t.Errorf("expected ErrKeyNotLoaded, got %v", err)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	km := NewKeyManager()

	// Generate and load key
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := km.LoadKey(key); err != nil {
		t.Fatal(err)
	}

	enc := NewEncryptor(km, DefaultChunkSize)

	// Test data
	plaintext := []byte("Hello, World! This is a test message for encryption.")
	objectKey := "test/object/key"
	metadata := &ObjectMetadata{
		ContentType:   "text/plain",
		ContentLength: int64(len(plaintext)),
		ETag:          "test-etag",
	}

	// Encrypt
	ciphertext, err := enc.Encrypt(objectKey, plaintext, metadata)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Contains(ciphertext, plaintext) {
		t.Error("ciphertext should not contain plaintext")
	}

	// Verify header
	if string(ciphertext[:4]) != HeaderMagic {
		t.Error("ciphertext should start with magic bytes")
	}

	// Decrypt
	decrypted, decMeta, err := enc.Decrypt(objectKey, ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify plaintext
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data does not match original")
	}

	// Verify metadata
	if decMeta.ContentType != metadata.ContentType {
		t.Errorf("content type mismatch: got %s, want %s", decMeta.ContentType, metadata.ContentType)
	}
	if decMeta.ContentLength != metadata.ContentLength {
		t.Errorf("content length mismatch: got %d, want %d", decMeta.ContentLength, metadata.ContentLength)
	}
	if decMeta.ETag != metadata.ETag {
		t.Errorf("ETag mismatch: got %s, want %s", decMeta.ETag, metadata.ETag)
	}
}

func TestNonceUniqueness(t *testing.T) {
	km := NewKeyManager()

	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := km.LoadKey(key); err != nil {
		t.Fatal(err)
	}

	enc := NewEncryptor(km, DefaultChunkSize)

	plaintext := []byte("Same content")
	objectKey := "same/key"
	metadata := &ObjectMetadata{ContentType: "text/plain", ContentLength: int64(len(plaintext))}

	// Encrypt same content twice
	ct1, err := enc.Encrypt(objectKey, plaintext, metadata)
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := enc.Encrypt(objectKey, plaintext, metadata)
	if err != nil {
		t.Fatal(err)
	}

	// Due to random salt, ciphertexts should be different
	if bytes.Equal(ct1, ct2) {
		t.Error("encrypting same content twice should produce different ciphertexts (different salt)")
	}

	// Both should decrypt correctly
	dec1, _, err := enc.Decrypt(objectKey, ct1)
	if err != nil {
		t.Fatalf("failed to decrypt ct1: %v", err)
	}

	dec2, _, err := enc.Decrypt(objectKey, ct2)
	if err != nil {
		t.Fatalf("failed to decrypt ct2: %v", err)
	}

	if !bytes.Equal(dec1, plaintext) || !bytes.Equal(dec2, plaintext) {
		t.Error("decryption should produce same plaintext")
	}
}

func TestTamperDetection(t *testing.T) {
	km := NewKeyManager()

	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := km.LoadKey(key); err != nil {
		t.Fatal(err)
	}

	enc := NewEncryptor(km, DefaultChunkSize)

	plaintext := []byte("Important data that should not be tampered with")
	objectKey := "secure/object"
	metadata := &ObjectMetadata{ContentType: "application/octet-stream", ContentLength: int64(len(plaintext))}

	ciphertext, err := enc.Encrypt(objectKey, plaintext, metadata)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext (modify a byte in the content section)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-20] ^= 0xFF // Flip bits near the end

	// Decryption should fail
	_, _, err = enc.Decrypt(objectKey, tampered)
	if err == nil {
		t.Error("decryption should fail for tampered ciphertext")
	}
	if err != ErrAuthenticationFailed {
		t.Errorf("expected ErrAuthenticationFailed, got %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	// Create two key managers with different keys
	km1 := NewKeyManager()
	km2 := NewKeyManager()

	key1 := make([]byte, MasterKeySize)
	key2 := make([]byte, MasterKeySize)
	rand.Read(key1)
	rand.Read(key2)

	km1.LoadKey(key1)
	km2.LoadKey(key2)

	enc1 := NewEncryptor(km1, DefaultChunkSize)
	enc2 := NewEncryptor(km2, DefaultChunkSize)

	plaintext := []byte("Secret message")
	objectKey := "test/key"
	metadata := &ObjectMetadata{ContentType: "text/plain", ContentLength: int64(len(plaintext))}

	// Encrypt with key1
	ciphertext, err := enc1.Encrypt(objectKey, plaintext, metadata)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with key2
	_, _, err = enc2.Decrypt(objectKey, ciphertext)
	if err == nil {
		t.Error("decryption should fail with wrong key")
	}
}

func TestKeyNotLoaded(t *testing.T) {
	km := NewKeyManager()
	enc := NewEncryptor(km, DefaultChunkSize)

	_, err := enc.Encrypt("key", []byte("data"), &ObjectMetadata{})
	if err != ErrKeyNotLoaded {
		t.Errorf("expected ErrKeyNotLoaded, got %v", err)
	}

	_, _, err = enc.Decrypt("key", []byte("invalid"))
	if err != ErrKeyNotLoaded {
		t.Errorf("expected ErrKeyNotLoaded, got %v", err)
	}
}

func TestInvalidHeader(t *testing.T) {
	km := NewKeyManager()
	key := make([]byte, MasterKeySize)
	rand.Read(key)
	km.LoadKey(key)

	enc := NewEncryptor(km, DefaultChunkSize)

	// Too short
	_, _, err := enc.Decrypt("key", []byte("short"))
	if err != ErrInvalidHeader {
		t.Errorf("expected ErrInvalidHeader for short input, got %v", err)
	}

	// Wrong magic
	wrongMagic := make([]byte, 100)
	copy(wrongMagic, "XXXX") // Wrong magic
	_, _, err = enc.Decrypt("key", wrongMagic)
	if err != ErrInvalidHeader {
		t.Errorf("expected ErrInvalidHeader for wrong magic, got %v", err)
	}
}

func TestLargeData(t *testing.T) {
	km := NewKeyManager()
	key := make([]byte, MasterKeySize)
	rand.Read(key)
	km.LoadKey(key)

	enc := NewEncryptor(km, DefaultChunkSize)

	// 1MB of data
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	metadata := &ObjectMetadata{
		ContentType:   "application/octet-stream",
		ContentLength: int64(len(plaintext)),
	}

	ciphertext, err := enc.Encrypt("large/object", plaintext, metadata)
	if err != nil {
		t.Fatalf("failed to encrypt large data: %v", err)
	}

	decrypted, _, err := enc.Decrypt("large/object", ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt large data: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large data decryption mismatch")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	km := NewKeyManager()
	key := make([]byte, MasterKeySize)
	rand.Read(key)
	km.LoadKey(key)

	enc := NewEncryptor(km, DefaultChunkSize)

	// 4MB chunk (typical PBS chunk size)
	plaintext := make([]byte, 4*1024*1024)
	rand.Read(plaintext)
	metadata := &ObjectMetadata{ContentType: "application/octet-stream", ContentLength: int64(len(plaintext))}

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := enc.Encrypt("bench/object", plaintext, metadata)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	km := NewKeyManager()
	key := make([]byte, MasterKeySize)
	rand.Read(key)
	km.LoadKey(key)

	enc := NewEncryptor(km, DefaultChunkSize)

	plaintext := make([]byte, 4*1024*1024)
	rand.Read(plaintext)
	metadata := &ObjectMetadata{ContentType: "application/octet-stream", ContentLength: int64(len(plaintext))}

	ciphertext, _ := enc.Encrypt("bench/object", plaintext, metadata)

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := enc.Decrypt("bench/object", ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
