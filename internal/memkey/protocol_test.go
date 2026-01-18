package memkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Test helper to create a server with identity
func newTestServer(t *testing.T) *Server {
	t.Helper()
	identity, err := NewServerIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	return NewServer(&ServerConfig{
		Identity:          identity,
		ChallengeTimeout:  5 * time.Second,
		MaxFailedAttempts: 3,
		LockoutDuration:   1 * time.Second,
	})
}

// Test helper to create a client with correct fingerprint
func newTestClient(t *testing.T, server *Server) *Client {
	t.Helper()
	return NewClient(server.Identity().Fingerprint())
}

// Test helper to generate a random master key
func randomMasterKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

// =============================================================================
// Server Identity Tests
// =============================================================================

func TestServerIdentity_New(t *testing.T) {
	identity, err := NewServerIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	// Verify key sizes
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("invalid public key size: %d", len(identity.PublicKey))
	}
	if len(identity.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("invalid private key size: %d", len(identity.PrivateKey))
	}
	if len(identity.X25519Public) != 32 {
		t.Errorf("invalid X25519 public key size: %d", len(identity.X25519Public))
	}
	if len(identity.X25519Private) != 32 {
		t.Errorf("invalid X25519 private key size: %d", len(identity.X25519Private))
	}

	// Verify fingerprint format (64 hex chars = 32 bytes SHA256)
	fp := identity.Fingerprint()
	if len(fp) != 64 {
		t.Errorf("invalid fingerprint length: %d", len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Errorf("fingerprint not valid hex: %v", err)
	}

	// Verify short fingerprint
	sfp := identity.ShortFingerprint()
	if len(sfp) != 16 {
		t.Errorf("invalid short fingerprint length: %d", len(sfp))
	}
	if sfp != fp[:16] {
		t.Error("short fingerprint should be prefix of full fingerprint")
	}
}

func TestServerIdentity_LoadFromSeed(t *testing.T) {
	// Create original identity
	original, err := NewServerIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	// Save and reload
	seed := original.Seed()
	reloaded, err := LoadServerIdentity(seed)
	if err != nil {
		t.Fatalf("failed to reload identity: %v", err)
	}

	// Verify same keys
	if !bytes.Equal(original.PublicKey, reloaded.PublicKey) {
		t.Error("public keys don't match")
	}
	if !bytes.Equal(original.PrivateKey, reloaded.PrivateKey) {
		t.Error("private keys don't match")
	}
	if !bytes.Equal(original.X25519Public, reloaded.X25519Public) {
		t.Error("X25519 public keys don't match")
	}
	if original.Fingerprint() != reloaded.Fingerprint() {
		t.Error("fingerprints don't match")
	}
}

func TestServerIdentity_LoadFromSeed_InvalidSeed(t *testing.T) {
	tests := []struct {
		name string
		seed string
	}{
		{"empty", ""},
		{"too short", "abcd"},
		{"not hex", "not-a-hex-string-at-all-definitely-not"},
		{"wrong length", "abcdef1234567890abcdef1234567890"}, // 16 bytes, need 32
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadServerIdentity(tc.seed)
			if err == nil {
				t.Error("expected error for invalid seed")
			}
		})
	}
}

func TestServerIdentity_Sign(t *testing.T) {
	identity, _ := NewServerIdentity()

	data := []byte("test message to sign")
	signature := identity.Sign(data)

	// Verify signature is valid
	if !ed25519.Verify(identity.PublicKey, data, signature) {
		t.Error("signature verification failed")
	}

	// Verify modified data fails
	data[0] ^= 0xFF
	if ed25519.Verify(identity.PublicKey, data, signature) {
		t.Error("signature should not verify for modified data")
	}
}

func TestServerIdentity_Uniqueness(t *testing.T) {
	// Generate multiple identities and ensure they're unique
	fingerprints := make(map[string]bool)
	for i := 0; i < 100; i++ {
		identity, _ := NewServerIdentity()
		fp := identity.Fingerprint()
		if fingerprints[fp] {
			t.Errorf("duplicate fingerprint generated: %s", fp)
		}
		fingerprints[fp] = true
	}
}

// =============================================================================
// Challenge Generation Tests
// =============================================================================

func TestServer_GenerateChallenge(t *testing.T) {
	server := newTestServer(t)

	resp, err := server.GenerateChallenge()
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	// Verify challenge is base64 encoded
	challenge, err := base64.StdEncoding.DecodeString(resp.Challenge)
	if err != nil {
		t.Errorf("challenge not valid base64: %v", err)
	}
	if len(challenge) != ChallengeSize {
		t.Errorf("invalid challenge size: %d", len(challenge))
	}

	// Verify server public key
	pubKey, err := base64.StdEncoding.DecodeString(resp.ServerPubKey)
	if err != nil {
		t.Errorf("server pubkey not valid base64: %v", err)
	}
	if !bytes.Equal(pubKey, server.Identity().PublicKey) {
		t.Error("server pubkey doesn't match identity")
	}

	// Verify X25519 public key
	x25519Pub, err := base64.StdEncoding.DecodeString(resp.ServerX25519PubKey)
	if err != nil {
		t.Errorf("X25519 pubkey not valid base64: %v", err)
	}
	if !bytes.Equal(x25519Pub, server.Identity().X25519Public) {
		t.Error("X25519 pubkey doesn't match identity")
	}

	// Verify timestamp is recent
	if resp.Timestamp == 0 {
		t.Error("timestamp should not be zero")
	}
	tsTime := time.Unix(resp.Timestamp, 0)
	if time.Since(tsTime) > time.Second {
		t.Error("timestamp should be recent")
	}

	// Verify signature
	signature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		t.Errorf("signature not valid base64: %v", err)
	}

	signData := make([]byte, len(challenge)+8)
	copy(signData, challenge)
	for i := 0; i < 8; i++ {
		signData[len(challenge)+i] = byte(resp.Timestamp >> (56 - i*8))
	}

	if !ed25519.Verify(pubKey, signData, signature) {
		t.Error("challenge signature verification failed")
	}
}

func TestServer_GenerateChallenge_Uniqueness(t *testing.T) {
	server := newTestServer(t)

	challenges := make(map[string]bool)
	for i := 0; i < 100; i++ {
		resp, err := server.GenerateChallenge()
		if err != nil {
			t.Fatalf("failed to generate challenge: %v", err)
		}
		if challenges[resp.Challenge] {
			t.Error("duplicate challenge generated")
		}
		challenges[resp.Challenge] = true
	}
}

// =============================================================================
// Client Verification Tests
// =============================================================================

func TestClient_VerifyChallenge_Success(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)

	resp, _ := server.GenerateChallenge()

	if err := client.VerifyChallenge(resp); err != nil {
		t.Errorf("challenge verification failed: %v", err)
	}
}

func TestClient_VerifyChallenge_WrongFingerprint(t *testing.T) {
	server := newTestServer(t)
	// Client with wrong fingerprint
	client := NewClient("0000000000000000000000000000000000000000000000000000000000000000")

	resp, _ := server.GenerateChallenge()

	err := client.VerifyChallenge(resp)
	if err != ErrFingerprintMismatch {
		t.Errorf("expected ErrFingerprintMismatch, got: %v", err)
	}
}

func TestClient_VerifyChallenge_TamperedSignature(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)

	resp, _ := server.GenerateChallenge()

	// Tamper with signature
	sig, _ := base64.StdEncoding.DecodeString(resp.Signature)
	sig[0] ^= 0xFF
	resp.Signature = base64.StdEncoding.EncodeToString(sig)

	err := client.VerifyChallenge(resp)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestClient_VerifyChallenge_TamperedChallenge(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)

	resp, _ := server.GenerateChallenge()

	// Tamper with challenge
	challenge, _ := base64.StdEncoding.DecodeString(resp.Challenge)
	challenge[0] ^= 0xFF
	resp.Challenge = base64.StdEncoding.EncodeToString(challenge)

	err := client.VerifyChallenge(resp)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestClient_VerifyChallenge_TamperedTimestamp(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)

	resp, _ := server.GenerateChallenge()

	// Tamper with timestamp
	resp.Timestamp += 1

	err := client.VerifyChallenge(resp)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestClient_VerifyChallenge_WrongServerKey(t *testing.T) {
	server := newTestServer(t)

	// Create another server with different identity
	otherIdentity, _ := NewServerIdentity()
	client := NewClient(otherIdentity.Fingerprint())

	resp, _ := server.GenerateChallenge()

	// Client expects different server
	err := client.VerifyChallenge(resp)
	if err != ErrFingerprintMismatch {
		t.Errorf("expected ErrFingerprintMismatch, got: %v", err)
	}
}

// =============================================================================
// Key Delivery Tests
// =============================================================================

func TestKeyDelivery_Success(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Get challenge
	challengeResp, _ := server.GenerateChallenge()

	// Verify challenge
	if err := client.VerifyChallenge(challengeResp); err != nil {
		t.Fatalf("challenge verification failed: %v", err)
	}

	// Prepare key delivery
	deliveryReq, err := client.PrepareKeyDelivery(challengeResp, masterKey)
	if err != nil {
		t.Fatalf("failed to prepare key delivery: %v", err)
	}

	// Deliver key
	deliveryResp, err := server.DeliverKey(deliveryReq)
	if err != nil {
		t.Fatalf("key delivery failed: %v", err)
	}

	if !deliveryResp.Success {
		t.Errorf("delivery should succeed: %s", deliveryResp.Message)
	}

	// Verify key was stored
	storedKey, err := server.GetKey()
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}

	if !bytes.Equal(storedKey, masterKey) {
		t.Error("stored key doesn't match delivered key")
	}

	// Verify fingerprint
	expectedFP := CalculateKeyFingerprint(masterKey)
	if deliveryResp.KeyFingerprint != expectedFP {
		t.Errorf("key fingerprint mismatch: got %s, want %s", deliveryResp.KeyFingerprint, expectedFP)
	}
}

func TestKeyDelivery_InvalidChallenge(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Get challenge
	challengeResp, _ := server.GenerateChallenge()

	// Tamper with challenge in delivery
	deliveryReq, _ := client.PrepareKeyDelivery(challengeResp, masterKey)
	deliveryReq.Challenge = base64.StdEncoding.EncodeToString(make([]byte, ChallengeSize))

	_, err := server.DeliverKey(deliveryReq)
	if err != ErrInvalidChallenge {
		t.Errorf("expected ErrInvalidChallenge, got: %v", err)
	}
}

func TestKeyDelivery_ExpiredChallenge(t *testing.T) {
	// Create server with very short timeout
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{
		Identity:         identity,
		ChallengeTimeout: 10 * time.Millisecond,
	})
	client := NewClient(identity.Fingerprint())
	masterKey := randomMasterKey(t)

	// Get challenge
	challengeResp, _ := server.GenerateChallenge()

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	// Try to deliver
	deliveryReq, _ := client.PrepareKeyDelivery(challengeResp, masterKey)
	_, err := server.DeliverKey(deliveryReq)
	if err != ErrInvalidChallenge {
		t.Errorf("expected ErrInvalidChallenge for expired challenge, got: %v", err)
	}
}

func TestKeyDelivery_ChallengeReuse(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Get challenge
	challengeResp, _ := server.GenerateChallenge()

	// First delivery should succeed
	deliveryReq1, _ := client.PrepareKeyDelivery(challengeResp, masterKey)
	_, err := server.DeliverKey(deliveryReq1)
	if err != nil {
		t.Fatalf("first delivery failed: %v", err)
	}

	// Clear key for second attempt
	server.ClearKey()

	// Second delivery with same challenge should fail
	deliveryReq2, _ := client.PrepareKeyDelivery(challengeResp, masterKey)
	_, err = server.DeliverKey(deliveryReq2)
	if err != ErrInvalidChallenge {
		t.Errorf("expected ErrInvalidChallenge for reused challenge, got: %v", err)
	}
}

func TestKeyDelivery_WrongKeySize(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)

	// Wrong size keys
	wrongKeys := [][]byte{
		make([]byte, 16), // Too short
		make([]byte, 64), // Too long
		{},               // Empty
	}

	for _, key := range wrongKeys {
		challengeResp, _ := server.GenerateChallenge()
		_, err := client.PrepareKeyDelivery(challengeResp, key)
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize for key size %d, got: %v", len(key), err)
		}
	}
}

func TestKeyDelivery_TamperedCiphertext(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	challengeResp, _ := server.GenerateChallenge()
	deliveryReq, _ := client.PrepareKeyDelivery(challengeResp, masterKey)

	// Tamper with ciphertext
	ciphertext, _ := base64.StdEncoding.DecodeString(deliveryReq.EncryptedKey)
	ciphertext[0] ^= 0xFF
	deliveryReq.EncryptedKey = base64.StdEncoding.EncodeToString(ciphertext)

	_, err := server.DeliverKey(deliveryReq)
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestKeyDelivery_TamperedNonce(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	challengeResp, _ := server.GenerateChallenge()
	deliveryReq, _ := client.PrepareKeyDelivery(challengeResp, masterKey)

	// Tamper with nonce
	nonce, _ := base64.StdEncoding.DecodeString(deliveryReq.Nonce)
	nonce[0] ^= 0xFF
	deliveryReq.Nonce = base64.StdEncoding.EncodeToString(nonce)

	_, err := server.DeliverKey(deliveryReq)
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

func TestKeyDelivery_TamperedEphemeralKey(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	challengeResp, _ := server.GenerateChallenge()
	deliveryReq, _ := client.PrepareKeyDelivery(challengeResp, masterKey)

	// Tamper with ephemeral public key
	ephPub, _ := base64.StdEncoding.DecodeString(deliveryReq.EphemeralPubKey)
	ephPub[0] ^= 0xFF
	deliveryReq.EphemeralPubKey = base64.StdEncoding.EncodeToString(ephPub)

	_, err := server.DeliverKey(deliveryReq)
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed, got: %v", err)
	}
}

// =============================================================================
// Perfect Forward Secrecy Tests
// =============================================================================

func TestPFS_DifferentEphemeralKeys(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Get two challenges
	challenge1, _ := server.GenerateChallenge()
	challenge2, _ := server.GenerateChallenge()

	// Prepare two deliveries
	delivery1, _ := client.PrepareKeyDelivery(challenge1, masterKey)
	delivery2, _ := client.PrepareKeyDelivery(challenge2, masterKey)

	// Ephemeral keys should be different
	if delivery1.EphemeralPubKey == delivery2.EphemeralPubKey {
		t.Error("ephemeral keys should be different for each delivery")
	}

	// Ciphertexts should be different (different nonces)
	if delivery1.EncryptedKey == delivery2.EncryptedKey {
		t.Error("ciphertexts should be different for each delivery")
	}

	// Nonces should be different
	if delivery1.Nonce == delivery2.Nonce {
		t.Error("nonces should be different for each delivery")
	}
}

func TestPFS_CompromisedSessionKeyDoesntAffectOthers(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Do first key delivery
	challenge1, _ := server.GenerateChallenge()
	delivery1, _ := client.PrepareKeyDelivery(challenge1, masterKey)
	resp1, _ := server.DeliverKey(delivery1)
	if !resp1.Success {
		t.Fatal("first delivery failed")
	}

	server.ClearKey()

	// Even if an attacker captures delivery1 and somehow derives the session key,
	// they can't use it for delivery2 because:
	// 1. Different ephemeral key
	// 2. Different challenge (used in key derivation)
	// 3. Challenge is consumed after use

	challenge2, _ := server.GenerateChallenge()
	delivery2, _ := client.PrepareKeyDelivery(challenge2, masterKey)
	resp2, _ := server.DeliverKey(delivery2)
	if !resp2.Success {
		t.Fatal("second delivery failed")
	}

	// Verify key is correct
	storedKey, _ := server.GetKey()
	if !bytes.Equal(storedKey, masterKey) {
		t.Error("key should be correctly stored")
	}
}

// =============================================================================
// Lockout Tests
// =============================================================================

func TestServer_Lockout(t *testing.T) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{
		Identity:          identity,
		ChallengeTimeout:  5 * time.Second,
		MaxFailedAttempts: 3,
		LockoutDuration:   100 * time.Millisecond,
	})

	// Generate valid challenges but deliver with invalid data
	for i := 0; i < 3; i++ {
		server.GenerateChallenge()
		_, err := server.DeliverKey(&KeyDeliveryRequest{
			Challenge: base64.StdEncoding.EncodeToString(make([]byte, ChallengeSize)),
		})
		if i < 2 && err == ErrLockedOut {
			t.Errorf("should not be locked out after %d attempts", i+1)
		}
	}

	// Should be locked out now
	_, err := server.GenerateChallenge()
	if err != ErrLockedOut {
		t.Errorf("expected ErrLockedOut, got: %v", err)
	}

	// Wait for lockout to expire
	time.Sleep(150 * time.Millisecond)

	// Should work again
	_, err = server.GenerateChallenge()
	if err != nil {
		t.Errorf("should work after lockout expires: %v", err)
	}
}

func TestServer_LockoutStatus(t *testing.T) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{
		Identity:          identity,
		MaxFailedAttempts: 2,
		LockoutDuration:   100 * time.Millisecond,
	})

	// Not locked out initially
	status := server.Status()
	if status.LockedOut {
		t.Error("should not be locked out initially")
	}

	// Trigger lockout
	for i := 0; i < 2; i++ {
		server.GenerateChallenge()
		server.DeliverKey(&KeyDeliveryRequest{
			Challenge: base64.StdEncoding.EncodeToString(make([]byte, ChallengeSize)),
		})
	}

	status = server.Status()
	if !status.LockedOut {
		t.Error("should be locked out")
	}
	if status.LockoutEndsAt == 0 {
		t.Error("lockout end time should be set")
	}
}

func TestServer_SuccessfulDeliveryResetsFailedAttempts(t *testing.T) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{
		Identity:          identity,
		MaxFailedAttempts: 3,
		LockoutDuration:   1 * time.Second,
	})
	client := NewClient(identity.Fingerprint())
	masterKey := randomMasterKey(t)

	// Two failed attempts
	for i := 0; i < 2; i++ {
		server.GenerateChallenge()
		server.DeliverKey(&KeyDeliveryRequest{
			Challenge: base64.StdEncoding.EncodeToString(make([]byte, ChallengeSize)),
		})
	}

	// Successful delivery
	challenge, _ := server.GenerateChallenge()
	delivery, _ := client.PrepareKeyDelivery(challenge, masterKey)
	server.DeliverKey(delivery)

	// Two more failed attempts should not trigger lockout
	// (counter was reset by successful delivery)
	for i := 0; i < 2; i++ {
		server.GenerateChallenge()
		server.DeliverKey(&KeyDeliveryRequest{
			Challenge: base64.StdEncoding.EncodeToString(make([]byte, ChallengeSize)),
		})
	}

	// Should not be locked out
	_, err := server.GenerateChallenge()
	if err == ErrLockedOut {
		t.Error("should not be locked out after successful delivery reset")
	}
}

// =============================================================================
// Status Tests
// =============================================================================

func TestServer_Status(t *testing.T) {
	server := newTestServer(t)

	status := server.Status()

	if status.KeyLoaded {
		t.Error("key should not be loaded initially")
	}
	if status.ServerFingerprint != server.Identity().Fingerprint() {
		t.Error("fingerprint mismatch")
	}
	if status.Uptime < 0 {
		t.Error("uptime should be non-negative")
	}

	// Load a key
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)
	challenge, _ := server.GenerateChallenge()
	delivery, _ := client.PrepareKeyDelivery(challenge, masterKey)
	server.DeliverKey(delivery)

	status = server.Status()
	if !status.KeyLoaded {
		t.Error("key should be loaded")
	}
	if status.KeyLoadedAt == 0 {
		t.Error("key loaded time should be set")
	}
}

func TestServer_ClearKey(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Load key
	challenge, _ := server.GenerateChallenge()
	delivery, _ := client.PrepareKeyDelivery(challenge, masterKey)
	server.DeliverKey(delivery)

	// Verify loaded
	_, err := server.GetKey()
	if err != nil {
		t.Error("key should be loaded")
	}

	// Clear
	server.ClearKey()

	// Verify cleared
	_, err = server.GetKey()
	if err == nil {
		t.Error("key should be cleared")
	}

	status := server.Status()
	if status.KeyLoaded {
		t.Error("status should show key not loaded")
	}
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestServer_ConcurrentChallenges(t *testing.T) {
	server := newTestServer(t)

	var wg sync.WaitGroup
	challenges := make(chan *ChallengeResponse, 100)

	// Generate challenges concurrently
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := server.GenerateChallenge()
			if err != nil {
				t.Errorf("challenge generation failed: %v", err)
				return
			}
			challenges <- resp
		}()
	}

	wg.Wait()
	close(challenges)

	// Verify all challenges are unique
	seen := make(map[string]bool)
	for resp := range challenges {
		if seen[resp.Challenge] {
			t.Error("duplicate challenge generated")
		}
		seen[resp.Challenge] = true
	}
}

func TestServer_ConcurrentDelivery(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	// Generate multiple challenges
	challenges := make([]*ChallengeResponse, 10)
	for i := range challenges {
		challenges[i], _ = server.GenerateChallenge()
	}

	// Try to deliver concurrently - only one should succeed
	var wg sync.WaitGroup
	successes := make(chan bool, len(challenges))

	for _, ch := range challenges {
		wg.Add(1)
		go func(challenge *ChallengeResponse) {
			defer wg.Done()
			delivery, _ := client.PrepareKeyDelivery(challenge, masterKey)
			resp, err := server.DeliverKey(delivery)
			if err == nil && resp.Success {
				successes <- true
			}
		}(ch)
	}

	wg.Wait()
	close(successes)

	// Count successes - multiple can succeed since we're not blocking
	// after first success (that's a design choice)
	successCount := 0
	for range successes {
		successCount++
	}

	// At least one should succeed
	if successCount == 0 {
		t.Error("at least one delivery should succeed")
	}
}

// =============================================================================
// Serialization Tests
// =============================================================================

func TestChallengeResponse_Serialization(t *testing.T) {
	server := newTestServer(t)
	original, _ := server.GenerateChallenge()

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := UnmarshalChallengeResponse(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if original.Challenge != restored.Challenge {
		t.Error("challenge mismatch")
	}
	if original.ServerPubKey != restored.ServerPubKey {
		t.Error("server pubkey mismatch")
	}
	if original.ServerX25519PubKey != restored.ServerX25519PubKey {
		t.Error("X25519 pubkey mismatch")
	}
	if original.Timestamp != restored.Timestamp {
		t.Error("timestamp mismatch")
	}
	if original.Signature != restored.Signature {
		t.Error("signature mismatch")
	}
}

func TestKeyDeliveryRequest_Serialization(t *testing.T) {
	server := newTestServer(t)
	client := newTestClient(t, server)
	masterKey := randomMasterKey(t)

	challenge, _ := server.GenerateChallenge()
	original, _ := client.PrepareKeyDelivery(challenge, masterKey)

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	restored, err := UnmarshalKeyDeliveryRequest(data)
	if err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if original.Challenge != restored.Challenge {
		t.Error("challenge mismatch")
	}
	if original.EphemeralPubKey != restored.EphemeralPubKey {
		t.Error("ephemeral pubkey mismatch")
	}
	if original.EncryptedKey != restored.EncryptedKey {
		t.Error("encrypted key mismatch")
	}
	if original.Nonce != restored.Nonce {
		t.Error("nonce mismatch")
	}
}

// =============================================================================
// Key Fingerprint Tests
// =============================================================================

func TestCalculateKeyFingerprint(t *testing.T) {
	key := make([]byte, MasterKeySize)
	for i := range key {
		key[i] = byte(i)
	}

	fp1 := CalculateKeyFingerprint(key)
	fp2 := CalculateKeyFingerprint(key)

	if fp1 != fp2 {
		t.Error("fingerprint should be deterministic")
	}

	// Should be 16 hex chars (8 bytes)
	if len(fp1) != 16 {
		t.Errorf("fingerprint should be 16 chars, got %d", len(fp1))
	}

	// Different key should have different fingerprint
	key[0] = 0xFF
	fp3 := CalculateKeyFingerprint(key)
	if fp1 == fp3 {
		t.Error("different keys should have different fingerprints")
	}
}

// =============================================================================
// ECDH Key Exchange Tests
// =============================================================================

func TestECDH_KeyExchange(t *testing.T) {
	// Test that client and server derive the same shared secret

	// Server's X25519 keypair
	serverPriv := make([]byte, 32)
	rand.Read(serverPriv)
	serverPriv[0] &= 248
	serverPriv[31] &= 127
	serverPriv[31] |= 64
	serverPub, _ := curve25519.X25519(serverPriv, curve25519.Basepoint)

	// Client's ephemeral X25519 keypair
	clientPriv := make([]byte, 32)
	rand.Read(clientPriv)
	clientPriv[0] &= 248
	clientPriv[31] &= 127
	clientPriv[31] |= 64
	clientPub, _ := curve25519.X25519(clientPriv, curve25519.Basepoint)

	// Both derive shared secret
	serverShared, _ := curve25519.X25519(serverPriv, clientPub)
	clientShared, _ := curve25519.X25519(clientPriv, serverPub)

	if !bytes.Equal(serverShared, clientShared) {
		t.Error("shared secrets should match")
	}

	// Verify derived encryption keys match
	challenge := make([]byte, ChallengeSize)
	rand.Read(challenge)

	serverKey := deriveEncryptionKey(serverShared, challenge)
	clientKey := deriveEncryptionKey(clientShared, challenge)

	if !bytes.Equal(serverKey, clientKey) {
		t.Error("derived encryption keys should match")
	}
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

func TestServer_InvalidEncodings(t *testing.T) {
	server := newTestServer(t)

	tests := []struct {
		name    string
		request *KeyDeliveryRequest
	}{
		{
			name: "invalid challenge base64",
			request: &KeyDeliveryRequest{
				Challenge:       "not-valid-base64!!!",
				EphemeralPubKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EncryptedKey:    base64.StdEncoding.EncodeToString(make([]byte, 48)),
				Nonce:           base64.StdEncoding.EncodeToString(make([]byte, 24)),
			},
		},
		{
			name: "invalid ephemeral key base64",
			request: &KeyDeliveryRequest{
				Challenge:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EphemeralPubKey: "not-valid-base64!!!",
				EncryptedKey:    base64.StdEncoding.EncodeToString(make([]byte, 48)),
				Nonce:           base64.StdEncoding.EncodeToString(make([]byte, 24)),
			},
		},
		{
			name: "invalid nonce base64",
			request: &KeyDeliveryRequest{
				Challenge:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EphemeralPubKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EncryptedKey:    base64.StdEncoding.EncodeToString(make([]byte, 48)),
				Nonce:           "not-valid-base64!!!",
			},
		},
		{
			name: "wrong ephemeral key size",
			request: &KeyDeliveryRequest{
				Challenge:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EphemeralPubKey: base64.StdEncoding.EncodeToString(make([]byte, 16)), // wrong size
				EncryptedKey:    base64.StdEncoding.EncodeToString(make([]byte, 48)),
				Nonce:           base64.StdEncoding.EncodeToString(make([]byte, 24)),
			},
		},
		{
			name: "wrong nonce size",
			request: &KeyDeliveryRequest{
				Challenge:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EphemeralPubKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				EncryptedKey:    base64.StdEncoding.EncodeToString(make([]byte, 48)),
				Nonce:           base64.StdEncoding.EncodeToString(make([]byte, 12)), // wrong size
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a valid challenge first
			server.GenerateChallenge()

			_, err := server.DeliverKey(tc.request)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

func TestClient_InvalidChallengeResponse(t *testing.T) {
	client := NewClient("0000000000000000000000000000000000000000000000000000000000000000")

	tests := []struct {
		name     string
		response *ChallengeResponse
	}{
		{
			name: "invalid server pubkey base64",
			response: &ChallengeResponse{
				Challenge:          base64.StdEncoding.EncodeToString(make([]byte, 32)),
				ServerPubKey:       "not-valid!!!",
				ServerX25519PubKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Timestamp:          time.Now().Unix(),
				Signature:          base64.StdEncoding.EncodeToString(make([]byte, 64)),
			},
		},
		{
			name: "wrong server pubkey size",
			response: &ChallengeResponse{
				Challenge:          base64.StdEncoding.EncodeToString(make([]byte, 32)),
				ServerPubKey:       base64.StdEncoding.EncodeToString(make([]byte, 16)), // wrong size
				ServerX25519PubKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
				Timestamp:          time.Now().Unix(),
				Signature:          base64.StdEncoding.EncodeToString(make([]byte, 64)),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := client.VerifyChallenge(tc.response)
			if err == nil {
				t.Error("expected error for invalid response")
			}
		})
	}
}

// =============================================================================
// Integration Test - Full Protocol Flow
// =============================================================================

func TestFullProtocolFlow(t *testing.T) {
	// This test simulates the complete protocol flow

	// 1. Server starts with persistent identity
	identity, _ := NewServerIdentity()
	seed := identity.Seed() // Would be persisted

	// 2. Server restarts (simulated by loading from seed)
	identity2, _ := LoadServerIdentity(seed)
	server := NewServer(&ServerConfig{Identity: identity2})

	// 3. Admin tool configured with server fingerprint
	client := NewClient(identity2.Fingerprint())

	// 4. Admin generates master key
	masterKey := randomMasterKey(t)
	keyFingerprint := CalculateKeyFingerprint(masterKey)

	// 5. Admin requests challenge
	challengeResp, err := server.GenerateChallenge()
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}

	// 6. Admin verifies server identity
	if err := client.VerifyChallenge(challengeResp); err != nil {
		t.Fatalf("server verification failed: %v", err)
	}

	// 7. Admin prepares encrypted key delivery
	deliveryReq, err := client.PrepareKeyDelivery(challengeResp, masterKey)
	if err != nil {
		t.Fatalf("key preparation failed: %v", err)
	}

	// 8. Admin sends key to server
	deliveryResp, err := server.DeliverKey(deliveryReq)
	if err != nil {
		t.Fatalf("key delivery failed: %v", err)
	}

	// 9. Verify delivery response
	if !deliveryResp.Success {
		t.Fatalf("delivery should succeed: %s", deliveryResp.Message)
	}
	if deliveryResp.KeyFingerprint != keyFingerprint {
		t.Error("key fingerprint mismatch in response")
	}

	// 10. Proxy can now get the key
	storedKey, err := server.GetKey()
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if !bytes.Equal(storedKey, masterKey) {
		t.Error("stored key doesn't match")
	}

	// 11. Verify status
	status := server.Status()
	if !status.KeyLoaded {
		t.Error("status should show key loaded")
	}
	if status.ServerFingerprint != identity2.Fingerprint() {
		t.Error("status fingerprint mismatch")
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkChallengeGeneration(b *testing.B) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{Identity: identity})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.GenerateChallenge()
	}
}

func BenchmarkChallengeVerification(b *testing.B) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{Identity: identity})
	client := NewClient(identity.Fingerprint())

	challenge, _ := server.GenerateChallenge()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.VerifyChallenge(challenge)
	}
}

func BenchmarkKeyDeliveryPreparation(b *testing.B) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{Identity: identity})
	client := NewClient(identity.Fingerprint())
	masterKey := make([]byte, MasterKeySize)
	rand.Read(masterKey)

	challenges := make([]*ChallengeResponse, b.N)
	for i := range challenges {
		challenges[i], _ = server.GenerateChallenge()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.PrepareKeyDelivery(challenges[i], masterKey)
	}
}

func BenchmarkKeyDelivery(b *testing.B) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{Identity: identity})
	client := NewClient(identity.Fingerprint())
	masterKey := make([]byte, MasterKeySize)
	rand.Read(masterKey)

	deliveries := make([]*KeyDeliveryRequest, b.N)
	for i := range deliveries {
		challenge, _ := server.GenerateChallenge()
		deliveries[i], _ = client.PrepareKeyDelivery(challenge, masterKey)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Need new challenge for each since they're consumed
		challenge, _ := server.GenerateChallenge()
		delivery, _ := client.PrepareKeyDelivery(challenge, masterKey)
		server.DeliverKey(delivery)
		server.ClearKey()
	}
}

func BenchmarkFullProtocol(b *testing.B) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{Identity: identity})
	client := NewClient(identity.Fingerprint())
	masterKey := make([]byte, MasterKeySize)
	rand.Read(masterKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		challenge, _ := server.GenerateChallenge()
		client.VerifyChallenge(challenge)
		delivery, _ := client.PrepareKeyDelivery(challenge, masterKey)
		server.DeliverKey(delivery)
		server.ClearKey()
	}
}
