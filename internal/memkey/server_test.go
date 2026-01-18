package memkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestHTTPServer(t *testing.T) (*HTTPServer, *Client) {
	t.Helper()

	identity, err := NewServerIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	server := NewServer(&ServerConfig{
		Identity:          identity,
		ChallengeTimeout:  5 * time.Second,
		MaxFailedAttempts: 3,
		LockoutDuration:   100 * time.Millisecond,
	})

	httpServer := NewHTTPServer(&HTTPServerConfig{
		ListenAddr: "127.0.0.1:0",
		Server:     server,
	})

	client := NewClient(identity.Fingerprint())

	return httpServer, client
}

func TestHTTPServer_Challenge(t *testing.T) {
	hs, client := newTestHTTPServer(t)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	w := httptest.NewRecorder()

	hs.handleChallenge(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ChallengeResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify challenge can be verified by client
	if err := client.VerifyChallenge(&resp); err != nil {
		t.Errorf("challenge verification failed: %v", err)
	}
}

func TestHTTPServer_Challenge_WrongMethod(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodPost, "/challenge", nil)
	w := httptest.NewRecorder()

	hs.handleChallenge(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestHTTPServer_KeyDelivery(t *testing.T) {
	hs, client := newTestHTTPServer(t)

	// Get challenge
	req1 := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	w1 := httptest.NewRecorder()
	hs.handleChallenge(w1, req1)

	var challengeResp ChallengeResponse
	json.NewDecoder(w1.Body).Decode(&challengeResp)

	// Prepare key delivery
	masterKey := make([]byte, MasterKeySize)
	rand.Read(masterKey)

	deliveryReq, err := client.PrepareKeyDelivery(&challengeResp, masterKey)
	if err != nil {
		t.Fatalf("failed to prepare delivery: %v", err)
	}

	// Send key
	body, _ := json.Marshal(deliveryReq)
	req2 := httptest.NewRequest(http.MethodPost, "/key", bytes.NewReader(body))
	w2 := httptest.NewRecorder()

	hs.handleKey(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var deliveryResp KeyDeliveryResponse
	if err := json.NewDecoder(w2.Body).Decode(&deliveryResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !deliveryResp.Success {
		t.Errorf("delivery should succeed: %s", deliveryResp.Message)
	}

	// Verify key was stored
	storedKey, err := hs.GetKey()
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}

	if !bytes.Equal(storedKey, masterKey) {
		t.Error("stored key doesn't match")
	}
}

func TestHTTPServer_KeyDelivery_WrongMethod(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/key", nil)
	w := httptest.NewRecorder()

	hs.handleKey(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestHTTPServer_KeyDelivery_InvalidBody(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodPost, "/key", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()

	hs.handleKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHTTPServer_KeyDelivery_InvalidChallenge(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	// Send key with non-existent challenge
	deliveryReq := &KeyDeliveryRequest{
		Challenge:       "aW52YWxpZA==", // "invalid" base64
		EphemeralPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		EncryptedKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Nonce:           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}

	body, _ := json.Marshal(deliveryReq)
	req := httptest.NewRequest(http.MethodPost, "/key", bytes.NewReader(body))
	w := httptest.NewRecorder()

	hs.handleKey(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHTTPServer_Status(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()

	hs.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var status StatusResponse
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if status.KeyLoaded {
		t.Error("key should not be loaded initially")
	}

	if status.ServerFingerprint == "" {
		t.Error("server fingerprint should be present")
	}
}

func TestHTTPServer_Status_WrongMethod(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodPost, "/status", nil)
	w := httptest.NewRecorder()

	hs.handleStatus(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestHTTPServer_Health_NoKey(t *testing.T) {
	hs, _ := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	hs.handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}

	var health struct {
		Healthy bool   `json:"healthy"`
		Reason  string `json:"reason"`
	}
	json.NewDecoder(w.Body).Decode(&health)

	if health.Healthy {
		t.Error("should not be healthy without key")
	}
	if health.Reason == "" {
		t.Error("should have reason for unhealthy")
	}
}

func TestHTTPServer_Health_WithKey(t *testing.T) {
	hs, client := newTestHTTPServer(t)

	// Load a key first
	req1 := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	w1 := httptest.NewRecorder()
	hs.handleChallenge(w1, req1)

	var challengeResp ChallengeResponse
	json.NewDecoder(w1.Body).Decode(&challengeResp)

	masterKey := make([]byte, MasterKeySize)
	rand.Read(masterKey)
	deliveryReq, _ := client.PrepareKeyDelivery(&challengeResp, masterKey)

	body, _ := json.Marshal(deliveryReq)
	req2 := httptest.NewRequest(http.MethodPost, "/key", bytes.NewReader(body))
	w2 := httptest.NewRecorder()
	hs.handleKey(w2, req2)

	// Now check health
	req3 := httptest.NewRequest(http.MethodGet, "/health", nil)
	w3 := httptest.NewRecorder()

	hs.handleHealth(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w3.Code)
	}

	var health struct {
		Healthy bool `json:"healthy"`
	}
	json.NewDecoder(w3.Body).Decode(&health)

	if !health.Healthy {
		t.Error("should be healthy with key loaded")
	}
}

func TestHTTPServer_Lockout(t *testing.T) {
	identity, _ := NewServerIdentity()
	server := NewServer(&ServerConfig{
		Identity:          identity,
		MaxFailedAttempts: 2,
		LockoutDuration:   100 * time.Millisecond,
	})

	hs := NewHTTPServer(&HTTPServerConfig{
		ListenAddr: "127.0.0.1:0",
		Server:     server,
	})

	// Trigger lockout by sending invalid key deliveries
	for i := 0; i < 2; i++ {
		// Get challenge
		req1 := httptest.NewRequest(http.MethodGet, "/challenge", nil)
		w1 := httptest.NewRecorder()
		hs.handleChallenge(w1, req1)

		// Send invalid key
		deliveryReq := &KeyDeliveryRequest{
			Challenge:       "aW52YWxpZA==",
			EphemeralPubKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			EncryptedKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			Nonce:           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		}
		body, _ := json.Marshal(deliveryReq)
		req2 := httptest.NewRequest(http.MethodPost, "/key", bytes.NewReader(body))
		w2 := httptest.NewRecorder()
		hs.handleKey(w2, req2)
	}

	// Should be locked out now
	req := httptest.NewRequest(http.MethodGet, "/challenge", nil)
	w := httptest.NewRecorder()
	hs.handleChallenge(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", w.Code)
	}
}

func TestHTTPServer_StartStop(t *testing.T) {
	hs, client := newTestHTTPServer(t)

	if err := hs.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	// Wait a bit for server to start
	time.Sleep(10 * time.Millisecond)

	// Make actual HTTP request
	addr := "http://" + hs.Addr()

	// Get challenge
	resp, err := http.Get(addr + "/challenge")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	var challengeResp ChallengeResponse
	json.NewDecoder(resp.Body).Decode(&challengeResp)

	if err := client.VerifyChallenge(&challengeResp); err != nil {
		t.Errorf("verification failed: %v", err)
	}

	// Shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := hs.Shutdown(ctx); err != nil {
		t.Errorf("shutdown failed: %v", err)
	}
}

func TestHTTPServer_FullIntegration(t *testing.T) {
	hs, client := newTestHTTPServer(t)

	if err := hs.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(ctx)
	}()

	time.Sleep(10 * time.Millisecond)
	addr := "http://" + hs.Addr()

	// 1. Check status - no key
	statusResp, _ := http.Get(addr + "/status")
	var status StatusResponse
	json.NewDecoder(statusResp.Body).Decode(&status)
	statusResp.Body.Close()

	if status.KeyLoaded {
		t.Error("key should not be loaded initially")
	}

	// 2. Check health - unhealthy
	healthResp, _ := http.Get(addr + "/health")
	if healthResp.StatusCode != http.StatusServiceUnavailable {
		t.Error("should be unhealthy without key")
	}
	healthResp.Body.Close()

	// 3. Get challenge
	challengeResp, _ := http.Get(addr + "/challenge")
	var challenge ChallengeResponse
	json.NewDecoder(challengeResp.Body).Decode(&challenge)
	challengeResp.Body.Close()

	// 4. Verify challenge
	if err := client.VerifyChallenge(&challenge); err != nil {
		t.Fatalf("verification failed: %v", err)
	}

	// 5. Prepare and send key
	masterKey := make([]byte, MasterKeySize)
	rand.Read(masterKey)

	deliveryReq, _ := client.PrepareKeyDelivery(&challenge, masterKey)
	body, _ := json.Marshal(deliveryReq)

	keyResp, _ := http.Post(addr+"/key", "application/json", bytes.NewReader(body))
	var delivery KeyDeliveryResponse
	json.NewDecoder(keyResp.Body).Decode(&delivery)
	keyResp.Body.Close()

	if !delivery.Success {
		t.Fatalf("key delivery failed: %s", delivery.Message)
	}

	// 6. Verify key fingerprint
	expectedFP := CalculateKeyFingerprint(masterKey)
	if delivery.KeyFingerprint != expectedFP {
		t.Errorf("fingerprint mismatch: got %s, want %s", delivery.KeyFingerprint, expectedFP)
	}

	// 7. Check health - healthy
	healthResp2, _ := http.Get(addr + "/health")
	if healthResp2.StatusCode != http.StatusOK {
		t.Error("should be healthy with key")
	}
	healthResp2.Body.Close()

	// 8. Check status - key loaded
	statusResp2, _ := http.Get(addr + "/status")
	var status2 StatusResponse
	json.NewDecoder(statusResp2.Body).Decode(&status2)
	statusResp2.Body.Close()

	if !status2.KeyLoaded {
		t.Error("key should be loaded")
	}

	// 9. Verify stored key
	storedKey, err := hs.GetKey()
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if !bytes.Equal(storedKey, masterKey) {
		t.Error("stored key doesn't match")
	}
}
