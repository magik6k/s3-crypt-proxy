package memkey

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPServer wraps the memkey Server with HTTP endpoints
type HTTPServer struct {
	server     *Server
	httpServer *http.Server
	listener   net.Listener

	mu       sync.RWMutex
	started  bool
	shutdown bool
}

// HTTPServerConfig holds HTTP server configuration
type HTTPServerConfig struct {
	// ListenAddr is the address to listen on (e.g., "127.0.0.1:7070")
	ListenAddr string

	// TLSConfig for HTTPS (optional)
	TLSConfig *tls.Config

	// Server is the underlying memkey server
	Server *Server

	// ReadTimeout for HTTP server
	ReadTimeout time.Duration

	// WriteTimeout for HTTP server
	WriteTimeout time.Duration
}

// NewHTTPServer creates a new HTTP server for the memkey protocol
func NewHTTPServer(cfg *HTTPServerConfig) *HTTPServer {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}

	hs := &HTTPServer{
		server: cfg.Server,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", hs.handleChallenge)
	mux.HandleFunc("/key", hs.handleKey)
	mux.HandleFunc("/key/raw", hs.handleKeyRaw)
	mux.HandleFunc("/status", hs.handleStatus)
	mux.HandleFunc("/health", hs.handleHealth)

	hs.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		TLSConfig:    cfg.TLSConfig,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return hs
}

// Start starts the HTTP server
func (hs *HTTPServer) Start() error {
	hs.mu.Lock()
	if hs.started {
		hs.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	hs.started = true
	hs.mu.Unlock()

	var err error
	hs.listener, err = net.Listen("tcp", hs.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	// Log server fingerprint on startup
	log.Printf("Memkey server starting on %s", hs.listener.Addr())
	log.Printf("Server fingerprint: %s", hs.server.Identity().Fingerprint())
	log.Printf("Server short fingerprint: %s", hs.server.Identity().ShortFingerprint())

	go func() {
		var err error
		if hs.httpServer.TLSConfig != nil {
			err = hs.httpServer.ServeTLS(hs.listener, "", "")
		} else {
			err = hs.httpServer.Serve(hs.listener)
		}
		if err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	return nil
}

// Shutdown gracefully shuts down the server
func (hs *HTTPServer) Shutdown(ctx context.Context) error {
	hs.mu.Lock()
	if hs.shutdown {
		hs.mu.Unlock()
		return nil
	}
	hs.shutdown = true
	hs.mu.Unlock()

	// Clear key from memory on shutdown
	hs.server.ClearKey()

	return hs.httpServer.Shutdown(ctx)
}

// Addr returns the server's listen address
func (hs *HTTPServer) Addr() string {
	if hs.listener != nil {
		return hs.listener.Addr().String()
	}
	return hs.httpServer.Addr
}

// handleChallenge handles GET /challenge
func (hs *HTTPServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		hs.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp, err := hs.server.GenerateChallenge()
	if err != nil {
		if err == ErrLockedOut {
			hs.sendError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		hs.sendError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hs.sendJSON(w, http.StatusOK, resp)
}

// handleKey handles POST /key
func (hs *HTTPServer) handleKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		hs.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req KeyDeliveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		hs.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := hs.server.DeliverKey(&req)
	if err != nil {
		switch err {
		case ErrLockedOut:
			hs.sendError(w, http.StatusTooManyRequests, err.Error())
		case ErrInvalidChallenge:
			hs.sendError(w, http.StatusBadRequest, err.Error())
		case ErrDecryptionFailed:
			hs.sendError(w, http.StatusBadRequest, err.Error())
		case ErrInvalidKeySize:
			hs.sendError(w, http.StatusBadRequest, err.Error())
		default:
			hs.sendError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	log.Printf("Master key loaded successfully, fingerprint: %s", resp.KeyFingerprint)
	hs.sendJSON(w, http.StatusOK, resp)
}

// handleKeyRaw handles GET /key/raw - returns raw key bytes for local proxy
// This endpoint should only be accessible from localhost
func (hs *HTTPServer) handleKeyRaw(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		hs.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	key, err := hs.server.GetKey()
	if err != nil {
		hs.sendError(w, http.StatusServiceUnavailable, "key not loaded")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", "32")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(key)
}

// handleStatus handles GET /status
func (hs *HTTPServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		hs.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	hs.sendJSON(w, http.StatusOK, hs.server.Status())
}

// handleHealth handles GET /health
func (hs *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		hs.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	status := hs.server.Status()
	health := struct {
		Healthy bool   `json:"healthy"`
		Reason  string `json:"reason,omitempty"`
	}{
		Healthy: status.KeyLoaded,
	}

	if !status.KeyLoaded {
		health.Reason = "master key not loaded"
	}

	statusCode := http.StatusOK
	if !health.Healthy {
		statusCode = http.StatusServiceUnavailable
	}

	hs.sendJSON(w, statusCode, health)
}

func (hs *HTTPServer) sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (hs *HTTPServer) sendError(w http.ResponseWriter, status int, message string) {
	hs.sendJSON(w, status, map[string]string{"error": message})
}

// GetKey returns the master key from the server (for proxy integration)
func (hs *HTTPServer) GetKey() ([]byte, error) {
	return hs.server.GetKey()
}

// Server returns the underlying memkey server
func (hs *HTTPServer) Server() *Server {
	return hs.server
}
