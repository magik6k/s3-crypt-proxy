// s3-crypt-proxy is a stateless S3 encryption proxy designed for Proxmox Backup Server.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s3-crypt-proxy/internal/admin"
	"github.com/s3-crypt-proxy/internal/auth"
	"github.com/s3-crypt-proxy/internal/config"
	"github.com/s3-crypt-proxy/internal/crypto"
	"github.com/s3-crypt-proxy/internal/metrics"
	"github.com/s3-crypt-proxy/internal/proxy"
	"github.com/s3-crypt-proxy/internal/s3client"
)

var (
	configFile = flag.String("config", "", "Path to configuration file (optional)")
	version    = flag.Bool("version", false, "Print version and exit")
)

const appVersion = "1.0.0"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("s3-crypt-proxy version %s\n", appVersion)
		os.Exit(0)
	}

	// Setup logging
	logLevel := slog.LevelInfo
	if lvl := os.Getenv("S3CP_LOG_LEVEL"); lvl == "debug" {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Load configuration
	var cfg *config.Config
	var err error

	if *configFile != "" {
		cfg, err = config.LoadFromFile(*configFile)
		if err != nil {
			logger.Error("failed to load config file", "error", err)
			os.Exit(1)
		}
	} else {
		cfg = config.LoadFromEnv()
	}

	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// Initialize components
	logger.Info("starting s3-crypt-proxy",
		"version", appVersion,
		"listen_addr", cfg.ListenAddr,
		"admin_addr", cfg.AdminListenAddr,
		"backend", cfg.Backend.Endpoint)

	// Create metrics
	m := metrics.New()

	// Create key manager
	km := crypto.NewKeyManager()

	// Create S3 backend client
	backend := s3client.NewClient(s3client.ClientOptions{
		Endpoint:           cfg.Backend.Endpoint,
		Region:             cfg.Backend.Region,
		AccessKey:          cfg.Backend.AccessKey,
		SecretKey:          cfg.Backend.SecretKey,
		PathStyle:          cfg.Backend.PathStyle,
		InsecureSkipVerify: cfg.Backend.InsecureSkipVerify,
	})

	// Create client authenticator
	clientAuth := auth.NewAuthenticator(cfg.Client.AccessKey, cfg.Client.SecretKey)

	// Create proxy
	p := proxy.NewProxy(proxy.ProxyOptions{
		Backend:   backend,
		KeyMgr:    km,
		Auth:      clientAuth,
		Metrics:   m,
		ChunkSize: cfg.Encryption.ChunkSize,
		Logger:    logger,
	})

	// Create admin server
	adminServer := admin.NewServer(km, cfg.Admin.Token, m)

	// Setup HTTP servers
	proxyServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      p,
		ReadTimeout:  30 * time.Minute,
		WriteTimeout: 30 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	adminHTTPServer := &http.Server{
		Addr:         cfg.AdminListenAddr,
		Handler:      adminServer,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start servers
	errChan := make(chan error, 2)

	go func() {
		logger.Info("starting S3 proxy server", "addr", cfg.ListenAddr)
		if cfg.TLSEnabled() {
			errChan <- proxyServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			errChan <- proxyServer.ListenAndServe()
		}
	}()

	go func() {
		logger.Info("starting admin server", "addr", cfg.AdminListenAddr)
		// Admin server always uses plain HTTP (should be behind firewall/localhost)
		errChan <- adminHTTPServer.ListenAndServe()
	}()

	// Start memkey poller if configured
	var memkeyCancel context.CancelFunc
	if cfg.Memkey.Endpoint != "" {
		var memkeyCtx context.Context
		memkeyCtx, memkeyCancel = context.WithCancel(context.Background())

		pollInterval := 5 * time.Second
		if d, err := time.ParseDuration(cfg.Memkey.PollInterval); err == nil {
			pollInterval = d
		}

		go pollMemkey(memkeyCtx, cfg.Memkey.Endpoint, cfg.Memkey.InsecureSkipVerify, km, m, pollInterval, logger)
		logger.Info("memkey poller started", "endpoint", cfg.Memkey.Endpoint, "interval", pollInterval)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		if err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	case sig := <-sigChan:
		logger.Info("received shutdown signal", "signal", sig)
	}

	// Stop memkey poller
	if memkeyCancel != nil {
		memkeyCancel()
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger.Info("shutting down servers...")

	if err := proxyServer.Shutdown(ctx); err != nil {
		logger.Error("proxy server shutdown error", "error", err)
	}

	if err := adminHTTPServer.Shutdown(ctx); err != nil {
		logger.Error("admin server shutdown error", "error", err)
	}

	// Clear key from memory on shutdown
	km.ClearKey()

	logger.Info("shutdown complete")
}

// pollMemkey periodically fetches the encryption key from the memkey server
func pollMemkey(ctx context.Context, endpoint string, insecure bool, km *crypto.KeyManager, m *metrics.Metrics, interval time.Duration, logger *slog.Logger) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			// #nosec G402 - InsecureSkipVerify is configurable for self-signed certs
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure, //nolint:gosec
			},
		},
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Try immediately on start
	fetchKey(client, endpoint, km, m, logger)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !km.IsLoaded() {
				fetchKey(client, endpoint, km, m, logger)
			}
		}
	}
}

func fetchKey(client *http.Client, endpoint string, km *crypto.KeyManager, m *metrics.Metrics, logger *slog.Logger) {
	// Check memkey server status
	resp, err := client.Get(endpoint + "/status")
	if err != nil {
		logger.Debug("memkey server not reachable", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Debug("memkey server returned error", "status", resp.StatusCode)
		return
	}

	var status struct {
		KeyLoaded bool `json:"key_loaded"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("failed to read memkey status", "error", err)
		return
	}

	if err := json.Unmarshal(body, &status); err != nil {
		logger.Debug("failed to parse memkey status", "error", err)
		return
	}

	if !status.KeyLoaded {
		logger.Debug("memkey server has no key loaded")
		return
	}

	// Fetch the key
	keyResp, err := client.Get(endpoint + "/key/raw")
	if err != nil {
		logger.Debug("failed to fetch key from memkey", "error", err)
		return
	}
	defer keyResp.Body.Close()

	if keyResp.StatusCode != http.StatusOK {
		logger.Debug("memkey key fetch failed", "status", keyResp.StatusCode)
		return
	}

	keyData, err := io.ReadAll(keyResp.Body)
	if err != nil {
		logger.Debug("failed to read key data", "error", err)
		return
	}

	if len(keyData) != 32 {
		logger.Error("invalid key size from memkey", "size", len(keyData))
		return
	}

	if err := km.LoadKey(keyData); err != nil {
		logger.Error("failed to load key", "error", err)
		return
	}

	m.SetKeyLoaded(true)
	logger.Info("encryption key loaded from memkey server")
}
