// memkey-server holds the master encryption key in memory and provides it
// to the s3-crypt-proxy via a secure protocol.
//
// The server's Ed25519 identity is generated on first run and persisted.
// On each startup, the server logs its public key fingerprint which must
// be verified by the admin before sending the encryption key.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s3-crypt-proxy/internal/memkey"
	"gopkg.in/yaml.v3"
)

// Config holds the server configuration
type Config struct {
	Server struct {
		ListenAddr     string `yaml:"listen_addr"`
		TLSEnabled     bool   `yaml:"tls_enabled"`
		TLSCert        string `yaml:"tls_cert"`
		TLSKey         string `yaml:"tls_key"`
		UnixSocketPath string `yaml:"unix_socket_path"` // For local key access
	} `yaml:"server"`

	Identity struct {
		PrivateKey string `yaml:"private_key"` // Ed25519 seed, hex encoded
	} `yaml:"identity"`

	Security struct {
		ChallengeTimeout  string `yaml:"challenge_timeout"`
		MaxFailedAttempts int    `yaml:"max_failed_attempts"`
		LockoutDuration   string `yaml:"lockout_duration"`
	} `yaml:"security"`
}

func main() {
	configPath := flag.String("config", "/etc/s3-crypt-proxy/memkey.yaml", "Path to config file")
	printFingerprint := flag.Bool("print-fingerprint", false, "Print server fingerprint and exit")
	generateIdentity := flag.Bool("generate-identity", false, "Generate new identity and print seed")
	flag.Parse()

	// Generate identity mode
	if *generateIdentity {
		identity, err := memkey.NewServerIdentity()
		if err != nil {
			log.Fatalf("Failed to generate identity: %v", err)
		}
		fmt.Printf("# New server identity generated\n")
		fmt.Printf("# Fingerprint: %s\n", identity.Fingerprint())
		fmt.Printf("private_key: %s\n", identity.Seed())
		return
	}

	// Load config
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load or create identity
	var identity *memkey.ServerIdentity
	if config.Identity.PrivateKey != "" {
		identity, err = memkey.LoadServerIdentity(config.Identity.PrivateKey)
		if err != nil {
			log.Fatalf("Failed to load identity: %v", err)
		}
	} else {
		log.Println("No identity configured, generating new one...")
		identity, err = memkey.NewServerIdentity()
		if err != nil {
			log.Fatalf("Failed to generate identity: %v", err)
		}
		log.Printf("Generated new identity. Add this to your config to persist it:")
		log.Printf("  private_key: %s", identity.Seed())
	}

	// Print fingerprint mode
	if *printFingerprint {
		fmt.Println(identity.Fingerprint())
		return
	}

	// Parse durations
	challengeTimeout := 30 * time.Second
	if config.Security.ChallengeTimeout != "" {
		challengeTimeout, err = time.ParseDuration(config.Security.ChallengeTimeout)
		if err != nil {
			log.Fatalf("Invalid challenge_timeout: %v", err)
		}
	}

	lockoutDuration := 5 * time.Minute
	if config.Security.LockoutDuration != "" {
		lockoutDuration, err = time.ParseDuration(config.Security.LockoutDuration)
		if err != nil {
			log.Fatalf("Invalid lockout_duration: %v", err)
		}
	}

	maxFailedAttempts := config.Security.MaxFailedAttempts
	if maxFailedAttempts == 0 {
		maxFailedAttempts = 5
	}

	// Create memkey server
	server := memkey.NewServer(&memkey.ServerConfig{
		Identity:          identity,
		ChallengeTimeout:  challengeTimeout,
		MaxFailedAttempts: maxFailedAttempts,
		LockoutDuration:   lockoutDuration,
	})

	// Configure TLS
	var tlsConfig *tls.Config
	if config.Server.TLSEnabled {
		cert, err := tls.LoadX509KeyPair(config.Server.TLSCert, config.Server.TLSKey)
		if err != nil {
			log.Fatalf("Failed to load TLS certificate: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	// Create HTTP server
	httpServer := memkey.NewHTTPServer(&memkey.HTTPServerConfig{
		ListenAddr:     config.Server.ListenAddr,
		TLSConfig:      tlsConfig,
		Server:         server,
		UnixSocketPath: config.Server.UnixSocketPath,
	})

	// Start server
	log.Println("========================================")
	log.Println("        MEMKEY SERVER STARTING")
	log.Println("========================================")
	log.Printf("Listen address: %s", config.Server.ListenAddr)
	log.Printf("TLS enabled: %v", config.Server.TLSEnabled)
	if config.Server.UnixSocketPath != "" {
		log.Printf("Unix socket: %s", config.Server.UnixSocketPath)
	}
	log.Println("----------------------------------------")
	log.Printf("SERVER FINGERPRINT: %s", identity.Fingerprint())
	log.Printf("SHORT FINGERPRINT:  %s", identity.ShortFingerprint())
	log.Println("----------------------------------------")
	log.Println("Verify this fingerprint before sending the encryption key!")
	log.Println("========================================")

	if err := httpServer.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	log.Println("Server started, waiting for key delivery...")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Server stopped")
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config
			return &Config{
				Server: struct {
					ListenAddr     string `yaml:"listen_addr"`
					TLSEnabled     bool   `yaml:"tls_enabled"`
					TLSCert        string `yaml:"tls_cert"`
					TLSKey         string `yaml:"tls_key"`
					UnixSocketPath string `yaml:"unix_socket_path"`
				}{
					ListenAddr:     "127.0.0.1:7070",
					UnixSocketPath: "/run/memkey/memkey.sock",
				},
			}, nil
		}
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	// Set defaults
	if config.Server.ListenAddr == "" {
		config.Server.ListenAddr = "127.0.0.1:7070"
	}

	return &config, nil
}
