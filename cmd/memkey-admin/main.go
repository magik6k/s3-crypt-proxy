// memkey-admin is a CLI tool for managing encryption keys on s3-crypt-proxy servers.
//
// Usage:
//
//	memkey-admin init --server https://server:7070 --fingerprint <fingerprint>
//	memkey-admin key generate
//	memkey-admin key import --file master.key
//	memkey-admin key send
//	memkey-admin status
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s3-crypt-proxy/internal/memkey"
)

const (
	configFileName = ".memkey-admin.json"
	keyFileName    = ".memkey-master.key"
)

// Config holds the admin tool configuration
type Config struct {
	// ServerURL is the memkey server URL
	ServerURL string `json:"server_url"`

	// ExpectedFingerprint is the expected server fingerprint
	ExpectedFingerprint string `json:"expected_fingerprint"`

	// SkipTLSVerify disables TLS certificate verification
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`

	// KeyFile is the path to the master key file
	KeyFile string `json:"key_file,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "key":
		if len(args) < 1 {
			fmt.Println("Usage: memkey-admin key <generate|import|send|show>")
			os.Exit(1)
		}
		switch args[0] {
		case "generate":
			err = cmdKeyGenerate(args[1:])
		case "import":
			err = cmdKeyImport(args[1:])
		case "send":
			err = cmdKeySend(args[1:])
		case "show":
			err = cmdKeyShow(args[1:])
		default:
			fmt.Printf("Unknown key command: %s\n", args[0])
			os.Exit(1)
		}
	case "status":
		err = cmdStatus(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`memkey-admin - Encryption key management tool for s3-crypt-proxy

USAGE:
    memkey-admin <command> [options]

COMMANDS:
    init        Initialize configuration with server details
    key         Key management commands
    status      Show server status

KEY COMMANDS:
    key generate    Generate a new master key
    key import      Import a master key from file
    key send        Send the master key to the server
    key show        Show master key fingerprint

INIT OPTIONS:
    --server <url>          Server URL (e.g., https://server:7070)
    --fingerprint <fp>      Expected server fingerprint (64 hex chars)
    --skip-tls-verify       Skip TLS certificate verification
    --config <path>         Config file path (default: ~/.memkey-admin.json)

KEY IMPORT OPTIONS:
    --file <path>           Path to key file (32 bytes, raw or hex)

EXAMPLES:
    # Initialize with server fingerprint (get from server logs)
    memkey-admin init --server https://192.168.1.100:7070 \
        --fingerprint abc123...

    # Generate a new master key
    memkey-admin key generate

    # Send the key to the server
    memkey-admin key send

    # Check server status
    memkey-admin status

SECURITY:
    - The master key is stored encrypted in ~/.memkey-master.key
    - Server identity is verified using Ed25519 signatures
    - Key transmission uses X25519 ECDH for Perfect Forward Secrecy
    - Always verify the server fingerprint from a trusted source`)
}

func cmdInit(args []string) error {
	var serverURL, fingerprint, configPath string
	var skipTLS bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--server":
			if i+1 >= len(args) {
				return fmt.Errorf("--server requires a value")
			}
			i++
			serverURL = args[i]
		case "--fingerprint":
			if i+1 >= len(args) {
				return fmt.Errorf("--fingerprint requires a value")
			}
			i++
			fingerprint = args[i]
		case "--skip-tls-verify":
			skipTLS = true
		case "--config":
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a value")
			}
			i++
			configPath = args[i]
		default:
			return fmt.Errorf("unknown option: %s", args[i])
		}
	}

	if serverURL == "" {
		return fmt.Errorf("--server is required")
	}
	if fingerprint == "" {
		return fmt.Errorf("--fingerprint is required")
	}

	// Validate fingerprint format
	fingerprint = strings.ToLower(fingerprint)
	if len(fingerprint) != 64 {
		return fmt.Errorf("fingerprint must be 64 hex characters (got %d)", len(fingerprint))
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return fmt.Errorf("invalid fingerprint: %v", err)
	}

	// Determine config path
	if configPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home dir: %v", err)
		}
		configPath = filepath.Join(home, configFileName)
	}

	// Determine key file path
	keyPath := filepath.Join(filepath.Dir(configPath), keyFileName)

	config := &Config{
		ServerURL:           serverURL,
		ExpectedFingerprint: fingerprint,
		SkipTLSVerify:       skipTLS,
		KeyFile:             keyPath,
	}

	// Test connection and verify fingerprint
	fmt.Printf("Testing connection to %s...\n", serverURL)

	client := createHTTPClient(config)
	resp, err := client.Get(serverURL + "/status")
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer resp.Body.Close()

	var status memkey.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("invalid response: %v", err)
	}

	// Verify fingerprint matches
	if status.ServerFingerprint != fingerprint {
		return fmt.Errorf("SECURITY WARNING: Server fingerprint mismatch!\n"+
			"  Expected: %s\n"+
			"  Got:      %s\n"+
			"This could indicate a man-in-the-middle attack.",
			fingerprint, status.ServerFingerprint)
	}

	// Save config
	data, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}

	fmt.Printf("Configuration saved to %s\n", configPath)
	fmt.Printf("Server fingerprint verified: %s\n", fingerprint[:16]+"...")
	fmt.Printf("Key loaded on server: %v\n", status.KeyLoaded)

	return nil
}

func cmdKeyGenerate(args []string) error {
	config, err := loadConfig("")
	if err != nil {
		return err
	}

	// Check if key already exists
	if _, err := os.Stat(config.KeyFile); err == nil {
		fmt.Printf("Key file already exists: %s\n", config.KeyFile)
		fmt.Print("Overwrite? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Generate key
	key := make([]byte, memkey.MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %v", err)
	}

	// Save key (hex encoded for safety)
	hexKey := hex.EncodeToString(key)
	if err := os.WriteFile(config.KeyFile, []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("failed to save key: %v", err)
	}

	fingerprint := memkey.CalculateKeyFingerprint(key)

	fmt.Printf("Master key generated and saved to %s\n", config.KeyFile)
	fmt.Printf("Key fingerprint: %s\n", fingerprint)
	fmt.Println("\nIMPORTANT: Back up this key securely. If lost, encrypted data cannot be recovered.")

	return nil
}

func cmdKeyImport(args []string) error {
	var filePath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("--file requires a value")
			}
			i++
			filePath = args[i]
		default:
			return fmt.Errorf("unknown option: %s", args[i])
		}
	}

	if filePath == "" {
		return fmt.Errorf("--file is required")
	}

	config, err := loadConfig("")
	if err != nil {
		return err
	}

	// Read key file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	var key []byte

	// Try hex decode first
	data = bytes.TrimSpace(data)
	if len(data) == 64 {
		key, err = hex.DecodeString(string(data))
		if err != nil {
			return fmt.Errorf("invalid hex key: %v", err)
		}
	} else if len(data) == 32 {
		// Raw binary
		key = data
	} else {
		return fmt.Errorf("invalid key size: expected 32 bytes (raw) or 64 chars (hex), got %d", len(data))
	}

	// Save to our key file
	hexKey := hex.EncodeToString(key)
	if err := os.WriteFile(config.KeyFile, []byte(hexKey), 0600); err != nil {
		return fmt.Errorf("failed to save key: %v", err)
	}

	fingerprint := memkey.CalculateKeyFingerprint(key)

	fmt.Printf("Key imported and saved to %s\n", config.KeyFile)
	fmt.Printf("Key fingerprint: %s\n", fingerprint)

	return nil
}

func cmdKeySend(args []string) error {
	config, err := loadConfig("")
	if err != nil {
		return err
	}

	// Load key
	key, err := loadKey(config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load key: %v\nRun 'memkey-admin key generate' first", err)
	}

	keyFingerprint := memkey.CalculateKeyFingerprint(key)
	fmt.Printf("Loaded key with fingerprint: %s\n", keyFingerprint)

	// Create client
	client := memkey.NewClient(config.ExpectedFingerprint)
	httpClient := createHTTPClient(config)

	// 1. Get challenge
	fmt.Printf("Requesting challenge from %s...\n", config.ServerURL)

	challengeResp, err := httpClient.Get(config.ServerURL + "/challenge")
	if err != nil {
		return fmt.Errorf("failed to get challenge: %v", err)
	}
	defer challengeResp.Body.Close()

	if challengeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(challengeResp.Body)
		return fmt.Errorf("challenge request failed: %s", string(body))
	}

	var challenge memkey.ChallengeResponse
	if err := json.NewDecoder(challengeResp.Body).Decode(&challenge); err != nil {
		return fmt.Errorf("invalid challenge response: %v", err)
	}

	// 2. Verify server identity
	fmt.Println("Verifying server identity...")

	if err := client.VerifyChallenge(&challenge); err != nil {
		if err == memkey.ErrFingerprintMismatch {
			return fmt.Errorf("SECURITY WARNING: Server fingerprint mismatch!\n" +
				"The server identity does not match the expected fingerprint.\n" +
				"This could indicate a man-in-the-middle attack.\n" +
				"Run 'memkey-admin init' to update the expected fingerprint if this is intentional.")
		}
		return fmt.Errorf("server verification failed: %v", err)
	}

	fmt.Println("Server identity verified.")

	// 3. Prepare key delivery
	fmt.Println("Encrypting key for transmission...")

	deliveryReq, err := client.PrepareKeyDelivery(&challenge, key)
	if err != nil {
		return fmt.Errorf("failed to prepare key: %v", err)
	}

	// 4. Send key
	fmt.Println("Sending key to server...")

	body, _ := json.Marshal(deliveryReq)
	keyResp, err := httpClient.Post(config.ServerURL+"/key", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to send key: %v", err)
	}
	defer keyResp.Body.Close()

	if keyResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(keyResp.Body)
		return fmt.Errorf("key delivery failed: %s", string(respBody))
	}

	var delivery memkey.KeyDeliveryResponse
	if err := json.NewDecoder(keyResp.Body).Decode(&delivery); err != nil {
		return fmt.Errorf("invalid delivery response: %v", err)
	}

	if !delivery.Success {
		return fmt.Errorf("key delivery failed: %s", delivery.Message)
	}

	// 5. Verify fingerprint matches
	if delivery.KeyFingerprint != keyFingerprint {
		return fmt.Errorf("key fingerprint mismatch after delivery!\n"+
			"  Sent:     %s\n"+
			"  Received: %s\n"+
			"This should not happen and may indicate a bug.",
			keyFingerprint, delivery.KeyFingerprint)
	}

	fmt.Printf("\nKey delivered successfully!\n")
	fmt.Printf("Key fingerprint: %s\n", delivery.KeyFingerprint)
	fmt.Println("\nThe s3-crypt-proxy server is now ready to handle encryption.")

	return nil
}

func cmdKeyShow(args []string) error {
	config, err := loadConfig("")
	if err != nil {
		return err
	}

	key, err := loadKey(config.KeyFile)
	if err != nil {
		return fmt.Errorf("no key found: %v\nRun 'memkey-admin key generate' first", err)
	}

	fingerprint := memkey.CalculateKeyFingerprint(key)
	fullHash := sha256.Sum256(key)

	fmt.Printf("Key file: %s\n", config.KeyFile)
	fmt.Printf("Key fingerprint (short): %s\n", fingerprint)
	fmt.Printf("Key fingerprint (full):  %s\n", hex.EncodeToString(fullHash[:]))
	fmt.Printf("Key size: %d bytes\n", len(key))

	return nil
}

func cmdStatus(args []string) error {
	config, err := loadConfig("")
	if err != nil {
		return err
	}

	client := createHTTPClient(config)

	resp, err := client.Get(config.ServerURL + "/status")
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer resp.Body.Close()

	var status memkey.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return fmt.Errorf("invalid response: %v", err)
	}

	fmt.Printf("Server: %s\n", config.ServerURL)
	fmt.Printf("Server fingerprint: %s\n", status.ServerFingerprint[:16]+"...")

	// Verify fingerprint
	if status.ServerFingerprint == config.ExpectedFingerprint {
		fmt.Println("Fingerprint: VERIFIED")
	} else {
		fmt.Println("Fingerprint: MISMATCH (warning!)")
	}

	fmt.Printf("Key loaded: %v\n", status.KeyLoaded)
	if status.KeyLoaded {
		loadedAt := time.Unix(status.KeyLoadedAt, 0)
		fmt.Printf("Key loaded at: %s\n", loadedAt.Format(time.RFC3339))
	}

	fmt.Printf("Server uptime: %s\n", formatDuration(time.Duration(status.Uptime)*time.Second))

	if status.LockedOut {
		lockoutEnds := time.Unix(status.LockoutEndsAt, 0)
		fmt.Printf("LOCKED OUT until: %s\n", lockoutEnds.Format(time.RFC3339))
	}

	// Also check health
	healthResp, err := client.Get(config.ServerURL + "/health")
	if err == nil {
		defer healthResp.Body.Close()
		if healthResp.StatusCode == http.StatusOK {
			fmt.Println("Health: HEALTHY")
		} else {
			fmt.Println("Health: UNHEALTHY (key not loaded)")
		}
	}

	return nil
}

func loadConfig(path string) (*Config, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home dir: %v", err)
		}
		path = filepath.Join(home, configFileName)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config not found at %s\nRun 'memkey-admin init' first", path)
		}
		return nil, fmt.Errorf("failed to read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	return &config, nil
}

func loadKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	data = bytes.TrimSpace(data)

	// Try hex decode
	if len(data) == 64 {
		return hex.DecodeString(string(data))
	}

	// Raw binary
	if len(data) == 32 {
		return data, nil
	}

	return nil, fmt.Errorf("invalid key size: %d", len(data))
}

func createHTTPClient(config *Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
