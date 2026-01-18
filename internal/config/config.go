// Package config handles configuration for s3-crypt-proxy.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the proxy.
type Config struct {
	// ListenAddr is the address for the S3 proxy endpoint
	ListenAddr string `yaml:"listen_addr"`

	// AdminListenAddr is the address for the admin API endpoint
	AdminListenAddr string `yaml:"admin_listen_addr"`

	// Backend configuration for the upstream S3 service
	Backend BackendConfig `yaml:"backend"`

	// Client credentials for authenticating incoming requests
	Client ClientConfig `yaml:"client"`

	// Encryption settings
	Encryption EncryptionConfig `yaml:"encryption"`

	// Admin API settings
	Admin AdminConfig `yaml:"admin"`

	// TLS configuration
	TLS TLSConfig `yaml:"tls"`

	// Memkey configuration for fetching encryption key
	Memkey MemkeyConfig `yaml:"memkey"`

	// AllowedBuckets is the list of buckets that clients can access
	// If empty, all buckets from backend are allowed (not recommended)
	// ListBuckets will return only these buckets
	AllowedBuckets []string `yaml:"allowed_buckets"`

	// Logging configuration
	LogLevel string `yaml:"log_level"`
}

// MemkeyConfig holds memkey server connection settings.
type MemkeyConfig struct {
	// SocketPath is the Unix socket path for local key fetch (recommended)
	// e.g., "/run/memkey/memkey.sock"
	SocketPath string `yaml:"socket_path"`

	// Endpoint is the memkey server URL (e.g., http://127.0.0.1:7070)
	// Only used for status checks, not for key fetch
	Endpoint string `yaml:"endpoint"`

	// PollInterval is how often to check for key availability (default 5s)
	PollInterval string `yaml:"poll_interval"`

	// InsecureSkipVerify skips TLS verification for memkey server
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// BackendConfig holds S3 backend connection settings.
type BackendConfig struct {
	// Endpoint is the S3 backend URL (e.g., https://s3.amazonaws.com)
	Endpoint string `yaml:"endpoint"`

	// Region is the S3 region
	Region string `yaml:"region"`

	// AccessKey for authenticating with the backend
	AccessKey string `yaml:"access_key"`

	// SecretKey for authenticating with the backend
	SecretKey string `yaml:"secret_key"`

	// PathStyle uses path-style bucket addressing if true
	PathStyle bool `yaml:"path_style"`

	// InsecureSkipVerify skips TLS verification (not recommended for production)
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// ClientConfig holds client authentication settings.
type ClientConfig struct {
	// AccessKey that clients must use
	AccessKey string `yaml:"access_key"`

	// SecretKey that clients must use
	SecretKey string `yaml:"secret_key"`
}

// EncryptionConfig holds encryption settings.
type EncryptionConfig struct {
	// ChunkSize is the encryption chunk size in bytes (default 4MB)
	ChunkSize int `yaml:"chunk_size"`
}

// AdminConfig holds admin API settings.
type AdminConfig struct {
	// Token is the bearer token for admin API authentication
	Token string `yaml:"token"`
}

// TLSConfig holds TLS settings.
type TLSConfig struct {
	// CertFile path to TLS certificate
	CertFile string `yaml:"cert_file"`

	// KeyFile path to TLS private key
	KeyFile string `yaml:"key_file"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:      ":8080",
		AdminListenAddr: ":8081",
		Backend: BackendConfig{
			Region:    "us-east-1",
			PathStyle: false,
		},
		Encryption: EncryptionConfig{
			ChunkSize: 4 * 1024 * 1024, // 4MB
		},
		Memkey: MemkeyConfig{
			SocketPath:   "/run/memkey/memkey.sock",
			PollInterval: "5s",
		},
		LogLevel: "info",
	}
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expanded := os.ExpandEnv(string(data))

	cfg := DefaultConfig()
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	if v := os.Getenv("S3CP_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("S3CP_ADMIN_LISTEN_ADDR"); v != "" {
		cfg.AdminListenAddr = v
	}

	// Backend settings
	if v := os.Getenv("S3CP_BACKEND_ENDPOINT"); v != "" {
		cfg.Backend.Endpoint = v
	}
	if v := os.Getenv("S3CP_BACKEND_REGION"); v != "" {
		cfg.Backend.Region = v
	}
	if v := os.Getenv("S3CP_BACKEND_ACCESS_KEY"); v != "" {
		cfg.Backend.AccessKey = v
	}
	if v := os.Getenv("S3CP_BACKEND_SECRET_KEY"); v != "" {
		cfg.Backend.SecretKey = v
	}
	if v := os.Getenv("S3CP_BACKEND_PATH_STYLE"); v != "" {
		cfg.Backend.PathStyle = parseBool(v)
	}
	if v := os.Getenv("S3CP_BACKEND_INSECURE"); v != "" {
		cfg.Backend.InsecureSkipVerify = parseBool(v)
	}

	// Client settings
	if v := os.Getenv("S3CP_CLIENT_ACCESS_KEY"); v != "" {
		cfg.Client.AccessKey = v
	}
	if v := os.Getenv("S3CP_CLIENT_SECRET_KEY"); v != "" {
		cfg.Client.SecretKey = v
	}

	// Encryption settings
	if v := os.Getenv("S3CP_CHUNK_SIZE"); v != "" {
		if size, err := strconv.Atoi(v); err == nil && size > 0 {
			cfg.Encryption.ChunkSize = size
		}
	}

	// Admin settings
	if v := os.Getenv("S3CP_ADMIN_TOKEN"); v != "" {
		cfg.Admin.Token = v
	}

	// TLS settings
	if v := os.Getenv("S3CP_TLS_CERT"); v != "" {
		cfg.TLS.CertFile = v
	}
	if v := os.Getenv("S3CP_TLS_KEY"); v != "" {
		cfg.TLS.KeyFile = v
	}

	// Memkey settings
	if v := os.Getenv("S3CP_MEMKEY_SOCKET"); v != "" {
		cfg.Memkey.SocketPath = v
	}
	if v := os.Getenv("S3CP_MEMKEY_ENDPOINT"); v != "" {
		cfg.Memkey.Endpoint = v
	}
	if v := os.Getenv("S3CP_MEMKEY_POLL_INTERVAL"); v != "" {
		cfg.Memkey.PollInterval = v
	}
	if v := os.Getenv("S3CP_MEMKEY_INSECURE"); v != "" {
		cfg.Memkey.InsecureSkipVerify = parseBool(v)
	}

	// Allowed buckets (comma-separated)
	if v := os.Getenv("S3CP_ALLOWED_BUCKETS"); v != "" {
		buckets := strings.Split(v, ",")
		for i := range buckets {
			buckets[i] = strings.TrimSpace(buckets[i])
		}
		cfg.AllowedBuckets = buckets
	}

	// Log level
	if v := os.Getenv("S3CP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	return cfg
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Backend.Endpoint == "" {
		return fmt.Errorf("backend endpoint is required")
	}
	if c.Backend.AccessKey == "" {
		return fmt.Errorf("backend access key is required")
	}
	if c.Backend.SecretKey == "" {
		return fmt.Errorf("backend secret key is required")
	}
	if c.Client.AccessKey == "" {
		return fmt.Errorf("client access key is required")
	}
	if c.Client.SecretKey == "" {
		return fmt.Errorf("client secret key is required")
	}
	if c.Admin.Token == "" {
		return fmt.Errorf("admin token is required")
	}
	if c.Encryption.ChunkSize <= 0 {
		return fmt.Errorf("chunk size must be positive")
	}
	if c.Encryption.ChunkSize > 64*1024*1024 {
		return fmt.Errorf("chunk size must not exceed 64MB")
	}

	// Validate TLS config - if one is set, both must be set
	if (c.TLS.CertFile != "" && c.TLS.KeyFile == "") ||
		(c.TLS.CertFile == "" && c.TLS.KeyFile != "") {
		return fmt.Errorf("both TLS cert and key must be provided together")
	}

	return nil
}

// TLSEnabled returns true if TLS is configured.
func (c *Config) TLSEnabled() bool {
	return c.TLS.CertFile != "" && c.TLS.KeyFile != ""
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}
