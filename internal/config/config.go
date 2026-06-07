package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type MasterKey struct {
	ID  string
	Key []byte
}

type Config struct {
	MongoURI                   string        `envconfig:"MONGO_URI" required:"true"`
	MongoDBName                string        `envconfig:"MONGO_DB_NAME" required:"true"`
	MongoUsersCollection       string        `envconfig:"MONGO_USERS_COLLECTION" required:"true"`
	FirebaseServiceAccountPath string        `envconfig:"FIREBASE_SERVICE_ACCOUNT_PATH" required:"true"`
	MasterKeys                 string        `envconfig:"MASTER_KEYS" required:"true"`
	TLSCertPath                string        `envconfig:"TLS_CERT_PATH" required:"true"`
	TLSKeyPath                 string        `envconfig:"TLS_KEY_PATH" required:"true"`
	MongoDEKCollection         string        `envconfig:"MONGO_DEK_COLLECTION" required:"true"`
	HTTPAddr                   string        `envconfig:"HTTP_ADDR" default:":8443"`
	HTTPReadHeaderTimeout      time.Duration `envconfig:"HTTP_READ_HEADER_TIMEOUT" default:"5s"`
	HTTPReadTimeout            time.Duration `envconfig:"HTTP_READ_TIMEOUT" default:"15s"`
	HTTPWriteTimeout           time.Duration `envconfig:"HTTP_WRITE_TIMEOUT" default:"30s"`
	HTTPIdleTimeout            time.Duration `envconfig:"HTTP_IDLE_TIMEOUT" default:"60s"`
	HTTPShutdownTimeout        time.Duration `envconfig:"HTTP_SHUTDOWN_TIMEOUT" default:"10s"`
	RequestTimeout             time.Duration `envconfig:"REQUEST_TIMEOUT" default:"15s"`
	MaxRequestBodyBytes        int64         `envconfig:"MAX_REQUEST_BODY_BYTES" default:"1048576"`
	HTTPMaxHeaderBytes         int           `envconfig:"HTTP_MAX_HEADER_BYTES" default:"1048576"`
	RateLimitRequestsPerSecond float64       `envconfig:"RATE_LIMIT_REQUESTS_PER_SECOND" default:"20"`
	RateLimitBurst             int           `envconfig:"RATE_LIMIT_BURST" default:"40"`
}

func LoadConfig() (*Config, error) {

	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found, relying on environment variables...")
	}

	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to process environment variables: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (cfg *Config) Validate() error {
	timeouts := map[string]time.Duration{
		"HTTP_READ_HEADER_TIMEOUT": cfg.HTTPReadHeaderTimeout,
		"HTTP_READ_TIMEOUT":        cfg.HTTPReadTimeout,
		"HTTP_WRITE_TIMEOUT":       cfg.HTTPWriteTimeout,
		"HTTP_IDLE_TIMEOUT":        cfg.HTTPIdleTimeout,
		"HTTP_SHUTDOWN_TIMEOUT":    cfg.HTTPShutdownTimeout,
		"REQUEST_TIMEOUT":          cfg.RequestTimeout,
	}
	for name, timeout := range timeouts {
		if timeout <= 0 {
			return fmt.Errorf("%s must be greater than zero", name)
		}
	}
	if cfg.MaxRequestBodyBytes <= 0 {
		return errors.New("MAX_REQUEST_BODY_BYTES must be greater than zero")
	}
	if cfg.HTTPMaxHeaderBytes <= 0 {
		return errors.New("HTTP_MAX_HEADER_BYTES must be greater than zero")
	}
	if cfg.RateLimitRequestsPerSecond <= 0 {
		return errors.New("RATE_LIMIT_REQUESTS_PER_SECOND must be greater than zero")
	}
	if cfg.RateLimitBurst <= 0 {
		return errors.New("RATE_LIMIT_BURST must be greater than zero")
	}
	return nil
}

func (cfg *Config) ParseMasterKeys() ([]MasterKey, error) {
	parts := strings.Split(cfg.MasterKeys, ",")
	var masterKeys []MasterKey
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			return nil, errors.New("invalid MASTER_KEYS format; expected id:base64key")
		}
		id := kv[0]
		keyBytes, err := base64.StdEncoding.DecodeString(kv[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 key for ID %s: %w", id, err)
		}
		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("master key for ID %s must be 32 bytes for AES-256", id)
		}
		masterKeys = append(masterKeys, MasterKey{
			ID:  id,
			Key: keyBytes,
		})
	}
	return masterKeys, nil
}
