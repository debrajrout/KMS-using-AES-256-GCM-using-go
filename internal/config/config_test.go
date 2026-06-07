package config

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		MaxRequestBodyBytes:        1024,
		HTTPMaxHeaderBytes:         1024,
		RateLimitRequestsPerSecond: 10,
		RateLimitBurst:             20,
		HTTPReadHeaderTimeout:      time.Second,
		HTTPReadTimeout:            time.Second,
		HTTPWriteTimeout:           time.Second,
		HTTPIdleTimeout:            time.Second,
		HTTPShutdownTimeout:        time.Second,
		RequestTimeout:             time.Second,
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name       string
		change     func(*Config)
		wantErrMsg string
	}{
		{
			name:       "valid",
			change:     func(*Config) {},
			wantErrMsg: "",
		},
		{
			name:       "invalid body limit",
			change:     func(cfg *Config) { cfg.MaxRequestBodyBytes = 0 },
			wantErrMsg: "MAX_REQUEST_BODY_BYTES",
		},
		{
			name:       "invalid header limit",
			change:     func(cfg *Config) { cfg.HTTPMaxHeaderBytes = 0 },
			wantErrMsg: "HTTP_MAX_HEADER_BYTES",
		},
		{
			name:       "invalid request rate",
			change:     func(cfg *Config) { cfg.RateLimitRequestsPerSecond = 0 },
			wantErrMsg: "RATE_LIMIT_REQUESTS_PER_SECOND",
		},
		{
			name:       "invalid burst",
			change:     func(cfg *Config) { cfg.RateLimitBurst = 0 },
			wantErrMsg: "RATE_LIMIT_BURST",
		},
		{
			name:       "invalid timeout",
			change:     func(cfg *Config) { cfg.RequestTimeout = 0 },
			wantErrMsg: "REQUEST_TIMEOUT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.change(&cfg)

			err := cfg.Validate()
			if tt.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.wantErrMsg)
			}
		})
	}
}
