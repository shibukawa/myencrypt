package config

import (
	"os"
	"testing"
)

func TestLoadFromEnvHostname(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "hostname set",
			envValue: "myencrypt.local",
			expected: "myencrypt.local",
		},
		{
			name:     "localhost hostname",
			envValue: "localhost",
			expected: "localhost",
		},
		{
			name:     "custom domain hostname",
			envValue: "acme.example.com",
			expected: "acme.example.com",
		},
		{
			name:     "empty hostname",
			envValue: "",
			expected: "", // Default value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv("MYENCRYPT_HOSTNAME")

			// Set environment variable if not empty
			if tt.envValue != "" {
				os.Setenv("MYENCRYPT_HOSTNAME", tt.envValue)
				defer os.Unsetenv("MYENCRYPT_HOSTNAME")
			}

			// Load configuration from environment
			cfg := LoadFromEnv()

			if cfg.Hostname != tt.expected {
				t.Errorf("LoadFromEnv() Hostname = %v, want %v", cfg.Hostname, tt.expected)
			}
		})
	}
}

func TestLoadFromEnvForDockerHostname(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "hostname set in docker mode",
			envValue: "myencrypt.local",
			expected: "myencrypt.local",
		},
		{
			name:     "localhost hostname in docker mode",
			envValue: "localhost",
			expected: "localhost",
		},
		{
			name:     "empty hostname in docker mode",
			envValue: "",
			expected: "", // Default value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv("MYENCRYPT_HOSTNAME")
			os.Unsetenv("MYENCRYPT_EXPOSE_PORT")
			os.Unsetenv("MYENCRYPT_PROJECT_NAME")

			// Set required Docker environment variables
			os.Setenv("MYENCRYPT_EXPOSE_PORT", "14000")
			os.Setenv("MYENCRYPT_PROJECT_NAME", "test-project")
			defer func() {
				os.Unsetenv("MYENCRYPT_EXPOSE_PORT")
				os.Unsetenv("MYENCRYPT_PROJECT_NAME")
			}()

			// Set hostname environment variable if not empty
			if tt.envValue != "" {
				os.Setenv("MYENCRYPT_HOSTNAME", tt.envValue)
				defer os.Unsetenv("MYENCRYPT_HOSTNAME")
			}

			// Load configuration from environment for Docker
			cfg, err := LoadFromEnvForDocker()
			if err != nil {
				t.Fatalf("LoadFromEnvForDocker() error = %v", err)
			}

			if cfg.Hostname != tt.expected {
				t.Errorf("LoadFromEnvForDocker() Hostname = %v, want %v", cfg.Hostname, tt.expected)
			}
		})
	}
}

func TestLoadWithEnvOverridesHostname(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "hostname override",
			envValue: "override.example.com",
			expected: "override.example.com",
		},
		{
			name:     "localhost override",
			envValue: "localhost",
			expected: "localhost",
		},
		{
			name:     "empty hostname uses default",
			envValue: "",
			expected: "", // Default value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			os.Unsetenv("MYENCRYPT_HOSTNAME")

			// Set environment variable if not empty
			if tt.envValue != "" {
				os.Setenv("MYENCRYPT_HOSTNAME", tt.envValue)
				defer os.Unsetenv("MYENCRYPT_HOSTNAME")
			}

			// Load configuration with environment overrides
			cfg, err := LoadWithEnvOverrides()
			if err != nil {
				t.Fatalf("LoadWithEnvOverrides() error = %v", err)
			}

			if cfg.Hostname != tt.expected {
				t.Errorf("LoadWithEnvOverrides() Hostname = %v, want %v", cfg.Hostname, tt.expected)
			}
		})
	}
}
