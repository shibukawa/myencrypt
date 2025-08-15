/*
MyEncrypt - Local ACME Certificate Authority
Copyright (C) 2025 Yoshiki Shibukawa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	HTTPPort    int    `yaml:"http_port"`
	BindAddress string `yaml:"bind_address"`
	Hostname    string `yaml:"hostname"` // ACME directory endpointで使用するホスト名

	// Certificate configuration
	IndividualCertTTL time.Duration `yaml:"individual_cert_ttl"`
	CACertTTL         time.Duration `yaml:"ca_cert_ttl"`

	// Domain configuration
	DefaultAllowedDomains []string `yaml:"default_allowed_domains"`
	AdditionalDomains     []string `yaml:"additional_domains"`

	// Storage configuration
	CertStorePath string `yaml:"cert_store_path"`
	DatabasePath  string `yaml:"database_path"`

	// Service configuration
	ServiceName        string `yaml:"service_name"`
	ServiceDisplayName string `yaml:"service_display_name"`
	ServiceDescription string `yaml:"service_description"`
	RunMode            string `yaml:"run_mode"`

	// Auto-renewal configuration
	AutoRenewal     bool          `yaml:"auto_renewal"`
	RenewalInterval time.Duration `yaml:"renewal_interval"`

	// Internal flags
	AutoInit bool `yaml:"-"` // Not saved to YAML, used for Docker mode
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fallback to home directory
		homeDir, _ := os.UserHomeDir()
		configDir = homeDir
	}

	// Default certificate store path
	certStorePath := filepath.Join(configDir, "myencrypt")

	return &Config{
		// Server defaults
		HTTPPort:    14000,
		BindAddress: "0.0.0.0",
		Hostname:    "", // 空の場合は自動検出

		// Certificate defaults
		IndividualCertTTL: 7 * 24 * time.Hour,   // 7 days
		CACertTTL:         800 * 24 * time.Hour, // 800 days

		// Domain defaults (same as mkcert)
		DefaultAllowedDomains: []string{
			"localhost",
			"*.localhost",
			"*.test",
			"*.example",
			"*.invalid",
		},
		AdditionalDomains: []string{},

		// Storage defaults
		CertStorePath: certStorePath,
		DatabasePath:  "", // Will be set to CertStorePath/myencrypt.db if empty

		// Service defaults
		ServiceName:        "myencrypt",
		ServiceDisplayName: "MyEncrypt ACME Server",
		ServiceDescription: "Local ACME certificate authority for development",
		RunMode:            "service",

		// Auto-renewal defaults
		AutoRenewal:     true,
		RenewalInterval: time.Hour,

		// Internal defaults
		AutoInit: false,
	}
}

// Load loads configuration from file or returns default configuration
func Load() (*Config, error) {
	cfg := DefaultConfig()

	configPath := filepath.Join(cfg.CertStorePath, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	return cfg, nil
}

// Save saves the configuration to file
func (c *Config) Save() error {
	// Ensure directory exists
	if err := os.MkdirAll(c.CertStorePath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	configPath := filepath.Join(c.CertStorePath, "config.yaml")
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// InitializeConfigFile creates a default config.yaml file if it doesn't exist
func (c *Config) InitializeConfigFile() error {
	configPath := filepath.Join(c.CertStorePath, "config.yaml")

	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // File already exists, nothing to do
	}

	// Ensure directory exists
	if err := os.MkdirAll(c.CertStorePath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save the current configuration as the default
	return c.Save()
}

// GetConfigFilePath returns the path to the config.yaml file
func (c *Config) GetConfigFilePath() string {
	return filepath.Join(c.CertStorePath, "config.yaml")
}

// GetCertStorePath returns the certificate storage path
func (c *Config) GetCertStorePath() string {
	return c.CertStorePath
}

// GetDatabasePath returns the database file path
func (c *Config) GetDatabasePath() string {
	if c.DatabasePath != "" {
		return c.DatabasePath
	}
	return filepath.Join(c.CertStorePath, "myencrypt.db")
}

// GetAllowedDomains returns all allowed domains (default + additional)
func (c *Config) GetAllowedDomains() []string {
	domains := make([]string, 0, len(c.DefaultAllowedDomains)+len(c.AdditionalDomains))
	domains = append(domains, c.DefaultAllowedDomains...)
	domains = append(domains, c.AdditionalDomains...)
	return domains
}

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s' (value: %v): %s", e.Field, e.Value, e.Message)
}

// Validate validates the configuration values
func (c *Config) Validate() error {
	var errors []ValidationError

	// Validate HTTP port
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		errors = append(errors, ValidationError{
			Field:   "http_port",
			Value:   c.HTTPPort,
			Message: "must be between 1 and 65535",
		})
	}

	// Validate bind address
	if strings.TrimSpace(c.BindAddress) == "" {
		errors = append(errors, ValidationError{
			Field:   "bind_address",
			Value:   c.BindAddress,
			Message: "cannot be empty",
		})
	}

	// Validate certificate TTL values
	if c.IndividualCertTTL <= 0 {
		errors = append(errors, ValidationError{
			Field:   "individual_cert_ttl",
			Value:   c.IndividualCertTTL,
			Message: "must be positive duration",
		})
	}

	if c.CACertTTL <= 0 {
		errors = append(errors, ValidationError{
			Field:   "ca_cert_ttl",
			Value:   c.CACertTTL,
			Message: "must be positive duration",
		})
	}

	// Validate storage paths
	if strings.TrimSpace(c.CertStorePath) == "" {
		errors = append(errors, ValidationError{
			Field:   "cert_store_path",
			Value:   c.CertStorePath,
			Message: "cannot be empty",
		})
	}

	// Validate service configuration
	if strings.TrimSpace(c.ServiceName) == "" {
		errors = append(errors, ValidationError{
			Field:   "service_name",
			Value:   c.ServiceName,
			Message: "cannot be empty",
		})
	}

	if strings.TrimSpace(c.ServiceDisplayName) == "" {
		errors = append(errors, ValidationError{
			Field:   "service_display_name",
			Value:   c.ServiceDisplayName,
			Message: "cannot be empty",
		})
	}

	if strings.TrimSpace(c.ServiceDescription) == "" {
		errors = append(errors, ValidationError{
			Field:   "service_description",
			Value:   c.ServiceDescription,
			Message: "cannot be empty",
		})
	}

	// Validate run mode
	validRunModes := []string{"service", "docker", "standalone"}
	validMode := false
	for _, mode := range validRunModes {
		if c.RunMode == mode {
			validMode = true
			break
		}
	}
	if !validMode {
		errors = append(errors, ValidationError{
			Field:   "run_mode",
			Value:   c.RunMode,
			Message: fmt.Sprintf("must be one of: %s", strings.Join(validRunModes, ", ")),
		})
	}

	// Validate renewal interval
	if c.RenewalInterval <= 0 {
		errors = append(errors, ValidationError{
			Field:   "renewal_interval",
			Value:   c.RenewalInterval,
			Message: "must be positive duration",
		})
	}

	// Validate TTL relationships
	if c.IndividualCertTTL > c.CACertTTL {
		errors = append(errors, ValidationError{
			Field:   "individual_cert_ttl",
			Value:   c.IndividualCertTTL,
			Message: "individual certificate TTL cannot be longer than CA certificate TTL",
		})
	}

	// Validate renewal interval is reasonable
	if c.RenewalInterval > c.IndividualCertTTL/2 {
		errors = append(errors, ValidationError{
			Field:   "renewal_interval",
			Value:   c.RenewalInterval,
			Message: "renewal interval should be less than half of individual certificate TTL",
		})
	}

	// Validate certificate store path accessibility
	if err := c.validateCertStorePath(); err != nil {
		errors = append(errors, ValidationError{
			Field:   "cert_store_path",
			Value:   c.CertStorePath,
			Message: err.Error(),
		})
	}

	if len(errors) > 0 {
		// Return the first error for simplicity
		return errors[0]
	}

	return nil
}

// validateCertStorePath validates that the certificate storage path is accessible
func (c *Config) validateCertStorePath() error {
	// Expand tilde if present
	path := c.CertStorePath
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot expand home directory: %w", err)
		}
		path = filepath.Join(homeDir, path[2:])
	}

	// Check if path exists or can be created
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Try to create the directory
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("cannot create directory: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}

	// Check if directory is writable
	testFile := filepath.Join(path, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("directory is not writable: %w", err)
	}
	os.Remove(testFile) // Clean up test file

	return nil
}

// LoadFromEnvironment loads configuration from environment variables only
// This is the centralized place for all environment variable processing
func LoadFromEnvironment() *Config {
	cfg := DefaultConfig()

	// Server configuration
	if port := os.Getenv("MYENCRYPT_HTTP_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.HTTPPort = p
		}
	}

	if addr := os.Getenv("MYENCRYPT_BIND_ADDRESS"); addr != "" {
		cfg.BindAddress = addr
	}

	if hostname := os.Getenv("MYENCRYPT_HOSTNAME"); hostname != "" {
		cfg.Hostname = hostname
	}

	// Certificate configuration
	if ttl := os.Getenv("MYENCRYPT_INDIVIDUAL_CERT_TTL"); ttl != "" {
		if duration, err := time.ParseDuration(ttl); err == nil {
			cfg.IndividualCertTTL = duration
		}
	}

	if ttl := os.Getenv("MYENCRYPT_CA_CERT_TTL"); ttl != "" {
		if duration, err := time.ParseDuration(ttl); err == nil {
			cfg.CACertTTL = duration
		}
	}

	// Domain configuration
	if domains := os.Getenv("MYENCRYPT_ALLOWED_DOMAINS"); domains != "" {
		cfg.DefaultAllowedDomains = parseDomainsFromString(domains)
		cfg.AdditionalDomains = []string{} // Clear additional domains when env is set
	}

	// Storage configuration
	if path := os.Getenv("MYENCRYPT_CERT_STORE_PATH"); path != "" {
		cfg.CertStorePath = path
	}

	if path := os.Getenv("MYENCRYPT_DATABASE_PATH"); path != "" {
		cfg.DatabasePath = path
	}

	// Auto renewal configuration
	if renewal := os.Getenv("MYENCRYPT_AUTO_RENEWAL"); renewal != "" {
		if b, err := strconv.ParseBool(renewal); err == nil {
			cfg.AutoRenewal = b
		}
	}

	if interval := os.Getenv("MYENCRYPT_RENEWAL_INTERVAL"); interval != "" {
		if duration, err := time.ParseDuration(interval); err == nil {
			cfg.RenewalInterval = duration
		}
	}

	// Service configuration
	if mode := os.Getenv("MYENCRYPT_RUN_MODE"); mode != "" {
		cfg.RunMode = mode
	}

	return cfg
}

// GetHostnameForACME returns the hostname to use for ACME directory endpoints
// This implements the hostname resolution logic centrally
func (c *Config) GetHostnameForACME() string {
	// 1. 明示的なHostname設定が最優先
	if c.Hostname != "" {
		return c.Hostname
	}

	// 2. BindAddressが0.0.0.0の場合はlocalhost
	if c.BindAddress == "0.0.0.0" {
		return "localhost"
	}

	// 3. BindAddressをそのまま使用
	return c.BindAddress
}

// parseDomainsFromString parses domains from a comma or newline separated string
func parseDomainsFromString(domainsStr string) []string {
	var domains []string

	// Support both comma and newline separation
	separators := []string{",", "\n", ";"}
	lines := []string{domainsStr}

	for _, sep := range separators {
		var newLines []string
		for _, line := range lines {
			newLines = append(newLines, strings.Split(line, sep)...)
		}
		lines = newLines
	}

	for _, domain := range lines {
		domain = strings.TrimSpace(domain)
		if domain != "" && !strings.HasPrefix(domain, "#") {
			domains = append(domains, domain)
		}
	}

	return domains
}

// Environment variable access functions - centralized environment variable handling

// GetExposePort returns the MYENCRYPT_EXPOSE_PORT environment variable
func GetExposePort() string {
	return os.Getenv("MYENCRYPT_EXPOSE_PORT")
}

// GetProjectName returns the MYENCRYPT_PROJECT_NAME environment variable
func GetProjectName() string {
	return os.Getenv("MYENCRYPT_PROJECT_NAME")
}

// GetLogLevel returns the MYENCRYPT_LOG_LEVEL environment variable
func GetLogLevel() string {
	return os.Getenv("MYENCRYPT_LOG_LEVEL")
}

// GetTestHTTP01BaseURL returns the MYENCRYPT_TEST_HTTP01_BASE_URL environment variable (for testing)
func GetTestHTTP01BaseURL() string {
	return os.Getenv("MYENCRYPT_TEST_HTTP01_BASE_URL")
}

// HasExposePort checks if MYENCRYPT_EXPOSE_PORT is set
func HasExposePort() bool {
	return GetExposePort() != ""
}

// HasProjectName checks if MYENCRYPT_PROJECT_NAME is set
func HasProjectName() bool {
	return GetProjectName() != ""
}

// CLIOverrides represents command-line overrides for configuration
type CLIOverrides struct {
	ConfigFile        string
	HTTPPort          *int
	BindAddress       string
	Hostname          string
	CertStorePath     string
	DatabasePath      string
	LogLevel          string
	IndividualCertTTL string
	CACertTTL         string
	AutoRenewal       *bool
	RenewalInterval   string
	RunMode           string
}

// ApplyOverrides applies command-line overrides to the configuration
func (c *Config) ApplyOverrides(overrides CLIOverrides) error {
	if overrides.HTTPPort != nil {
		c.HTTPPort = *overrides.HTTPPort
	}
	if overrides.BindAddress != "" {
		c.BindAddress = overrides.BindAddress
	}
	if overrides.Hostname != "" {
		c.Hostname = overrides.Hostname
	}
	if overrides.CertStorePath != "" {
		// Handle tilde expansion
		if strings.HasPrefix(overrides.CertStorePath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get user home directory: %w", err)
			}
			if len(overrides.CertStorePath) > 2 {
				c.CertStorePath = filepath.Join(homeDir, overrides.CertStorePath[2:])
			} else {
				c.CertStorePath = homeDir
			}
		} else {
			c.CertStorePath = overrides.CertStorePath
		}
	}
	if overrides.DatabasePath != "" {
		// Handle tilde expansion
		if strings.HasPrefix(overrides.DatabasePath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get user home directory: %w", err)
			}
			if len(overrides.DatabasePath) > 2 {
				c.DatabasePath = filepath.Join(homeDir, overrides.DatabasePath[2:])
			} else {
				c.DatabasePath = filepath.Join(homeDir, "myencrypt.db")
			}
		} else {
			c.DatabasePath = overrides.DatabasePath
		}
	}
	if strings.TrimSpace(overrides.IndividualCertTTL) != "" {
		duration, err := time.ParseDuration(overrides.IndividualCertTTL)
		if err != nil {
			return fmt.Errorf("invalid individual certificate TTL: %w", err)
		}
		c.IndividualCertTTL = duration
	}
	if strings.TrimSpace(overrides.CACertTTL) != "" {
		duration, err := time.ParseDuration(overrides.CACertTTL)
		if err != nil {
			return fmt.Errorf("invalid CA certificate TTL: %w", err)
		}
		c.CACertTTL = duration
	}
	if overrides.AutoRenewal != nil {
		c.AutoRenewal = *overrides.AutoRenewal
	}
	if strings.TrimSpace(overrides.RenewalInterval) != "" {
		duration, err := time.ParseDuration(overrides.RenewalInterval)
		if err != nil {
			return fmt.Errorf("invalid renewal interval: %w", err)
		}
		c.RenewalInterval = duration
	}
	if overrides.RunMode != "" {
		c.RunMode = overrides.RunMode
	}

	return nil
}

// ValidateOverrides validates CLI overrides before applying them
func ValidateOverrides(overrides CLIOverrides) error {
	// Validate port ranges
	if overrides.HTTPPort != nil && (*overrides.HTTPPort < 1 || *overrides.HTTPPort > 65535) {
		return fmt.Errorf("HTTP port must be between 1 and 65535, got %d", *overrides.HTTPPort)
	}

	// Validate duration strings
	if overrides.IndividualCertTTL != "" {
		if _, err := time.ParseDuration(overrides.IndividualCertTTL); err != nil {
			return fmt.Errorf("invalid individual certificate TTL '%s': %w", overrides.IndividualCertTTL, err)
		}
	}
	if overrides.CACertTTL != "" {
		if _, err := time.ParseDuration(overrides.CACertTTL); err != nil {
			return fmt.Errorf("invalid CA certificate TTL '%s': %w", overrides.CACertTTL, err)
		}
	}
	if overrides.RenewalInterval != "" {
		if _, err := time.ParseDuration(overrides.RenewalInterval); err != nil {
			return fmt.Errorf("invalid renewal interval '%s': %w", overrides.RenewalInterval, err)
		}
	}

	return nil
}

// GetConfigurationHelp returns help text for configuration options
func GetConfigurationHelp() string {
	return `Configuration can be provided through:
1. Configuration file (default: ~/.myencrypt/config.yaml)
2. Environment variables (MYENCRYPT_*)
3. Command line flags (highest priority)

Example configuration file:
---
http_port: 14000
bind_address: "0.0.0.0"
individual_cert_ttl: "24h"
ca_cert_ttl: "19200h"
cert_store_path: "~/.myencrypt"
service_name: "myencrypt"
service_display_name: "MyEncrypt ACME Server"
service_description: "Local ACME certificate authority for development"
run_mode: "service"
auto_renewal: true
renewal_interval: "1h"
default_allowed_domains:
  - "localhost"
  - "*.localhost"
  - "*.test"
  - "*.example"
  - "*.invalid"
additional_domains: []
---

Duration formats: 1h, 30m, 24h, 7d, 800d, etc.
Port ranges: 1-65535
Run modes: service, docker, standalone`
}

// LoadWithOverrides loads configuration from file and applies CLI overrides
func LoadWithOverrides(overrides CLIOverrides) (*Config, error) {
	// Determine config file path
	configPath := overrides.ConfigFile
	if configPath == "" || strings.HasPrefix(configPath, "~/") {
		// Handle default path or tilde expansion
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}

		if configPath == "" {
			// Use UserConfigDir for default path
			configDir, err := os.UserConfigDir()
			if err != nil {
				configDir = homeDir // Fallback to home directory
			}
			configPath = filepath.Join(configDir, "myencrypt", "config.yaml")
		} else {
			configPath = filepath.Join(homeDir, configPath[2:])
		}
	}

	// Start with default configuration
	cfg := DefaultConfig()

	// Try to load from config file
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
		}
	}

	// Apply CLI overrides
	if err := cfg.ApplyOverrides(overrides); err != nil {
		return nil, fmt.Errorf("failed to apply CLI overrides: %w", err)
	}

	// Validate final configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}
