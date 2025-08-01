package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Server configuration
	HTTPPort    int    `yaml:"http_port"`
	BindAddress string `yaml:"bind_address"`

	// Certificate configuration
	IndividualCertTTL time.Duration `yaml:"individual_cert_ttl"`
	CACertTTL         time.Duration `yaml:"ca_cert_ttl"`

	// Domain configuration
	DefaultAllowedDomains []string `yaml:"default_allowed_domains"`
	AdditionalDomains     []string `yaml:"additional_domains"`

	// File storage configuration
	CertStorePath string `yaml:"cert_store_path"`

	// Service configuration
	ServiceName        string `yaml:"service_name"`
	ServiceDisplayName string `yaml:"service_display_name"`
	ServiceDescription string `yaml:"service_description"`

	// Runtime configuration
	RunMode         string        `yaml:"run_mode"`
	AutoRenewal     bool          `yaml:"auto_renewal"`
	RenewalInterval time.Duration `yaml:"renewal_interval"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	configDir, err := os.UserConfigDir()
	if err != nil {
		// Fallback to home directory if UserConfigDir fails
		homeDir, _ := os.UserHomeDir()
		configDir = homeDir
	}
	certStorePath := filepath.Join(configDir, "myencrypt")

	return &Config{
		// Server defaults
		HTTPPort:    14000,
		BindAddress: "0.0.0.0",

		// Certificate defaults
		IndividualCertTTL: 24 * time.Hour,       // 1 day
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

		// File storage default
		CertStorePath: certStorePath,

		// Service defaults
		ServiceName:        "myencrypt",
		ServiceDisplayName: "MyEncrypt ACME Server",
		ServiceDescription: "Local ACME certificate authority for development",

		// Runtime defaults
		RunMode:         "service",
		AutoRenewal:     true,
		RenewalInterval: time.Hour,
	}
}

// Load loads configuration from file or returns default configuration
func Load() (*Config, error) {
	cfg := DefaultConfig()

	// Try to load from ~/.myencrypt/config.yaml
	configPath := filepath.Join(cfg.CertStorePath, "config.yaml")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config file doesn't exist, return default configuration
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save saves the configuration to file
func (c *Config) Save() error {
	// Ensure directory exists
	if err := os.MkdirAll(c.CertStorePath, 0755); err != nil {
		return err
	}

	configPath := filepath.Join(c.CertStorePath, "config.yaml")

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// InitializeConfigFile creates a default config.yaml file if it doesn't exist
func (c *Config) InitializeConfigFile() error {
	configPath := filepath.Join(c.CertStorePath, "config.yaml")

	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		return nil // File already exists
	}

	// Ensure directory exists
	if err := os.MkdirAll(c.CertStorePath, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Save default configuration
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

	// Validate ports
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

	// Validate certificate storage path
	if strings.TrimSpace(c.CertStorePath) == "" {
		errors = append(errors, ValidationError{
			Field:   "cert_store_path",
			Value:   c.CertStorePath,
			Message: "cannot be empty",
		})
	}

	// Validate that certificate storage path is accessible
	if err := c.validateCertStorePath(); err != nil {
		errors = append(errors, ValidationError{
			Field:   "cert_store_path",
			Value:   c.CertStorePath,
			Message: fmt.Sprintf("path validation failed: %v", err),
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

	// Return first error if any
	if len(errors) > 0 {
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
		// Remove the directory we just created for testing
		os.Remove(path)
	} else if err != nil {
		return fmt.Errorf("cannot access path: %w", err)
	}

	return nil
}

// CLIOverrides represents command-line overrides for configuration
type CLIOverrides struct {
	ConfigFile        string
	HTTPPort          *int
	BindAddress       string
	CertStorePath     string
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
	if strings.TrimSpace(overrides.BindAddress) != "" {
		c.BindAddress = overrides.BindAddress
	}
	if strings.TrimSpace(overrides.CertStorePath) != "" {
		// Expand tilde in path
		if strings.HasPrefix(overrides.CertStorePath, "~/") {
			if homeDir, err := os.UserHomeDir(); err == nil {
				overrides.CertStorePath = filepath.Join(homeDir, overrides.CertStorePath[2:])
			}
		}
		c.CertStorePath = overrides.CertStorePath
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
	if strings.TrimSpace(overrides.RunMode) != "" {
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

	// Validate run mode
	if overrides.RunMode != "" {
		validModes := []string{"service", "docker", "standalone"}
		valid := false
		for _, mode := range validModes {
			if overrides.RunMode == mode {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid run mode '%s', must be one of: %s", overrides.RunMode, strings.Join(validModes, ", "))
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
