package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"
)

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv() *Config {
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

	// Domain configuration - unified domains
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

	return cfg
}

// LoadFromEnvForDocker loads configuration from environment variables with Docker-specific requirements
func LoadFromEnvForDocker() (*Config, error) {
	cfg := DefaultConfig()

	// Docker mode requires MYENCRYPT_EXPOSE_PORT to be set
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	if exposePort == "" {
		return nil, fmt.Errorf("MYENCRYPT_EXPOSE_PORT environment variable is required in Docker mode")
	}

	// Validate expose port
	if _, err := strconv.Atoi(exposePort); err != nil {
		return nil, fmt.Errorf("MYENCRYPT_EXPOSE_PORT must be a valid port number: %v", err)
	}

	// Docker mode requires MYENCRYPT_PROJECT_NAME to be set
	projectName := os.Getenv("MYENCRYPT_PROJECT_NAME")
	if projectName == "" {
		return nil, fmt.Errorf("MYENCRYPT_PROJECT_NAME environment variable is required in Docker mode")
	}

	// Validate project name (alphanumeric, hyphens, underscores only)
	if !isValidProjectName(projectName) {
		return nil, fmt.Errorf("MYENCRYPT_PROJECT_NAME must contain only alphanumeric characters, hyphens, and underscores")
	}

	// Set internal port to 80 for Docker mode
	cfg.HTTPPort = 80
	cfg.BindAddress = "0.0.0.0"

	// Override hostname if specified
	if hostname := os.Getenv("MYENCRYPT_HOSTNAME"); hostname != "" {
		cfg.Hostname = hostname
	}

	// Enable auto-initialization in Docker mode
	cfg.AutoInit = true

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

	// Domain configuration - unified domains
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

	return cfg, nil
}

// isValidProjectName validates project name format
func isValidProjectName(name string) bool {
	// Allow alphanumeric characters, hyphens, and underscores
	// Length between 1 and 50 characters
	if len(name) == 0 || len(name) > 50 {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return matched
}

// parseDomainsFromString parses domains from a comma or newline separated string

// GetEnvWithDefault returns environment variable value or default
func GetEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetEnvBoolWithDefault returns environment variable as bool or default
func GetEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// GetEnvIntWithDefault returns environment variable as int or default
func GetEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// GetEnvDurationWithDefault returns environment variable as duration or default
func GetEnvDurationWithDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// LoadWithEnvOverrides loads configuration with environment variable overrides
func LoadWithEnvOverrides() (*Config, error) {
	// Start with file-based config if available
	cfg, err := Load()
	if err != nil {
		// If file loading fails, start with defaults
		cfg = DefaultConfig()
	}

	// Override with environment variables
	envCfg := LoadFromEnv()

	// Merge configurations (env takes precedence)
	if envCfg.HTTPPort != cfg.HTTPPort && envCfg.HTTPPort != DefaultConfig().HTTPPort {
		cfg.HTTPPort = envCfg.HTTPPort
	}

	if envCfg.BindAddress != cfg.BindAddress && envCfg.BindAddress != DefaultConfig().BindAddress {
		cfg.BindAddress = envCfg.BindAddress
	}

	if envCfg.Hostname != cfg.Hostname && envCfg.Hostname != DefaultConfig().Hostname {
		cfg.Hostname = envCfg.Hostname
	}

	if envCfg.IndividualCertTTL != cfg.IndividualCertTTL && envCfg.IndividualCertTTL != DefaultConfig().IndividualCertTTL {
		cfg.IndividualCertTTL = envCfg.IndividualCertTTL
	}

	if envCfg.CACertTTL != cfg.CACertTTL && envCfg.CACertTTL != DefaultConfig().CACertTTL {
		cfg.CACertTTL = envCfg.CACertTTL
	}

	// For domains, if env is set, it completely overrides file config
	if len(envCfg.DefaultAllowedDomains) > 0 && !equalStringSlices(envCfg.DefaultAllowedDomains, DefaultConfig().DefaultAllowedDomains) {
		cfg.DefaultAllowedDomains = envCfg.DefaultAllowedDomains
		cfg.AdditionalDomains = []string{} // Clear additional domains
	}

	if envCfg.CertStorePath != cfg.CertStorePath && envCfg.CertStorePath != DefaultConfig().CertStorePath {
		cfg.CertStorePath = envCfg.CertStorePath
	}

	if envCfg.DatabasePath != cfg.DatabasePath && envCfg.DatabasePath != DefaultConfig().DatabasePath {
		cfg.DatabasePath = envCfg.DatabasePath
	}

	return cfg, nil
}

// equalStringSlices compares two string slices for equality
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// PrintEnvHelp prints help for environment variables
func PrintEnvHelp() {
	envVars := []struct {
		Name        string
		Description string
		Default     string
		Example     string
	}{
		{"MYENCRYPT_HTTP_PORT", "HTTP server port", "14000", "14000"},
		{"MYENCRYPT_BIND_ADDRESS", "Bind address", "0.0.0.0", "0.0.0.0"},
		{"MYENCRYPT_HOSTNAME", "Hostname for ACME directory endpoints", "", "localhost"},
		{"MYENCRYPT_INDIVIDUAL_CERT_TTL", "Individual certificate TTL", "168h", "168h"},
		{"MYENCRYPT_CA_CERT_TTL", "CA certificate TTL", "800 days", "19200h"},
		{"MYENCRYPT_ALLOWED_DOMAINS", "Allowed domains (comma/newline separated)", "localhost,*.localhost,*.test,*.example,*.invalid", "localhost,*.localhost,example.com,*.example.com"},
		{"MYENCRYPT_CERT_STORE_PATH", "Certificate storage path", "/data", "/data"},
		{"MYENCRYPT_DATABASE_PATH", "SQLite database file path", "/data/myencrypt.db", "/data/myencrypt.db"},
	}

	println("MyEncrypt Environment Variables:")
	println("================================")
	println()

	for _, env := range envVars {
		println("Name:        " + env.Name)
		println("Description: " + env.Description)
		println("Default:     " + env.Default)
		println("Example:     " + env.Example)
		println()
	}
}
