package certmanager

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// DomainManager handles domain validation and management
type DomainManager struct {
	config             *config.Config
	logger             *logger.Logger
	allowedDomains     map[string]bool
	domainsMutex       sync.RWMutex
	allowedDomainsFile string
}

// NewDomainManager creates a new domain manager instance
func NewDomainManager(cfg *config.Config, log *logger.Logger) *DomainManager {
	allowedDomainsFile := filepath.Join(cfg.GetCertStorePath(), "allowed-domains.txt")

	dm := &DomainManager{
		config:             cfg,
		logger:             log.WithComponent("domain-manager"),
		allowedDomains:     make(map[string]bool),
		allowedDomainsFile: allowedDomainsFile,
	}

	return dm
}

// LoadAllowedDomains loads all domains from allowed-domains.txt
func (dm *DomainManager) LoadAllowedDomains() error {
	dm.logger.Debug("Loading allowed domains from file", "file", dm.allowedDomainsFile)

	// Check if file exists
	if _, err := os.Stat(dm.allowedDomainsFile); os.IsNotExist(err) {
		dm.logger.Debug("Allowed domains file does not exist")
		return fmt.Errorf("allowed domains file does not exist: %s (run 'myencrypt init' first)", dm.allowedDomainsFile)
	}

	file, err := os.Open(dm.allowedDomainsFile)
	if err != nil {
		return fmt.Errorf("failed to open allowed domains file: %w", err)
	}
	defer file.Close()

	dm.domainsMutex.Lock()
	defer dm.domainsMutex.Unlock()

	// Clear existing domains
	dm.allowedDomains = make(map[string]bool)

	// Load all domains from file
	scanner := bufio.NewScanner(file)
	domainCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Validate domain format
		if err := dm.validateDomainFormat(line); err != nil {
			dm.logger.Warn("Invalid domain format in allowed-domains.txt", "domain", line, "error", err)
			continue
		}

		dm.allowedDomains[line] = true
		domainCount++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading allowed domains file: %w", err)
	}

	dm.logger.Debug("Allowed domains loaded", "count", domainCount)
	return nil
}

// ReloadAllowedDomains reloads domains from file (for runtime updates)
func (dm *DomainManager) ReloadAllowedDomains() error {
	dm.logger.Info("Reloading allowed domains from file")
	return dm.LoadAllowedDomains()
}

// ListAllowedDomains returns all currently allowed domains
func (dm *DomainManager) ListAllowedDomains() ([]string, error) {
	dm.domainsMutex.RLock()
	defer dm.domainsMutex.RUnlock()

	domains := make([]string, 0, len(dm.allowedDomains))
	for domain := range dm.allowedDomains {
		domains = append(domains, domain)
	}

	return domains, nil
}

// IsAllowedDomain checks if a domain is allowed for certificate issuance
func (dm *DomainManager) IsAllowedDomain(domain string) bool {
	dm.domainsMutex.RLock()
	defer dm.domainsMutex.RUnlock()

	// Direct match
	if dm.allowedDomains[domain] {
		return true
	}

	// Check wildcard patterns
	for allowedDomain := range dm.allowedDomains {
		if dm.matchesWildcard(allowedDomain, domain) {
			return true
		}
	}

	return false
}

// AddDomainToFile adds a domain to the allowed-domains.txt file
func (dm *DomainManager) AddDomainToFile(domain string) error {
	dm.logger.Info("Adding domain to allowed list", "domain", domain)

	// Validate domain format
	if err := dm.validateDomainFormat(domain); err != nil {
		return fmt.Errorf("invalid domain format: %w", err)
	}

	// Check if domain is already allowed
	if dm.IsAllowedDomain(domain) {
		return fmt.Errorf("domain %s is already allowed", domain)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dm.allowedDomainsFile), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Read existing domains to avoid duplicates
	existingDomains, err := dm.readDomainsFromFile()
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read existing domains: %w", err)
	}

	// Check if domain already exists in file
	for _, existingDomain := range existingDomains {
		if existingDomain == domain {
			return fmt.Errorf("domain %s already exists in file", domain)
		}
	}

	// Append domain to file
	file, err := os.OpenFile(dm.allowedDomainsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open allowed domains file: %w", err)
	}
	defer file.Close()

	if _, err := fmt.Fprintf(file, "%s\n", domain); err != nil {
		return fmt.Errorf("failed to write domain to file: %w", err)
	}

	// Reload domains to update in-memory cache
	if err := dm.LoadAllowedDomains(); err != nil {
		return fmt.Errorf("failed to reload domains after adding: %w", err)
	}

	dm.logger.Info("Domain added successfully", "domain", domain)
	return nil
}

// RemoveDomainFromFile removes a domain from the allowed-domains.txt file
func (dm *DomainManager) RemoveDomainFromFile(domain string) error {
	dm.logger.Info("Removing domain from allowed list", "domain", domain)

	// Read existing domains
	existingDomains, err := dm.readDomainsFromFile()
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("domain %s not found (file does not exist)", domain)
		}
		return fmt.Errorf("failed to read existing domains: %w", err)
	}

	// Filter out the domain to remove
	var filteredDomains []string
	found := false

	for _, existingDomain := range existingDomains {
		if existingDomain != domain {
			filteredDomains = append(filteredDomains, existingDomain)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("domain %s not found in allowed domains file", domain)
	}

	// Write filtered domains back to file
	if err := dm.writeDomainsToFile(filteredDomains); err != nil {
		return fmt.Errorf("failed to write updated domains: %w", err)
	}

	// Reload domains to update in-memory cache
	if err := dm.LoadAllowedDomains(); err != nil {
		return fmt.Errorf("failed to reload domains after removal: %w", err)
	}

	dm.logger.Info("Domain removed successfully", "domain", domain)
	return nil
}

// readDomainsFromFile reads domains from the allowed-domains.txt file
func (dm *DomainManager) readDomainsFromFile() ([]string, error) {
	file, err := os.Open(dm.allowedDomainsFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		domains = append(domains, line)
	}

	return domains, scanner.Err()
}

// writeDomainsToFile writes domains to the allowed-domains.txt file
func (dm *DomainManager) writeDomainsToFile(domains []string) error {
	file, err := os.Create(dm.allowedDomainsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header comment
	if _, err := fmt.Fprintf(file, "# Allowed domains for MyEncrypt ACME server\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(file, "# One domain per line. Lines starting with # are comments.\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(file, "# You can add or remove domains using 'myencrypt domain add/remove' commands.\n\n"); err != nil {
		return err
	}

	// Write domains
	for _, domain := range domains {
		if _, err := fmt.Fprintf(file, "%s\n", domain); err != nil {
			return err
		}
	}

	return nil
}

// validateDomainFormat validates domain name format
func (dm *DomainManager) validateDomainFormat(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}

	// Basic validation - more comprehensive validation can be added
	if strings.Contains(domain, " ") {
		return fmt.Errorf("domain cannot contain spaces")
	}

	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("domain cannot start or end with a dot")
	}

	return nil
}

// matchesWildcard checks if a domain matches a wildcard pattern
func (dm *DomainManager) matchesWildcard(pattern, domain string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := pattern[2:] // Remove "*."

	// Domain must end with the suffix
	if !strings.HasSuffix(domain, "."+suffix) {
		return false
	}

	// Check that there's exactly one subdomain level
	prefix := domain[:len(domain)-len(suffix)-1] // -1 for the dot
	if strings.Contains(prefix, ".") {
		return false
	}

	return len(prefix) > 0
}

// GetAllowedDomainsFilePath returns the path to the allowed-domains.txt file
func (dm *DomainManager) GetAllowedDomainsFilePath() string {
	return dm.allowedDomainsFile
}
