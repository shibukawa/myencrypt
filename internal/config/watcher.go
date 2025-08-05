package config

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/shibukawa/myencrypt/internal/logger"
)

// ConfigWatcher watches for configuration file changes and reloads them
type ConfigWatcher struct {
	config  *Config
	logger  logger.Logger
	watcher *fsnotify.Watcher
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex

	// Callbacks for configuration changes
	callbacks []ConfigChangeCallback

	// File paths to watch
	configPath  string
	domainsPath string

	// Debouncing
	debounceDelay  time.Duration
	lastChangeTime time.Time
}

// ConfigChangeCallback is called when configuration changes
type ConfigChangeCallback func(oldConfig, newConfig *Config) error

// ConfigChange represents a configuration change event
type ConfigChange struct {
	Type      ConfigChangeType
	Path      string
	OldConfig *Config
	NewConfig *Config
	Timestamp time.Time
}

// ConfigChangeType represents the type of configuration change
type ConfigChangeType int

const (
	ConfigChangeTypeConfig ConfigChangeType = iota
	ConfigChangeTypeDomains
)

func (t ConfigChangeType) String() string {
	switch t {
	case ConfigChangeTypeConfig:
		return "config"
	case ConfigChangeTypeDomains:
		return "domains"
	default:
		return "unknown"
	}
}

// NewConfigWatcher creates a new configuration watcher
func NewConfigWatcher(config *Config, logger logger.Logger) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	cw := &ConfigWatcher{
		config:        config,
		logger:        logger,
		watcher:       watcher,
		ctx:           ctx,
		cancel:        cancel,
		callbacks:     make([]ConfigChangeCallback, 0),
		debounceDelay: 500 * time.Millisecond, // 500ms debounce
	}

	// Set up file paths
	cw.configPath = filepath.Join(config.GetCertStorePath(), "config.yaml")
	cw.domainsPath = filepath.Join(config.GetCertStorePath(), "allowed-domains.txt")

	return cw, nil
}

// Start begins watching for configuration changes
func (cw *ConfigWatcher) Start() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	cw.logger.Info("Starting configuration watcher",
		"config_path", cw.configPath,
		"domains_path", cw.domainsPath)

	// Watch config directory
	configDir := filepath.Dir(cw.configPath)
	if err := cw.watcher.Add(configDir); err != nil {
		return fmt.Errorf("failed to watch config directory: %w", err)
	}

	// Start the watch loop
	cw.wg.Add(1)
	go cw.watchLoop()

	cw.logger.Info("Configuration watcher started")
	return nil
}

// Stop stops the configuration watcher
func (cw *ConfigWatcher) Stop() error {
	cw.logger.Info("Stopping configuration watcher")

	cw.cancel()

	if cw.watcher != nil {
		cw.watcher.Close()
	}

	cw.wg.Wait()

	cw.logger.Info("Configuration watcher stopped")
	return nil
}

// AddCallback adds a callback for configuration changes
func (cw *ConfigWatcher) AddCallback(callback ConfigChangeCallback) {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	cw.callbacks = append(cw.callbacks, callback)
}

// watchLoop is the main watch loop
func (cw *ConfigWatcher) watchLoop() {
	defer cw.wg.Done()

	for {
		select {
		case <-cw.ctx.Done():
			cw.logger.Debug("Configuration watch loop stopping")
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				cw.logger.Debug("Watcher events channel closed")
				return
			}

			cw.handleFileEvent(event)

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				cw.logger.Debug("Watcher errors channel closed")
				return
			}

			cw.logger.Error("File watcher error", "error", err)
		}
	}
}

// handleFileEvent processes a file system event
func (cw *ConfigWatcher) handleFileEvent(event fsnotify.Event) {
	// Check if this is a file we care about
	if !cw.isWatchedFile(event.Name) {
		return
	}

	// Debounce rapid changes
	now := time.Now()
	if now.Sub(cw.lastChangeTime) < cw.debounceDelay {
		return
	}
	cw.lastChangeTime = now

	cw.logger.Debug("Configuration file changed",
		"file", event.Name,
		"operation", event.Op.String())

	// Handle the change after a short delay to allow file writes to complete
	go func() {
		time.Sleep(100 * time.Millisecond)
		cw.processConfigChange(event.Name)
	}()
}

// isWatchedFile checks if a file is one we're watching
func (cw *ConfigWatcher) isWatchedFile(path string) bool {
	filename := filepath.Base(path)
	return filename == "config.yaml" || filename == "allowed-domains.txt"
}

// processConfigChange processes a configuration file change
func (cw *ConfigWatcher) processConfigChange(path string) {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	filename := filepath.Base(path)

	// Store old config for comparison
	oldConfig := cw.copyConfig(cw.config)

	var changeType ConfigChangeType
	var err error

	switch filename {
	case "config.yaml":
		changeType = ConfigChangeTypeConfig
		err = cw.reloadConfig()
	case "allowed-domains.txt":
		changeType = ConfigChangeTypeDomains
		err = cw.reloadDomains()
	default:
		cw.logger.Debug("Ignoring change to untracked file", "file", filename)
		return
	}

	if err != nil {
		cw.logger.Error("Failed to reload configuration",
			"file", filename,
			"error", err)
		return
	}

	// Create change event
	change := &ConfigChange{
		Type:      changeType,
		Path:      path,
		OldConfig: oldConfig,
		NewConfig: cw.copyConfig(cw.config),
		Timestamp: time.Now(),
	}

	cw.logger.Info("Configuration reloaded",
		"type", change.Type.String(),
		"file", filename)

	// Notify callbacks
	cw.notifyCallbacks(change)
}

// reloadConfig reloads the main configuration file
func (cw *ConfigWatcher) reloadConfig() error {
	// Check if config file exists
	if _, err := os.Stat(cw.configPath); os.IsNotExist(err) {
		cw.logger.Debug("Config file does not exist, using defaults", "path", cw.configPath)
		return nil
	}

	// Load new configuration
	newConfig, err := Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Update current configuration (preserve some runtime values)
	cw.updateConfig(newConfig)

	return nil
}

// reloadDomains reloads the allowed domains file
func (cw *ConfigWatcher) reloadDomains() error {
	// Check if domains file exists
	if _, err := os.Stat(cw.domainsPath); os.IsNotExist(err) {
		cw.logger.Debug("Domains file does not exist, using defaults", "path", cw.domainsPath)
		return nil
	}

	// Load domains from file
	domains, err := cw.loadDomainsFromFile()
	if err != nil {
		return fmt.Errorf("failed to load domains: %w", err)
	}

	// Update additional domains (keep default domains unchanged)
	cw.config.AdditionalDomains = domains

	return nil
}

// loadDomainsFromFile loads domains from the allowed-domains.txt file
func (cw *ConfigWatcher) loadDomainsFromFile() ([]string, error) {
	content, err := os.ReadFile(cw.domainsPath)
	if err != nil {
		return nil, err
	}

	return parseDomainsFromContent(string(content)), nil
}

// updateConfig updates the current configuration with new values
func (cw *ConfigWatcher) updateConfig(newConfig *Config) {
	// Update configuration fields that can be changed at runtime
	cw.config.AdditionalDomains = newConfig.AdditionalDomains
	cw.config.IndividualCertTTL = newConfig.IndividualCertTTL
	cw.config.CACertTTL = newConfig.CACertTTL
	cw.config.AutoRenewal = newConfig.AutoRenewal
	cw.config.RenewalInterval = newConfig.RenewalInterval

	// Note: Some fields like ports and bind address cannot be changed at runtime
	// without restarting the server
}

// copyConfig creates a deep copy of a configuration
func (cw *ConfigWatcher) copyConfig(config *Config) *Config {
	newConfig := *config

	// Deep copy slices
	newConfig.DefaultAllowedDomains = make([]string, len(config.DefaultAllowedDomains))
	copy(newConfig.DefaultAllowedDomains, config.DefaultAllowedDomains)

	newConfig.AdditionalDomains = make([]string, len(config.AdditionalDomains))
	copy(newConfig.AdditionalDomains, config.AdditionalDomains)

	return &newConfig
}

// notifyCallbacks notifies all registered callbacks of a configuration change
func (cw *ConfigWatcher) notifyCallbacks(change *ConfigChange) {
	for _, callback := range cw.callbacks {
		go func(cb ConfigChangeCallback) {
			defer func() {
				if r := recover(); r != nil {
					cw.logger.Error("Configuration callback panicked",
						"panic", r,
						"change_type", change.Type.String())
				}
			}()

			if err := cb(change.OldConfig, change.NewConfig); err != nil {
				cw.logger.Error("Configuration callback failed",
					"error", err,
					"change_type", change.Type.String())
			}
		}(callback)
	}
}

// GetCurrentConfig returns the current configuration
func (cw *ConfigWatcher) GetCurrentConfig() *Config {
	cw.mu.RLock()
	defer cw.mu.RUnlock()

	return cw.copyConfig(cw.config)
}

// ForceReload forces a reload of all configuration files
func (cw *ConfigWatcher) ForceReload() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	cw.logger.Info("Forcing configuration reload")

	oldConfig := cw.copyConfig(cw.config)

	// Reload config file
	if err := cw.reloadConfig(); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	// Reload domains file
	if err := cw.reloadDomains(); err != nil {
		return fmt.Errorf("failed to reload domains: %w", err)
	}

	// Create change event
	change := &ConfigChange{
		Type:      ConfigChangeTypeConfig, // Use config type for manual reload
		Path:      "manual_reload",
		OldConfig: oldConfig,
		NewConfig: cw.copyConfig(cw.config),
		Timestamp: time.Now(),
	}

	// Notify callbacks
	cw.notifyCallbacks(change)

	cw.logger.Info("Configuration force reload completed")
	return nil
}

// parseDomainsFromContent parses domains from file content
func parseDomainsFromContent(content string) []string {
	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		domains = append(domains, line)
	}

	return domains
}
