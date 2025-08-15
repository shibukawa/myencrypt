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

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shibukawa/incontainer"
	"github.com/shibukawa/myencrypt/internal/certmanager"
	"github.com/shibukawa/myencrypt/internal/config"
	initialize "github.com/shibukawa/myencrypt/internal/init"
	"github.com/shibukawa/myencrypt/internal/logger"
	"github.com/shibukawa/myencrypt/internal/service"

	"github.com/alecthomas/kong"
)

// CLI represents the command line interface structure
type CLI struct {
	// Global configuration options that can override config.yaml
	ConfigFile    string `help:"Path to configuration file" default:"" env:"MYENCRYPT_CONFIG" group:"config"`
	HTTPPort      int    `help:"HTTP server port" default:"14000" env:"MYENCRYPT_HTTP_PORT" group:"server" range:"1-65535"`
	BindAddress   string `help:"Server bind address" default:"0.0.0.0" env:"MYENCRYPT_BIND_ADDRESS" group:"server"`
	Hostname      string `help:"Hostname for ACME directory endpoints" default:"" env:"MYENCRYPT_HOSTNAME" group:"server"`
	CertStorePath string `help:"Certificate storage path" default:"" env:"MYENCRYPT_CERT_STORE_PATH" group:"storage"`
	DatabasePath  string `help:"SQLite database file path" default:"" env:"MYENCRYPT_DATABASE_PATH" group:"storage"`
	LogLevel      string `help:"Log level (debug, info, error)" default:"info" enum:"debug,info,error" env:"MYENCRYPT_LOG_LEVEL" group:"logging"`

	// Additional configuration options
	IndividualCertTTL string `help:"Individual certificate TTL (e.g., 24h, 1d)" default:"24h" env:"MYENCRYPT_INDIVIDUAL_CERT_TTL" group:"certificates"`
	CACertTTL         string `help:"CA certificate TTL (e.g., 800d, 19200h)" default:"19200h" env:"MYENCRYPT_CA_CERT_TTL" group:"certificates"`
	AutoRenewal       bool   `help:"Enable automatic certificate renewal" default:"true" env:"MYENCRYPT_AUTO_RENEWAL" group:"certificates"`
	RenewalInterval   string `help:"Certificate renewal check interval (e.g., 1h, 30m)" default:"1h" env:"MYENCRYPT_RENEWAL_INTERVAL" group:"certificates"`
	RunMode           string `help:"Service run mode" default:"service" enum:"service,docker,standalone" env:"MYENCRYPT_RUN_MODE" group:"service"`

	// Commands
	Init        InitCmd        `cmd:"" help:"Initialize CA certificate and generate installation scripts"`
	Run         RunCmd         `cmd:"" help:"Run myencrypt server"`
	Test        TestCmd        `cmd:"" help:"Test certificate generation (for development)"`
	Service     ServiceCmd     `cmd:"" help:"Manage myencrypt as an OS service"`
	Domain      DomainCmd      `cmd:"" help:"Manage allowed domains"`
	Config      ConfigCmd      `cmd:"" help:"Show configuration information and help"`
	Version     VersionCmd     `cmd:"" help:"Show version information"`
	Healthcheck HealthcheckCmd `cmd:"" help:"Check if MyEncrypt server is healthy (for Docker healthcheck)"`
}

// InitCmd handles the init command
type InitCmd struct {
	Force bool `help:"Force regeneration of CA certificate even if it exists" short:"f"`
}

// RunCmd handles running the server
type RunCmd struct {
	DryRun    bool `help:"Check configuration and exit without starting server" short:"n"`
	Container bool `help:"Use container mode (environment variables only, auto-detected in Docker)" default:"false"`
}

// TestCmd handles certificate generation testing
type TestCmd struct {
	Domain string `arg:"" help:"Domain name to generate certificate for" default:"localhost"`
}

// ServiceCmd handles service management commands
type ServiceCmd struct {
	Install   ServiceInstallCmd   `cmd:"" help:"Install myencrypt as an OS service"`
	Uninstall ServiceUninstallCmd `cmd:"" help:"Uninstall myencrypt OS service"`
	Start     ServiceStartCmd     `cmd:"" help:"Start the myencrypt service"`
	Stop      ServiceStopCmd      `cmd:"" help:"Stop the myencrypt service"`
	Restart   ServiceRestartCmd   `cmd:"" help:"Restart the myencrypt service"`
	Status    ServiceStatusCmd    `cmd:"" help:"Show myencrypt service status"`
	Run       ServiceRunCmd       `cmd:"" help:"Run myencrypt service directly (used by service manager)"`
}

// ServiceInstallCmd handles service installation
type ServiceInstallCmd struct {
	ServiceConfigPath string `help:"Path to configuration file for the service" default:"" env:"MYENCRYPT_SERVICE_CONFIG_PATH"`
}

// ServiceUninstallCmd handles service uninstallation
type ServiceUninstallCmd struct{}

// ServiceStartCmd handles service start
type ServiceStartCmd struct{}

// ServiceStopCmd handles service stop
type ServiceStopCmd struct{}

// ServiceRestartCmd handles service restart
type ServiceRestartCmd struct{}

// ServiceStatusCmd handles service status check
type ServiceStatusCmd struct{}

// ServiceRunCmd handles direct service execution
type ServiceRunCmd struct{}

// DomainCmd handles domain management
type DomainCmd struct {
	Add    DomainAddCmd    `cmd:"" help:"Add a domain to the allowed domains list"`
	Remove DomainRemoveCmd `cmd:"" help:"Remove a domain from the allowed domains list"`
	List   DomainListCmd   `cmd:"" help:"List all allowed domains"`
}

// DomainAddCmd handles adding domains to the allowed list
type DomainAddCmd struct {
	Domain string `arg:"" help:"Domain to add to the allowed list"`
}

// DomainRemoveCmd handles removing domains from the allowed list
type DomainRemoveCmd struct {
	Domain string `arg:"" help:"Domain to remove from the allowed list"`
}

// DomainListCmd handles listing allowed domains
type DomainListCmd struct{}

// ConfigCmd handles configuration management
type ConfigCmd struct {
	Show     ConfigShowCmd     `cmd:"" help:"Show current configuration"`
	Validate ConfigValidateCmd `cmd:"" help:"Validate configuration file"`
	Help     ConfigHelpCmd     `cmd:"" help:"Show configuration help and examples"`
}

// ConfigShowCmd shows current configuration
type ConfigShowCmd struct{}

// ConfigValidateCmd validates configuration
type ConfigValidateCmd struct{}

// ConfigHelpCmd shows configuration help
type ConfigHelpCmd struct{}

// HealthcheckCmd handles health check for Docker
type HealthcheckCmd struct {
	URL     string `help:"Health check URL" default:"http://localhost:80/health"`
	Timeout string `help:"Request timeout" default:"5s"`
}

// VersionCmd handles version display
type VersionCmd struct{}

func main() {
	// Parse command line arguments using kong first to get CLI overrides
	cli := CLI{}
	ctx := kong.Parse(&cli,
		kong.Name("myencrypt"),
		kong.Description("MyEncrypt ACME Server - Local development certificate authority"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
	)

	// Prepare CLI overrides
	overrides := config.CLIOverrides{
		ConfigFile:        cli.ConfigFile,
		BindAddress:       cli.BindAddress,
		Hostname:          cli.Hostname,
		CertStorePath:     cli.CertStorePath,
		DatabasePath:      cli.DatabasePath,
		LogLevel:          cli.LogLevel,
		IndividualCertTTL: cli.IndividualCertTTL,
		CACertTTL:         cli.CACertTTL,
		RenewalInterval:   cli.RenewalInterval,
		RunMode:           cli.RunMode,
	}

	// Only set port overrides if they differ from defaults
	if cli.HTTPPort != 14000 {
		overrides.HTTPPort = &cli.HTTPPort
	}

	// Only set AutoRenewal override if it differs from default
	if !cli.AutoRenewal {
		overrides.AutoRenewal = &cli.AutoRenewal
	}

	// Validate CLI overrides first
	if err := config.ValidateOverrides(overrides); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nUse --help for usage information or see configuration help:\n")
		fmt.Fprintf(os.Stderr, "%s\n", config.GetConfigurationHelp())
		os.Exit(1)
	}

	// Load configuration with CLI overrides
	cfg, err := config.LoadWithOverrides(overrides)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		fmt.Fprintf(os.Stderr, "\nConfiguration help:\n%s\n", config.GetConfigurationHelp())
		os.Exit(1)
	}

	// Initialize logger with configured log level
	log := logger.New()
	if cli.LogLevel != "" {
		// Set log level based on CLI override
		switch strings.ToLower(cli.LogLevel) {
		case "debug":
			log.SetLevel(logger.DebugLevel)
		case "info":
			log.SetLevel(logger.InfoLevel)
		case "error":
			log.SetLevel(logger.ErrorLevel)
		default:
			log.Warn("Invalid log level, using default", "level", cli.LogLevel)
		}
	}

	// Execute the selected command
	switch ctx.Command() {
	case "init":
		err = handleInitCommand(cfg, log, cli.Init.Force)
	case "run":
		// Auto-detect container environment if not explicitly set
		containerMode := cli.Run.Container
		if !containerMode && incontainer.IsInContainer() {
			containerMode = true
			log.Info("Container environment detected, enabling container mode automatically")
		}
		err = handleRunCommand(cfg, log, cli.Run.DryRun, containerMode)
	case "test <domain>":
		err = handleTestCommand(cfg, log, cli.Test.Domain)
	case "service install":
		configPath := cli.Service.Install.ServiceConfigPath
		if configPath == "" {
			userConfigDir, err := os.UserConfigDir()
			if err != nil {
				log.Fatal("Failed to get user config directory", "error", err)
			}
			configPath = filepath.Join(userConfigDir, "myencrypt", "config.yaml")
		}
		err = handleServiceInstallCommand(cfg, log, configPath)
	case "service uninstall":
		err = handleServiceUninstallCommand(cfg, log)
	case "service start":
		err = handleServiceStartCommand(cfg, log)
	case "service stop":
		err = handleServiceStopCommand(cfg, log)
	case "service restart":
		err = handleServiceRestartCommand(cfg, log)
	case "service status":
		err = handleServiceStatusCommand(cfg, log)
	case "service run":
		err = handleServiceRunCommand(cfg, log)
	case "domain add <domain>":
		err = handleAddDomainCommand(cli.Domain.Add.Domain, cfg, log)
	case "domain remove <domain>":
		err = handleRemoveDomainCommand(cli.Domain.Remove.Domain, cfg, log)
	case "domain list":
		err = handleListDomainsCommand(cfg, log)
	case "config show":
		err = handleConfigShowCommand(cfg, log)
	case "config validate":
		err = handleConfigValidateCommand(cfg, log)
	case "config help":
		err = handleConfigHelpCommand()
	case "healthcheck":
		err = handleHealthcheckCommand(cli.Healthcheck.URL, cli.Healthcheck.Timeout)
	case "version":
		err = handleVersionCommand()
	default:
		ctx.FatalIfErrorf(fmt.Errorf("unknown command: %s", ctx.Command()))
	}

	if err != nil {
		log.Fatal("Command failed", "command", ctx.Command(), "error", err)
	}
}

// handleInitCommand handles the init command
func handleInitCommand(cfg *config.Config, log *logger.Logger, force bool) error {
	initCmd := initialize.New(cfg, log)
	if err := initCmd.Execute(force); err != nil {
		return fmt.Errorf("init command failed: %w", err)
	}

	return nil
}

// handleRunCommand handles running the server
func handleRunCommand(cfg *config.Config, log *logger.Logger, dryRun bool, containerMode bool) error {
	var finalCfg *config.Config
	var err error

	if containerMode {
		// Use Docker-specific configuration (environment variables only with validation)
		log.Info("Using container mode configuration (environment variables only)")
		finalCfg, err = config.LoadFromEnvForDocker()
		if err != nil {
			return fmt.Errorf("failed to load Docker configuration: %w", err)
		}

		// Auto-initialize if needed in Docker mode
		if finalCfg.AutoInit {
			log.Info("Auto-initialization enabled in Docker mode")
			initCmd := initialize.New(finalCfg, log)
			if err := initCmd.Execute(false); err != nil {
				log.Warn("Auto-initialization failed, continuing anyway", "error", err)
			} else {
				log.Info("Auto-initialization completed successfully")
			}
		}
	} else {
		// Use normal configuration loading (development mode)
		log.Info("Using development mode configuration (config files + environment)")
		finalCfg, err = config.LoadWithEnvOverrides()
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}
	}

	if dryRun {
		fmt.Println("🧪 MyEncrypt Configuration Check")
		fmt.Println("============================")
		fmt.Printf("HTTP Server: http://%s:%d\n", finalCfg.BindAddress, finalCfg.HTTPPort)
		if containerMode {
			exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
			fmt.Printf("Docker Expose Port: %s (host access)\n", exposePort)
			fmt.Printf("Internal Port: %d (container internal)\n", finalCfg.HTTPPort)
		}
		fmt.Printf("Certificate Store: %s\n", finalCfg.GetCertStorePath())
		fmt.Printf("Database Path: %s\n", finalCfg.GetDatabasePath())
		fmt.Printf("Individual Cert TTL: %s\n", finalCfg.IndividualCertTTL)
		fmt.Printf("CA Cert TTL: %s\n", finalCfg.CACertTTL)
		fmt.Printf("Auto Renewal: %t\n", finalCfg.AutoRenewal)
		fmt.Printf("Container Mode: %t\n", containerMode)
		if containerMode {
			fmt.Printf("Container Detection: %t\n", incontainer.IsInContainer())
		}
		fmt.Println()

		// Validate configuration
		if err := finalCfg.Validate(); err != nil {
			fmt.Printf("❌ Configuration validation failed: %v\n", err)
			return err
		}

		// Check certificate manager initialization
		certMgr := certmanager.New(finalCfg, log)
		if err := certMgr.LoadAllowedDomains(); err != nil {
			fmt.Printf("❌ Failed to load allowed domains: %v\n", err)
			return err
		}

		domains, _ := certMgr.ListAllowedDomains()
		fmt.Printf("Allowed domains: %d configured\n", len(domains))

		// Check CA certificate
		if err := certMgr.ValidateCA(); err != nil {
			fmt.Printf("⚠️  CA certificate issue: %v\n", err)
			fmt.Println("   Run 'myencrypt init' to initialize CA certificate")
		} else {
			fmt.Println("✅ CA certificate is valid")
		}

		fmt.Println()
		fmt.Println("✅ Configuration check completed successfully!")
		fmt.Println("   Ready to start server with: myencrypt run")
		return nil
	}

	fmt.Printf("Starting MyEncrypt ACME Server...\n")
	fmt.Printf("HTTP Server: http://%s:%d\n", finalCfg.BindAddress, finalCfg.HTTPPort)
	if containerMode {
		exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
		fmt.Printf("Docker Expose Port: %s (host access)\n", exposePort)
		fmt.Printf("Internal Port: %d (container internal)\n", finalCfg.HTTPPort)
		fmt.Printf("Container Access: http://myencrypt (within Docker network)\n")
		fmt.Println()
		fmt.Println("📋 CA Certificate Installation Guide:")
		fmt.Println("=====================================")
		fmt.Printf("Quick install (one-liner):\n")
		fmt.Printf("   # macOS/Linux:\n")
		fmt.Printf("   curl -sSL http://localhost:%s/download/install.sh | bash\n", exposePort)
		fmt.Printf("   \n")
		fmt.Printf("   # Windows (PowerShell):\n")
		fmt.Printf("   # Download and run separately:\n")
		fmt.Printf("   curl http://localhost:%s/download/install.ps1 -o install.ps1\n", exposePort)
		fmt.Printf("   .\\install.ps1\n")
		fmt.Printf("   \n")
		fmt.Printf("More options and manual install: http://localhost:%s/download\n", exposePort)
		fmt.Println()
	}
	fmt.Printf("Certificate Store: %s\n", finalCfg.GetCertStorePath())
	fmt.Printf("Database Path: %s\n", finalCfg.GetDatabasePath())
	if containerMode {
		fmt.Println("Mode: Container (environment variables only)")
		if incontainer.IsInContainer() {
			fmt.Println("Container Environment: Detected automatically")
		} else {
			fmt.Println("Container Environment: Forced via --container flag")
		}
	} else {
		fmt.Println("Mode: Development (config files + environment)")
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop the server")
	fmt.Println()

	log.Info("Starting MyEncrypt server",
		"http_port", finalCfg.HTTPPort,
		"bind_address", finalCfg.BindAddress,
		"cert_store_path", finalCfg.GetCertStorePath(),
		"database_path", finalCfg.GetDatabasePath(),
		"container_mode", containerMode,
		"container_detected", incontainer.IsInContainer())

	// Create a service manager and run it directly
	serviceManager, err := service.New(finalCfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// Run the service directly (this will block until interrupted)
	return serviceManager.Run()
}

// handleAddDomainCommand handles adding a domain to the allowed list
func handleAddDomainCommand(domain string, cfg *config.Config, log *logger.Logger) error {
	log.Info("Adding domain to allowed list", "domain", domain)

	domainManager := certmanager.NewDomainManager(cfg, log)

	// Load existing domains first
	if err := domainManager.LoadAllowedDomains(); err != nil {
		return fmt.Errorf("failed to load existing domains: %w", err)
	}

	// Add the domain
	if err := domainManager.AddDomainToFile(domain); err != nil {
		return fmt.Errorf("failed to add domain: %w", err)
	}

	fmt.Printf("Domain '%s' added successfully to allowed domains list.\n", domain)
	fmt.Println("Note: Restart the myencrypt service for changes to take effect.")
	return nil
}

// handleRemoveDomainCommand handles removing a domain from the allowed list
func handleRemoveDomainCommand(domain string, cfg *config.Config, log *logger.Logger) error {
	log.Info("Removing domain from allowed list", "domain", domain)

	domainManager := certmanager.NewDomainManager(cfg, log)

	// Load existing domains first
	if err := domainManager.LoadAllowedDomains(); err != nil {
		return fmt.Errorf("failed to load existing domains: %w", err)
	}

	// Remove the domain
	if err := domainManager.RemoveDomainFromFile(domain); err != nil {
		return fmt.Errorf("failed to remove domain: %w", err)
	}

	fmt.Printf("Domain '%s' removed successfully from allowed domains list.\n", domain)
	fmt.Println("Note: Restart the myencrypt service for changes to take effect.")
	return nil
}

// handleListDomainsCommand handles listing all allowed domains
func handleListDomainsCommand(cfg *config.Config, log *logger.Logger) error {
	log.Debug("Listing allowed domains")

	domainManager := certmanager.NewDomainManager(cfg, log)

	// Load domains
	if err := domainManager.LoadAllowedDomains(); err != nil {
		return fmt.Errorf("failed to load domains: %w", err)
	}

	// Get all allowed domains
	domains, err := domainManager.ListAllowedDomains()
	if err != nil {
		return fmt.Errorf("failed to list domains: %w", err)
	}

	fmt.Println("Allowed domains:")
	fmt.Println()

	if len(domains) == 0 {
		fmt.Println("  (none - run 'myencrypt init' to initialize default domains)")
	} else {
		for _, domain := range domains {
			fmt.Printf("  %s\n", domain)
		}
	}

	fmt.Printf("\nTotal: %d domains\n", len(domains))
	fmt.Printf("Configuration file: %s\n", domainManager.GetAllowedDomainsFilePath())
	return nil
}

// handleConfigShowCommand shows current configuration
func handleConfigShowCommand(cfg *config.Config, log *logger.Logger) error {
	log.Debug("Showing current configuration")

	fmt.Println("Current Configuration:")
	fmt.Println("=====================")
	fmt.Printf("Configuration file: %s\n", cfg.GetConfigFilePath())
	fmt.Printf("Certificate store: %s\n", cfg.GetCertStorePath())
	fmt.Println()

	fmt.Println("Server Settings:")
	fmt.Printf("  HTTP Port: %d\n", cfg.HTTPPort)
	fmt.Printf("  Bind Address: %s\n", cfg.BindAddress)
	if cfg.Hostname != "" {
		fmt.Printf("  Hostname: %s\n", cfg.Hostname)
	} else {
		fmt.Printf("  Hostname: (auto-detected)\n")
	}
	fmt.Println()

	fmt.Println("Certificate Settings:")
	fmt.Printf("  Individual Cert TTL: %s\n", cfg.IndividualCertTTL)
	fmt.Printf("  CA Cert TTL: %s\n", cfg.CACertTTL)
	fmt.Printf("  Auto Renewal: %t\n", cfg.AutoRenewal)
	fmt.Printf("  Renewal Interval: %s\n", cfg.RenewalInterval)
	fmt.Println()

	fmt.Println("Service Settings:")
	fmt.Printf("  Service Name: %s\n", cfg.ServiceName)
	fmt.Printf("  Display Name: %s\n", cfg.ServiceDisplayName)
	fmt.Printf("  Description: %s\n", cfg.ServiceDescription)
	fmt.Printf("  Run Mode: %s\n", cfg.RunMode)
	fmt.Println()

	fmt.Println("Domain Settings:")
	fmt.Println("  Default Allowed Domains:")
	for _, domain := range cfg.DefaultAllowedDomains {
		fmt.Printf("    %s\n", domain)
	}
	fmt.Println("  Additional Domains:")
	if len(cfg.AdditionalDomains) == 0 {
		fmt.Println("    (none)")
	} else {
		for _, domain := range cfg.AdditionalDomains {
			fmt.Printf("    %s\n", domain)
		}
	}

	return nil
}

// handleConfigValidateCommand validates configuration
func handleConfigValidateCommand(cfg *config.Config, log *logger.Logger) error {
	log.Debug("Validating configuration")

	fmt.Println("Validating Configuration...")
	fmt.Println("==========================")

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		fmt.Printf("❌ Configuration validation failed: %v\n", err)
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	fmt.Println("✅ Configuration is valid!")
	fmt.Println()

	// Show configuration file status
	configPath := cfg.GetConfigFilePath()
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("ℹ️  Configuration file does not exist: %s\n", configPath)
		fmt.Println("   Using default configuration values.")
		fmt.Println("   Run 'myencrypt init' to create a configuration file.")
	} else {
		fmt.Printf("✅ Configuration file exists: %s\n", configPath)
	}

	// Check certificate store directory
	certStorePath := cfg.GetCertStorePath()
	if _, err := os.Stat(certStorePath); os.IsNotExist(err) {
		fmt.Printf("ℹ️  Certificate store directory does not exist: %s\n", certStorePath)
		fmt.Println("   It will be created when needed.")
	} else {
		fmt.Printf("✅ Certificate store directory exists: %s\n", certStorePath)
	}

	return nil
}

// handleConfigHelpCommand shows configuration help
func handleConfigHelpCommand() error {
	fmt.Println("Configuration Help")
	fmt.Println("==================")
	fmt.Println()
	fmt.Println(config.GetConfigurationHelp())
	return nil
}

// Version is set at build time via -ldflags
var Version = "latest"

// handleVersionCommand handles version display
func handleVersionCommand() error {
	fmt.Println("MyEncrypt " + Version)
	return nil
}

// handleServiceInstallCommand handles service installation
func handleServiceInstallCommand(cfg *config.Config, log *logger.Logger, configPath string) error {
	fmt.Printf("Installing myencrypt service...\n")
	fmt.Printf("Certificate store path: %s\n", cfg.GetCertStorePath())
	fmt.Printf("Configuration file path: %s\n", configPath)
	fmt.Println()

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// Check if already installed
	if serviceManager.IsInstalled() {
		fmt.Printf("Service '%s' is already installed.\n", cfg.ServiceName)
		fmt.Println("Use 'myencrypt service uninstall' to remove it first.")
		return nil
	}

	if err := serviceManager.Install(configPath); err != nil {
		return fmt.Errorf("failed to install service: %w", err)
	}

	fmt.Printf("✅ Service '%s' installed successfully.\n", cfg.ServiceName)
	fmt.Println()
	fmt.Println("Important notes:")
	fmt.Printf("- Service will use certificate store: %s\n", cfg.GetCertStorePath())
	fmt.Printf("- Service will use configuration file: %s\n", configPath)
	fmt.Println("- Make sure to run 'myencrypt init' first to create CA certificates")
	fmt.Println("- Service will run as the current user to access your certificate store")
	fmt.Println()
	fmt.Println("Use 'myencrypt service start' to start the service.")
	return nil
}

// handleServiceUninstallCommand handles service uninstallation
func handleServiceUninstallCommand(cfg *config.Config, log *logger.Logger) error {
	log.Info("Uninstalling myencrypt service")

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// Check if installed
	if !serviceManager.IsInstalled() {
		fmt.Printf("Service '%s' is not installed.\n", cfg.ServiceName)
		return nil
	}

	if err := serviceManager.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service: %w", err)
	}

	fmt.Printf("Service '%s' uninstalled successfully.\n", cfg.ServiceName)
	return nil
}

// handleServiceStartCommand handles service start
func handleServiceStartCommand(cfg *config.Config, log *logger.Logger) error {
	log.Info("Starting myencrypt service")

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// Check if installed
	if !serviceManager.IsInstalled() {
		fmt.Printf("Service '%s' is not installed.\n", cfg.ServiceName)
		fmt.Println("Use 'myencrypt service install' to install it first.")
		return nil
	}

	// Check if already running
	if serviceManager.IsRunning() {
		fmt.Printf("Service '%s' is already running.\n", cfg.ServiceName)
		return nil
	}

	if err := serviceManager.StartService(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Printf("Service '%s' started successfully.\n", cfg.ServiceName)
	return nil
}

// handleServiceStopCommand handles service stop
func handleServiceStopCommand(cfg *config.Config, log *logger.Logger) error {
	log.Info("Stopping myencrypt service")

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// Check if installed
	if !serviceManager.IsInstalled() {
		fmt.Printf("Service '%s' is not installed.\n", cfg.ServiceName)
		return nil
	}

	// Check if running
	if !serviceManager.IsRunning() {
		fmt.Printf("Service '%s' is not running.\n", cfg.ServiceName)
		return nil
	}

	if err := serviceManager.StopService(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	fmt.Printf("Service '%s' stopped successfully.\n", cfg.ServiceName)
	return nil
}

// handleServiceRestartCommand handles service restart
func handleServiceRestartCommand(cfg *config.Config, log *logger.Logger) error {
	log.Info("Restarting myencrypt service")

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// Check if installed
	if !serviceManager.IsInstalled() {
		fmt.Printf("Service '%s' is not installed.\n", cfg.ServiceName)
		fmt.Println("Use 'myencrypt service install' to install it first.")
		return nil
	}

	if err := serviceManager.Restart(); err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}

	fmt.Printf("Service '%s' restarted successfully.\n", cfg.ServiceName)
	return nil
}

// handleServiceStatusCommand handles service status check
func handleServiceStatusCommand(cfg *config.Config, log *logger.Logger) error {
	log.Debug("Checking myencrypt service status")

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	status, err := serviceManager.Status()
	if err != nil {
		// If we can't get status, the service is likely not installed
		fmt.Printf("Service '%s' is not installed or not accessible.\n", cfg.ServiceName)
		fmt.Println("Use 'myencrypt service install' to install it.")
		return nil
	}

	fmt.Printf("Service Name: %s\n", status.Name)
	fmt.Printf("Display Name: %s\n", cfg.ServiceDisplayName)
	fmt.Printf("Description: %s\n", cfg.ServiceDescription)
	fmt.Printf("Installed: %v\n", status.IsInstalled)
	fmt.Printf("Running: %v\n", status.IsRunning)

	// Convert service status to human-readable string
	var statusStr string
	switch status.Status {
	case 0: // StatusUnknown
		statusStr = "Unknown"
	case 1: // StatusRunning
		statusStr = "Running"
	case 2: // StatusStopped
		statusStr = "Stopped"
	default:
		statusStr = fmt.Sprintf("Status(%d)", status.Status)
	}
	fmt.Printf("Status: %s\n", statusStr)

	if status.IsInstalled && !status.IsRunning {
		fmt.Println("\nService is installed but not running.")
		fmt.Println("Use 'myencrypt service start' to start it.")
	} else if !status.IsInstalled {
		fmt.Println("\nService is not installed.")
		fmt.Println("Use 'myencrypt service install' to install it.")
	}

	return nil
}

// handleServiceRunCommand handles direct service execution
func handleServiceRunCommand(cfg *config.Config, log *logger.Logger) error {
	log.Info("Running myencrypt service directly",
		"cert_store_path", cfg.GetCertStorePath(),
		"http_port", cfg.HTTPPort)

	serviceManager, err := service.New(cfg, log)
	if err != nil {
		return fmt.Errorf("failed to create service manager: %w", err)
	}

	// This is called by the service manager, so we run the service directly
	return serviceManager.Run()
}

// handleTestCommand handles certificate generation testing
func handleTestCommand(cfg *config.Config, log *logger.Logger, domain string) error {
	fmt.Printf("Testing certificate generation for domain: %s\n", domain)
	fmt.Println("================================================")

	// Initialize certificate manager
	certMgr := certmanager.New(cfg, log)

	// Load allowed domains
	if err := certMgr.LoadAllowedDomains(); err != nil {
		return fmt.Errorf("failed to load allowed domains: %w", err)
	}

	// Check if domain is allowed
	if !certMgr.IsAllowedDomain(domain) {
		fmt.Printf("❌ Domain '%s' is not in the allowed domains list\n", domain)
		fmt.Println("\nAllowed domains:")
		domains, _ := certMgr.ListAllowedDomains()
		for _, d := range domains {
			fmt.Printf("  - %s\n", d)
		}
		fmt.Printf("\nTo add this domain: myencrypt domain add %s\n", domain)
		return fmt.Errorf("domain not allowed")
	}

	fmt.Printf("✅ Domain '%s' is allowed\n", domain)

	// Generate certificate
	fmt.Println("\nGenerating certificate...")
	cert, err := certMgr.GenerateCertificate(domain)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %w", err)
	}

	fmt.Println("✅ Certificate generated successfully!")

	// Display certificate information
	info := certMgr.GetCertificateInfo(cert)
	fmt.Println("\nCertificate Information:")
	fmt.Printf("  Domain: %s\n", info["domain"])
	fmt.Printf("  Serial: %s\n", info["serial"])
	fmt.Printf("  Algorithm: %s\n", info["algorithm"])
	fmt.Printf("  Signature: %s\n", info["signature"])
	fmt.Printf("  Valid From: %s\n", info["valid_from"])
	fmt.Printf("  Valid Until: %s\n", info["valid_until"])
	fmt.Printf("  Remaining Days: %d\n", info["remaining_days"])

	if dnsNames, ok := info["dns_names"].([]string); ok && len(dnsNames) > 0 {
		fmt.Printf("  DNS Names: %v\n", dnsNames)
	}

	// Validate certificate
	if err := certMgr.ValidateCertificate(cert); err != nil {
		fmt.Printf("⚠️  Certificate validation warning: %v\n", err)
	} else {
		fmt.Println("✅ Certificate is valid")
	}

	// Get certificate chain
	chain, err := certMgr.GetCertificateChain(cert)
	if err != nil {
		fmt.Printf("⚠️  Failed to get certificate chain: %v\n", err)
	} else {
		fmt.Printf("✅ Certificate chain length: %d bytes\n", len(chain))
	}

	// Save certificate to files for inspection
	certFile := fmt.Sprintf("test_%s.pem", strings.ReplaceAll(domain, "*", "wildcard"))
	keyFile := fmt.Sprintf("test_%s.key", strings.ReplaceAll(domain, "*", "wildcard"))

	if err := os.WriteFile(certFile, cert.CertPEM, 0644); err != nil {
		fmt.Printf("⚠️  Failed to save certificate file: %v\n", err)
	} else {
		fmt.Printf("📄 Certificate saved to: %s\n", certFile)
	}

	if err := os.WriteFile(keyFile, cert.KeyPEM, 0600); err != nil {
		fmt.Printf("⚠️  Failed to save private key file: %v\n", err)
	} else {
		fmt.Printf("🔐 Private key saved to: %s\n", keyFile)
	}

	fmt.Println("\n🎉 Certificate generation test completed successfully!")
	fmt.Printf("\nTo verify the certificate:\n")
	fmt.Printf("  openssl x509 -in %s -text -noout\n", certFile)
	fmt.Printf("  openssl x509 -in %s -noout -subject -dates\n", certFile)

	return nil
}

// handleHealthcheckCommand performs a health check for Docker healthcheck
func handleHealthcheckCommand(url, timeoutStr string) error {
	// Parse timeout
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid timeout format: %v\n", err)
		return err
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: timeout,
	}

	// Make health check request
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Health check failed: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Health check failed: HTTP %d\n", resp.StatusCode)
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	// Read and parse response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read health check response: %v\n", err)
		return err
	}

	var healthResponse map[string]interface{}
	if err := json.Unmarshal(body, &healthResponse); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse health check response: %v\n", err)
		return err
	}

	// Check status field
	status, ok := healthResponse["status"].(string)
	if !ok || status != "healthy" {
		fmt.Fprintf(os.Stderr, "Health check failed: status is not healthy\n")
		return fmt.Errorf("health check failed: status is %v", status)
	}

	// Health check passed
	fmt.Println("Health check passed")
	return nil
}
