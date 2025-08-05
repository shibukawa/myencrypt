package initialize

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/shibukawa/myencrypt/internal/certmanager"
	"github.com/shibukawa/myencrypt/internal/config"
	"github.com/shibukawa/myencrypt/internal/logger"
	"github.com/shibukawa/myencrypt/internal/platform"
	"github.com/shibukawa/myencrypt/internal/scriptgen"
)

// InitCommand handles the init command functionality
type InitCommand struct {
	config      *config.Config
	logger      *logger.Logger
	caManager   *certmanager.CAManager
	platformMgr *platform.Manager
	scriptGen   *scriptgen.Generator
}

// New creates a new init command instance
func New(cfg *config.Config, log *logger.Logger) *InitCommand {
	caManager := certmanager.NewCAManager(cfg, log)
	platformMgr := platform.New()
	scriptGen := scriptgen.New(platformMgr)

	return &InitCommand{
		config:      cfg,
		logger:      log.WithComponent("init"),
		caManager:   caManager,
		platformMgr: platformMgr,
		scriptGen:   scriptGen,
	}
}

// Execute runs the init command
func (cmd *InitCommand) Execute(force bool) error {
	fmt.Println("Initializing MyEncrypt CA certificate and configuration...")
	fmt.Println()

	// Step 1: Initialize CA certificate
	fmt.Print("📁 Setting up certificate store directory... ")
	caExists, err := cmd.initializeCA(force)
	if err != nil {
		fmt.Println("❌")
		return fmt.Errorf("failed to initialize CA: %w", err)
	}
	fmt.Println("✅")

	// Step 1.5: Initialize allowed domains file
	fmt.Print("📝 Setting up allowed domains configuration... ")
	if err := cmd.initializeAllowedDomainsFile(); err != nil {
		fmt.Println("❌")
		return fmt.Errorf("failed to initialize allowed domains: %w", err)
	}
	fmt.Println("✅")

	// Step 2: Copy CA certificate to current directory
	fmt.Print("📄 Copying CA certificate to current directory... ")
	if err := cmd.copyCACertificateToCurrentDir(); err != nil {
		fmt.Println("❌")
		return fmt.Errorf("failed to copy CA certificate to current directory: %w", err)
	}
	fmt.Println("✅")

	// Step 3: Generate and output scripts based on OS detection
	fmt.Print("📜 Generating installation scripts... ")
	if err := cmd.generateScriptsToCurrentDir(); err != nil {
		fmt.Println("❌")
		return fmt.Errorf("failed to generate scripts: %w", err)
	}
	fmt.Println("✅")

	// Step 4: Display completion message with platform-specific instructions
	cmd.displayCompletionMessage(caExists, force)

	return nil
}

// copyCACertificateToCurrentDir copies the CA certificate to the current working directory
func (cmd *InitCommand) copyCACertificateToCurrentDir() error {
	// Get CA certificate
	caCert, err := cmd.caManager.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Write CA certificate to current directory
	caCertPath := filepath.Join(currentDir, "rootCA.pem")
	if err := os.WriteFile(caCertPath, caCert.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s: %w", caCertPath, err)
	}

	return nil
}

// generateScriptsToCurrentDir generates installation scripts and outputs them to current directory
func (cmd *InitCommand) generateScriptsToCurrentDir() error {
	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Get the current platform
	currentPlatform := cmd.platformMgr.GetPlatform()

	// Generate scripts based on platform
	scriptsToGenerate := cmd.getScriptsToGenerate(currentPlatform)

	for scriptType, platforms := range scriptsToGenerate {
		for _, targetPlatform := range platforms {
			if err := cmd.generateScript(scriptType, targetPlatform, currentDir); err != nil {
				return fmt.Errorf("failed to generate %s script for %s: %w", scriptType, targetPlatform, err)
			}
		}
	}

	return nil
}

// getScriptsToGenerate returns a map of script types to platforms that should be generated
func (cmd *InitCommand) getScriptsToGenerate(currentPlatform platform.Platform) map[string][]platform.Platform {
	scripts := make(map[string][]platform.Platform)

	switch currentPlatform {
	case platform.PlatformWindows:
		// Windows native - only PowerShell scripts
		scripts["install"] = []platform.Platform{platform.PlatformWindows}
		scripts["uninstall"] = []platform.Platform{platform.PlatformWindows}

	case platform.PlatformUnix:
		// Linux/macOS - only shell scripts
		scripts["install"] = []platform.Platform{platform.PlatformUnix}
		scripts["uninstall"] = []platform.Platform{platform.PlatformUnix}

	case platform.PlatformWSL:
		// WSL - both shell scripts (for WSL) and PowerShell scripts (for Windows host)
		scripts["install"] = []platform.Platform{platform.PlatformWSL, platform.PlatformWindows}
		scripts["uninstall"] = []platform.Platform{platform.PlatformWSL, platform.PlatformWindows}

	default:
		// Default to shell scripts for unknown platforms
		scripts["install"] = []platform.Platform{platform.PlatformUnix}
		scripts["uninstall"] = []platform.Platform{platform.PlatformUnix}
	}

	return scripts
}

// generateScript generates a single script file
func (cmd *InitCommand) generateScript(scriptType string, targetPlatform platform.Platform, outputDir string) error {
	// Generate script content
	scriptContent, err := cmd.scriptGen.GetScriptContent(scriptType, targetPlatform)
	if err != nil {
		return fmt.Errorf("failed to generate script content: %w", err)
	}

	// Determine filename
	filename := cmd.getScriptFilename(scriptType, targetPlatform)
	scriptPath := filepath.Join(outputDir, filename)

	// Determine file permissions
	fileMode := cmd.getScriptFileMode(targetPlatform)

	// Write script file
	if err := os.WriteFile(scriptPath, []byte(scriptContent), fileMode); err != nil {
		return fmt.Errorf("failed to write script file %s: %w", scriptPath, err)
	}

	return nil
}

// getScriptFilename returns the appropriate filename for a script
func (cmd *InitCommand) getScriptFilename(scriptType string, targetPlatform platform.Platform) string {
	switch targetPlatform {
	case platform.PlatformWindows:
		return fmt.Sprintf("%s.ps1", scriptType)
	case platform.PlatformUnix, platform.PlatformWSL:
		return fmt.Sprintf("%s.sh", scriptType)
	default:
		return fmt.Sprintf("%s.sh", scriptType)
	}
}

// getScriptFileMode returns the appropriate file permissions for a script
func (cmd *InitCommand) getScriptFileMode(targetPlatform platform.Platform) os.FileMode {
	switch targetPlatform {
	case platform.PlatformWindows:
		// Windows doesn't use Unix permissions, but we set readable
		return 0644
	case platform.PlatformUnix, platform.PlatformWSL:
		// Unix-like systems need executable permission
		return 0755
	default:
		return 0755
	}
}

// initializeCA initializes the CA certificate with force option
func (cmd *InitCommand) initializeCA(force bool) (bool, error) {
	// Check if CA already exists
	caExists := cmd.caManager.CAExists()

	if caExists && !force {
		// CA exists and no force flag, show certificate info
		caCert, err := cmd.caManager.GetCACertificate()
		if err != nil {
			return false, fmt.Errorf("failed to get existing CA certificate: %w", err)
		}

		fmt.Printf("\n📋 Using existing CA certificate:\n")
		fmt.Printf("   Subject: %s\n", caCert.Certificate.Subject.CommonName)
		fmt.Printf("   Valid until: %s\n", caCert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST"))

		// Check if certificate is expiring soon (within 30 days)
		daysUntilExpiry := int(time.Until(caCert.Certificate.NotAfter).Hours() / 24)
		if daysUntilExpiry < 30 {
			fmt.Printf("   ⚠️  Certificate expires in %d days\n", daysUntilExpiry)
			fmt.Printf("   Consider using --force to regenerate\n")
		} else {
			fmt.Printf("   ✅ Certificate is valid for %d more days\n", daysUntilExpiry)
		}
		fmt.Println()

		return true, nil
	}

	if force && caExists {
		fmt.Printf("\n🔄 Force flag specified, regenerating CA certificate...\n")
	}

	// Initialize or regenerate CA
	if err := cmd.caManager.InitializeCAWithForce(force); err != nil {
		return false, fmt.Errorf("failed to initialize CA: %w", err)
	}

	if force && caExists {
		// Show new certificate info
		caCert, err := cmd.caManager.GetCACertificate()
		if err != nil {
			return false, fmt.Errorf("failed to get new CA certificate: %w", err)
		}

		fmt.Printf("📋 New CA certificate generated:\n")
		fmt.Printf("   Subject: %s\n", caCert.Certificate.Subject.CommonName)
		fmt.Printf("   Valid until: %s\n", caCert.Certificate.NotAfter.Format("2006-01-02 15:04:05 MST"))
		fmt.Println()
	}

	return caExists, nil
}

// displayCompletionMessage shows completion message with platform-specific instructions
func (cmd *InitCommand) displayCompletionMessage(caExisted bool, force bool) {
	currentDir, _ := os.Getwd()

	fmt.Println()
	fmt.Println("🎉 MyEncrypt initialization completed successfully!")
	fmt.Println()
	fmt.Printf("Generated files in %s:\n", currentDir)
	fmt.Println("  📄 rootCA.pem - CA certificate for manual installation")
	fmt.Println()
	configPath := cmd.config.GetCertStorePath()
	if caExisted && !force {
		fmt.Printf("Using existing configuration in %s:\n", configPath)
	} else {
		fmt.Printf("Created configuration in %s:\n", configPath)
	}
	fmt.Println("  📄 config.yaml - MyEncrypt configuration file")
	fmt.Println("  📄 rootCA.pem - CA certificate (master copy)")
	fmt.Println("  🔐 rootCA-key.pem - CA private key (keep secure!)")
	fmt.Println("  📄 allowed-domains.txt - Allowed domains configuration")
	fmt.Println()

	// List generated scripts based on platform
	currentPlatform := cmd.platformMgr.GetPlatform()
	switch currentPlatform {
	case platform.PlatformWindows:
		fmt.Println("  📜 install.ps1 - PowerShell installation script")
		fmt.Println("  📜 uninstall.ps1 - PowerShell uninstallation script")
		fmt.Println()
		fmt.Println("To install the CA certificate:")
		fmt.Println("  PowerShell: .\\install.ps1")
		fmt.Println()
		fmt.Println("To uninstall the CA certificate:")
		fmt.Println("  PowerShell: .\\uninstall.ps1")

	case platform.PlatformUnix:
		fmt.Println("  📜 install.sh - Shell installation script")
		fmt.Println("  📜 uninstall.sh - Shell uninstallation script")
		fmt.Println()
		if cmd.platformMgr.GetOS() == "darwin" {
			fmt.Println("To install the CA certificate on macOS:")
		} else {
			fmt.Println("To install the CA certificate on Linux:")
		}
		fmt.Println("  ./install.sh")
		fmt.Println()
		fmt.Println("To uninstall the CA certificate:")
		fmt.Println("  ./uninstall.sh")

	case platform.PlatformWSL:
		fmt.Println("  📜 install.sh - Shell installation script (for WSL)")
		fmt.Println("  📜 uninstall.sh - Shell uninstallation script (for WSL)")
		fmt.Println("  📜 install.ps1 - PowerShell installation script (for Windows host)")
		fmt.Println("  📜 uninstall.ps1 - PowerShell uninstallation script (for Windows host)")
		fmt.Println()
		fmt.Println("To install the CA certificate:")
		fmt.Println("  WSL: ./install.sh (installs in both WSL and Windows host)")
		fmt.Println("  Windows: .\\install.ps1 (from Windows PowerShell)")
		fmt.Println()
		fmt.Println("To uninstall the CA certificate:")
		fmt.Println("  WSL: ./uninstall.sh (removes from both WSL and Windows host)")
		fmt.Println("  Windows: .\\uninstall.ps1 (from Windows PowerShell)")

	default:
		fmt.Println("  📜 install.sh - Shell installation script")
		fmt.Println("  📜 uninstall.sh - Shell uninstallation script")
		fmt.Println()
		fmt.Println("To install the CA certificate:")
		fmt.Println("  ./install.sh")
		fmt.Println()
		fmt.Println("To uninstall the CA certificate:")
		fmt.Println("  ./uninstall.sh")
	}

	fmt.Println()
	fmt.Printf("Platform detected: %s\n", cmd.platformMgr.GetPlatformString())
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("1. Run the installation script to add the CA certificate to your system trust store")
	fmt.Println("2. Start the MyEncrypt service: myencrypt service start")
	fmt.Println("3. Configure your applications to use the ACME server at http://localhost:14000")
	fmt.Println()
	fmt.Println("For more information, visit: https://github.com/myencrypt/myencrypt")
}

// initializeAllowedDomainsFile creates the allowed-domains.txt file with default domains
func (cmd *InitCommand) initializeAllowedDomainsFile() error {
	allowedDomainsPath := filepath.Join(cmd.config.GetCertStorePath(), "allowed-domains.txt")

	// Check if file already exists
	if _, err := os.Stat(allowedDomainsPath); err == nil {
		// File exists, don't overwrite
		return nil
	}

	// Create the file with default domains
	file, err := os.Create(allowedDomainsPath)
	if err != nil {
		return fmt.Errorf("failed to create allowed-domains.txt: %w", err)
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

	// Write default domains
	for _, domain := range cmd.config.DefaultAllowedDomains {
		if _, err := fmt.Fprintf(file, "%s\n", domain); err != nil {
			return fmt.Errorf("failed to write domain %s: %w", domain, err)
		}
	}

	return nil
}
