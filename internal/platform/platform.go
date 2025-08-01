package platform

import (
	"os"
	"runtime"
	"strings"
)

// Platform represents the operating system platform
type Platform string

const (
	PlatformUnix    Platform = "unix" // Linux/macOS共通
	PlatformWindows Platform = "windows"
	PlatformWSL     Platform = "wsl"
)

// Manager handles platform-specific operations
type Manager struct {
	platform Platform
	isWSL    bool
}

// New creates a new platform manager with automatic OS detection
func New() *Manager {
	return &Manager{
		platform: detectPlatform(),
		isWSL:    detectWSL(),
	}
}

// GetPlatform returns the detected platform
func (m *Manager) GetPlatform() Platform {
	if m.isWSL {
		return PlatformWSL
	}
	return m.platform
}

// IsWSL returns true if running in WSL environment
func (m *Manager) IsWSL() bool {
	return m.isWSL
}

// GetArchitecture returns the system architecture
func (m *Manager) GetArchitecture() string {
	return runtime.GOARCH
}

// GetOS returns the runtime OS
func (m *Manager) GetOS() string {
	return runtime.GOOS
}

// detectPlatform detects the base platform using runtime.GOOS
func detectPlatform() Platform {
	switch runtime.GOOS {
	case "windows":
		return PlatformWindows
	case "linux", "darwin":
		return PlatformUnix
	default:
		// Default to unix for other Unix-like systems
		return PlatformUnix
	}
}

// detectWSL detects if running in Windows Subsystem for Linux
func detectWSL() bool {
	// WSL detection is only relevant on Linux
	if runtime.GOOS != "linux" {
		return false
	}

	// Check for WSL-specific environment variables and files
	// WSL sets these environment variables
	if wslDistro := os.Getenv("WSL_DISTRO_NAME"); wslDistro != "" {
		return true
	}

	if wslInterop := os.Getenv("WSL_INTEROP"); wslInterop != "" {
		return true
	}

	// Check for WSL in /proc/version (fallback method)
	// This is a common way to detect WSL1/WSL2
	return checkProcVersion()
}

// checkProcVersion checks /proc/version for WSL indicators
func checkProcVersion() bool {
	// Read /proc/version to detect WSL
	content, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}

	versionStr := strings.ToLower(string(content))
	// WSL1 contains "Microsoft" in /proc/version
	// WSL2 contains "microsoft" or "WSL" in /proc/version
	return strings.Contains(versionStr, "microsoft") || strings.Contains(versionStr, "wsl")
}

// GetScriptExtension returns the appropriate script file extension for the platform
func (m *Manager) GetScriptExtension() string {
	switch m.GetPlatform() {
	case PlatformWindows, PlatformWSL:
		return ".ps1"
	case PlatformUnix:
		return ".sh"
	default:
		return ".sh"
	}
}

// GetInstallScriptName returns the install script filename for the platform
func (m *Manager) GetInstallScriptName() string {
	switch m.GetPlatform() {
	case PlatformWindows, PlatformWSL:
		return "install.ps1"
	case PlatformUnix:
		return "install.sh"
	default:
		return "install.sh"
	}
}

// GetUninstallScriptName returns the uninstall script filename for the platform
func (m *Manager) GetUninstallScriptName() string {
	switch m.GetPlatform() {
	case PlatformWindows, PlatformWSL:
		return "uninstall.ps1"
	case PlatformUnix:
		return "uninstall.sh"
	default:
		return "uninstall.sh"
	}
}

// IsUnixLike returns true if the platform is Unix-like (Linux, macOS, WSL)
func (m *Manager) IsUnixLike() bool {
	platform := m.GetPlatform()
	return platform == PlatformUnix || platform == PlatformWSL
}

// IsWindows returns true if the platform is Windows (native or WSL)
func (m *Manager) IsWindows() bool {
	return m.GetPlatform() == PlatformWindows
}

// GetPlatformString returns a human-readable platform string
func (m *Manager) GetPlatformString() string {
	switch m.GetPlatform() {
	case PlatformWindows:
		return "Windows"
	case PlatformUnix:
		if runtime.GOOS == "darwin" {
			return "macOS"
		}
		return "Linux"
	case PlatformWSL:
		return "WSL (Windows Subsystem for Linux)"
	default:
		return "Unknown"
	}
}

// GetScriptFilesForInit returns the list of script files to generate for init command
func (m *Manager) GetScriptFilesForInit() []string {
	var scripts []string

	switch m.GetPlatform() {
	case PlatformWindows:
		// Windows native - only PowerShell scripts
		scripts = []string{"install.ps1", "uninstall.ps1"}
	case PlatformUnix:
		// Linux/macOS - only shell scripts
		scripts = []string{"install.sh", "uninstall.sh"}
	case PlatformWSL:
		// WSL - both shell scripts (for WSL) and PowerShell scripts (for Windows host)
		scripts = []string{"install.sh", "uninstall.sh", "install.ps1", "uninstall.ps1"}
	default:
		// Default to shell scripts for unknown platforms
		scripts = []string{"install.sh", "uninstall.sh"}
	}

	return scripts
}

// ShouldGenerateShellScripts returns true if shell scripts should be generated
func (m *Manager) ShouldGenerateShellScripts() bool {
	platform := m.GetPlatform()
	return platform == PlatformUnix || platform == PlatformWSL
}

// ShouldGeneratePowerShellScripts returns true if PowerShell scripts should be generated
func (m *Manager) ShouldGeneratePowerShellScripts() bool {
	platform := m.GetPlatform()
	return platform == PlatformWindows || platform == PlatformWSL
}

// GetPrimaryScriptType returns the primary script type for the current platform
func (m *Manager) GetPrimaryScriptType() string {
	switch m.GetPlatform() {
	case PlatformWindows:
		return "powershell"
	case PlatformUnix, PlatformWSL:
		return "shell"
	default:
		return "shell"
	}
}

// SelectScriptFilesForInit selects appropriate script files for init command based on OS
func (m *Manager) SelectScriptFilesForInit() map[string]bool {
	selection := make(map[string]bool)

	// Always include CA certificate
	selection["rootCA.pem"] = true

	// Select scripts based on platform
	switch m.GetPlatform() {
	case PlatformWindows:
		// Windows native - only PowerShell scripts
		selection["install.ps1"] = true
		selection["uninstall.ps1"] = true
		selection["install.sh"] = false
		selection["uninstall.sh"] = false
	case PlatformUnix:
		// Linux/macOS - only shell scripts
		selection["install.sh"] = true
		selection["uninstall.sh"] = true
		selection["install.ps1"] = false
		selection["uninstall.ps1"] = false
	case PlatformWSL:
		// WSL - both shell scripts (for WSL) and PowerShell scripts (for Windows host)
		selection["install.sh"] = true
		selection["uninstall.sh"] = true
		selection["install.ps1"] = true
		selection["uninstall.ps1"] = true
	default:
		// Default to shell scripts for unknown platforms
		selection["install.sh"] = true
		selection["uninstall.sh"] = true
		selection["install.ps1"] = false
		selection["uninstall.ps1"] = false
	}

	return selection
}

// GetInitCommandInstructions returns platform-specific instructions for init command
func (m *Manager) GetInitCommandInstructions() string {
	switch m.GetPlatform() {
	case PlatformWindows:
		return "Generated PowerShell scripts for Windows. Run install.ps1 to install the CA certificate."
	case PlatformUnix:
		if runtime.GOOS == "darwin" {
			return "Generated shell scripts for macOS. Run install.sh to install the CA certificate."
		}
		return "Generated shell scripts for Linux. Run install.sh to install the CA certificate."
	case PlatformWSL:
		return "Generated scripts for WSL environment. Run install.sh for WSL and install.ps1 for Windows host."
	default:
		return "Generated shell scripts. Run install.sh to install the CA certificate."
	}
}
