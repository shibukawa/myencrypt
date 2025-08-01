package scriptgen

import (
	"fmt"

	"github.com/shibukawayoshiki/myencrypt2/internal/platform"
)

// Generator handles script generation for different platforms
type Generator struct {
	platformMgr *platform.Manager
}

// New creates a new script generator
func New(platformMgr *platform.Manager) *Generator {
	return &Generator{
		platformMgr: platformMgr,
	}
}

// GenerateInstallScript generates an install script for the specified platform
func (g *Generator) GenerateInstallScript(caCertPath string, targetPlatform platform.Platform) (string, error) {
	switch targetPlatform {
	case platform.PlatformUnix:
		return g.generateUnixInstallScript(caCertPath), nil
	case platform.PlatformWindows:
		return g.generateWindowsInstallScript(caCertPath), nil
	case platform.PlatformWSL:
		// For WSL, we generate Unix script but with additional Windows host support
		return g.generateWSLInstallScript(caCertPath), nil
	default:
		return "", fmt.Errorf("unsupported platform: %s", targetPlatform)
	}
}

// GenerateUninstallScript generates an uninstall script for the specified platform
func (g *Generator) GenerateUninstallScript(caCertPath string, targetPlatform platform.Platform) (string, error) {
	switch targetPlatform {
	case platform.PlatformUnix:
		return g.generateUnixUninstallScript(caCertPath), nil
	case platform.PlatformWindows:
		return g.generateWindowsUninstallScript(caCertPath), nil
	case platform.PlatformWSL:
		// For WSL, we generate Unix script but with additional Windows host support
		return g.generateWSLUninstallScript(caCertPath), nil
	default:
		return "", fmt.Errorf("unsupported platform: %s", targetPlatform)
	}
}

// generateUnixInstallScript generates install script for Linux/macOS
func (g *Generator) generateUnixInstallScript(caCertPath string) string {
	return `#!/bin/bash

# MyEncrypt CA Certificate Installation Script
# This script installs the MyEncrypt CA certificate to the system trust store

set -e

CA_CERT_FILE="rootCA.pem"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_CERT_PATH="${SCRIPT_DIR}/${CA_CERT_FILE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if CA certificate file exists
if [ ! -f "${CA_CERT_PATH}" ]; then
    print_error "CA certificate file not found: ${CA_CERT_PATH}"
    print_error "Please run 'myencrypt init' first to generate the CA certificate."
    exit 1
fi

# Detect OS and install accordingly
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

# Install on macOS
install_macos() {
    print_info "Installing CA certificate on macOS..."
    
    # Add to system keychain
    if sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${CA_CERT_PATH}"; then
        print_info "CA certificate successfully installed to macOS system keychain"
    else
        print_error "Failed to install CA certificate to macOS system keychain"
        return 1
    fi
    
    # Also add to user keychain for applications that don't use system keychain
    if security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain "${CA_CERT_PATH}"; then
        print_info "CA certificate also installed to user keychain"
    else
        print_warning "Failed to install CA certificate to user keychain (this is usually not critical)"
    fi
}

# Install on Linux
install_linux() {
    print_info "Installing CA certificate on Linux..."
    
    # Detect Linux distribution and package manager
    if command -v update-ca-certificates >/dev/null 2>&1; then
        # Debian/Ubuntu based
        CERT_DIR="/usr/local/share/ca-certificates"
        CERT_FILE="${CERT_DIR}/myencrypt-ca.crt"
        
        print_info "Detected Debian/Ubuntu-based system"
        sudo mkdir -p "${CERT_DIR}"
        sudo cp "${CA_CERT_PATH}" "${CERT_FILE}"
        sudo update-ca-certificates
        
    elif command -v update-ca-trust >/dev/null 2>&1; then
        # RedHat/CentOS/Fedora based
        CERT_DIR="/etc/pki/ca-trust/source/anchors"
        CERT_FILE="${CERT_DIR}/myencrypt-ca.crt"
        
        print_info "Detected RedHat/CentOS/Fedora-based system"
        sudo mkdir -p "${CERT_DIR}"
        sudo cp "${CA_CERT_PATH}" "${CERT_FILE}"
        sudo update-ca-trust
        
    elif [ -d "/etc/ssl/certs" ]; then
        # Generic Linux with /etc/ssl/certs
        CERT_DIR="/etc/ssl/certs"
        CERT_FILE="${CERT_DIR}/myencrypt-ca.pem"
        
        print_info "Using generic Linux certificate directory"
        sudo cp "${CA_CERT_PATH}" "${CERT_FILE}"
        
        # Try to update certificate hash links
        if command -v c_rehash >/dev/null 2>&1; then
            sudo c_rehash "${CERT_DIR}"
        fi
        
    else
        print_error "Unable to determine Linux certificate installation method"
        print_error "Please manually install the CA certificate: ${CA_CERT_PATH}"
        return 1
    fi
    
    print_info "CA certificate successfully installed on Linux"
}

# Main installation logic
main() {
    print_info "MyEncrypt CA Certificate Installation"
    print_info "CA Certificate: ${CA_CERT_PATH}"
    
    OS=$(detect_os)
    case $OS in
        "macos")
            install_macos
            ;;
        "linux")
            install_linux
            ;;
        *)
            print_error "Unsupported operating system: $OSTYPE"
            print_error "Please manually install the CA certificate: ${CA_CERT_PATH}"
            exit 1
            ;;
    esac
    
    print_info "Installation completed successfully!"
    print_info "You may need to restart your browser or applications to recognize the new CA certificate."
}

# Run main function
main "$@"
`
}

// generateUnixUninstallScript generates uninstall script for Linux/macOS
func (g *Generator) generateUnixUninstallScript(caCertPath string) string {
	return `#!/bin/bash

# MyEncrypt CA Certificate Uninstallation Script
# This script removes the MyEncrypt CA certificate from the system trust store

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect OS and uninstall accordingly
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    else
        echo "unknown"
    fi
}

# Uninstall from macOS
uninstall_macos() {
    print_info "Removing CA certificate from macOS..."
    
    # Find and remove from system keychain
    CERT_HASH=$(security find-certificate -c "MyEncrypt Local CA" -Z /Library/Keychains/System.keychain 2>/dev/null | grep "SHA-1 hash:" | cut -d' ' -f3 || true)
    
    if [ -n "$CERT_HASH" ]; then
        if sudo security delete-certificate -Z "$CERT_HASH" /Library/Keychains/System.keychain; then
            print_info "CA certificate removed from macOS system keychain"
        else
            print_warning "Failed to remove CA certificate from system keychain"
        fi
    else
        print_warning "MyEncrypt CA certificate not found in system keychain"
    fi
    
    # Find and remove from user keychain
    USER_CERT_HASH=$(security find-certificate -c "MyEncrypt Local CA" -Z ~/Library/Keychains/login.keychain 2>/dev/null | grep "SHA-1 hash:" | cut -d' ' -f3 || true)
    
    if [ -n "$USER_CERT_HASH" ]; then
        if security delete-certificate -Z "$USER_CERT_HASH" ~/Library/Keychains/login.keychain; then
            print_info "CA certificate removed from user keychain"
        else
            print_warning "Failed to remove CA certificate from user keychain"
        fi
    else
        print_warning "MyEncrypt CA certificate not found in user keychain"
    fi
}

# Uninstall from Linux
uninstall_linux() {
    print_info "Removing CA certificate from Linux..."
    
    REMOVED=false
    
    # Check Debian/Ubuntu based systems
    if [ -f "/usr/local/share/ca-certificates/myencrypt-ca.crt" ]; then
        print_info "Removing from Debian/Ubuntu-based system"
        sudo rm -f "/usr/local/share/ca-certificates/myencrypt-ca.crt"
        sudo update-ca-certificates --fresh
        REMOVED=true
    fi
    
    # Check RedHat/CentOS/Fedora based systems
    if [ -f "/etc/pki/ca-trust/source/anchors/myencrypt-ca.crt" ]; then
        print_info "Removing from RedHat/CentOS/Fedora-based system"
        sudo rm -f "/etc/pki/ca-trust/source/anchors/myencrypt-ca.crt"
        sudo update-ca-trust
        REMOVED=true
    fi
    
    # Check generic Linux location
    if [ -f "/etc/ssl/certs/myencrypt-ca.pem" ]; then
        print_info "Removing from generic Linux certificate directory"
        sudo rm -f "/etc/ssl/certs/myencrypt-ca.pem"
        
        # Try to update certificate hash links
        if command -v c_rehash >/dev/null 2>&1; then
            sudo c_rehash "/etc/ssl/certs"
        fi
        REMOVED=true
    fi
    
    if [ "$REMOVED" = true ]; then
        print_info "CA certificate successfully removed from Linux"
    else
        print_warning "MyEncrypt CA certificate not found in standard locations"
    fi
}

# Main uninstallation logic
main() {
    print_info "MyEncrypt CA Certificate Uninstallation"
    
    OS=$(detect_os)
    case $OS in
        "macos")
            uninstall_macos
            ;;
        "linux")
            uninstall_linux
            ;;
        *)
            print_error "Unsupported operating system: $OSTYPE"
            exit 1
            ;;
    esac
    
    print_info "Uninstallation completed!"
    print_info "You may need to restart your browser or applications to stop recognizing the removed CA certificate."
}

# Run main function
main "$@"
`
}

// generateWindowsInstallScript generates install script for Windows
func (g *Generator) generateWindowsInstallScript(caCertPath string) string {
	return `# MyEncrypt CA Certificate Installation Script for Windows
# This script installs the MyEncrypt CA certificate to the Windows certificate store

param(
    [switch]$Force = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$CACertFile = "rootCA.pem"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$CACertPath = Join-Path $ScriptDir $CACertFile

# Function to write colored output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to install CA certificate
function Install-CACertificate {
    param(
        [string]$CertPath,
        [string]$StoreName,
        [string]$StoreLocation
    )
    
    try {
        # Load the certificate
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
        
        # Open the certificate store
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        
        # Check if certificate already exists
        $existingCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($existingCert -and -not $Force) {
            Write-Warning "Certificate already exists in $StoreLocation\$StoreName store"
            return $false
        }
        
        # Add the certificate
        $store.Add($cert)
        $store.Close()
        
        Write-Info "Certificate installed to $StoreLocation\$StoreName store"
        return $true
    }
    catch {
        Write-Error "Failed to install certificate to $StoreLocation\$StoreName store: $($_.Exception.Message)"
        return $false
    }
}

# Main installation logic
function Main {
    Write-Info "MyEncrypt CA Certificate Installation for Windows"
    Write-Info "CA Certificate: $CACertPath"
    
    # Check if CA certificate file exists
    if (-not (Test-Path $CACertPath)) {
        Write-Error "CA certificate file not found: $CACertPath"
        Write-Error "Please run 'myencrypt init' first to generate the CA certificate."
        exit 1
    }
    
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        Write-Warning "This script is not running as Administrator."
        Write-Warning "Installing to Current User certificate store only."
        Write-Warning "For system-wide installation, run PowerShell as Administrator."
    }
    
    $success = $false
    
    # Install to Current User Root store (always possible)
    Write-Info "Installing CA certificate to Current User Root certificate store..."
    if (Install-CACertificate -CertPath $CACertPath -StoreName "Root" -StoreLocation "CurrentUser") {
        $success = $true
    }
    
    # Install to Local Machine Root store (requires administrator)
    if (Test-Administrator) {
        Write-Info "Installing CA certificate to Local Machine Root certificate store..."
        if (Install-CACertificate -CertPath $CACertPath -StoreName "Root" -StoreLocation "LocalMachine") {
            $success = $true
        }
    }
    
    if ($success) {
        Write-Info "Installation completed successfully!"
        Write-Info "You may need to restart your browser or applications to recognize the new CA certificate."
    } else {
        Write-Error "Installation failed!"
        exit 1
    }
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    exit 1
}
`
}

// generateWindowsUninstallScript generates uninstall script for Windows
func (g *Generator) generateWindowsUninstallScript(caCertPath string) string {
	return `# MyEncrypt CA Certificate Uninstallation Script for Windows
# This script removes the MyEncrypt CA certificate from the Windows certificate store

param(
    [switch]$Force = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to write colored output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to remove CA certificate
function Remove-CACertificate {
    param(
        [string]$StoreName,
        [string]$StoreLocation
    )
    
    try {
        # Open the certificate store
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, $StoreLocation)
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        
        # Find MyEncrypt certificates
        $myencryptCerts = $store.Certificates | Where-Object { 
            $_.Subject -like "*MyEncrypt*" -or 
            $_.Issuer -like "*MyEncrypt*" -or
            $_.Subject -like "*myencrypt*" -or
            $_.Issuer -like "*myencrypt*"
        }
        
        $removed = 0
        foreach ($cert in $myencryptCerts) {
            Write-Info "Removing certificate: $($cert.Subject) (Thumbprint: $($cert.Thumbprint))"
            $store.Remove($cert)
            $removed++
        }
        
        $store.Close()
        
        if ($removed -gt 0) {
            Write-Info "Removed $removed certificate(s) from $StoreLocation\$StoreName store"
            return $true
        } else {
            Write-Warning "No MyEncrypt certificates found in $StoreLocation\$StoreName store"
            return $false
        }
    }
    catch {
        Write-Error "Failed to remove certificates from $StoreLocation\$StoreName store: $($_.Exception.Message)"
        return $false
    }
}

# Main uninstallation logic
function Main {
    Write-Info "MyEncrypt CA Certificate Uninstallation for Windows"
    
    # Check if running as administrator
    if (-not (Test-Administrator)) {
        Write-Warning "This script is not running as Administrator."
        Write-Warning "Can only remove certificates from Current User certificate store."
        Write-Warning "For system-wide removal, run PowerShell as Administrator."
    }
    
    $success = $false
    
    # Remove from Current User Root store
    Write-Info "Removing CA certificates from Current User Root certificate store..."
    if (Remove-CACertificate -StoreName "Root" -StoreLocation "CurrentUser") {
        $success = $true
    }
    
    # Remove from Local Machine Root store (requires administrator)
    if (Test-Administrator) {
        Write-Info "Removing CA certificates from Local Machine Root certificate store..."
        if (Remove-CACertificate -StoreName "Root" -StoreLocation "LocalMachine") {
            $success = $true
        }
    }
    
    if ($success) {
        Write-Info "Uninstallation completed successfully!"
        Write-Info "You may need to restart your browser or applications to stop recognizing the removed CA certificate."
    } else {
        Write-Warning "No MyEncrypt certificates were found or removed."
    }
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    exit 1
}
`
}

// generateWSLInstallScript generates install script for WSL environment
func (g *Generator) generateWSLInstallScript(caCertPath string) string {
	return `#!/bin/bash

# MyEncrypt CA Certificate Installation Script for WSL
# This script installs the MyEncrypt CA certificate to both WSL and Windows host

set -e

CA_CERT_FILE="rootCA.pem"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_CERT_PATH="${SCRIPT_DIR}/${CA_CERT_FILE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if CA certificate file exists
if [ ! -f "${CA_CERT_PATH}" ]; then
    print_error "CA certificate file not found: ${CA_CERT_PATH}"
    print_error "Please run 'myencrypt init' first to generate the CA certificate."
    exit 1
fi

# Install on WSL Linux
install_wsl_linux() {
    print_info "Installing CA certificate in WSL Linux environment..."
    
    # Detect Linux distribution and install accordingly
    if command -v update-ca-certificates >/dev/null 2>&1; then
        # Debian/Ubuntu based
        CERT_DIR="/usr/local/share/ca-certificates"
        CERT_FILE="${CERT_DIR}/myencrypt-ca.crt"
        
        print_info "Installing to WSL Debian/Ubuntu-based system"
        sudo mkdir -p "${CERT_DIR}"
        sudo cp "${CA_CERT_PATH}" "${CERT_FILE}"
        sudo update-ca-certificates
        
    elif command -v update-ca-trust >/dev/null 2>&1; then
        # RedHat/CentOS/Fedora based
        CERT_DIR="/etc/pki/ca-trust/source/anchors"
        CERT_FILE="${CERT_DIR}/myencrypt-ca.crt"
        
        print_info "Installing to WSL RedHat/CentOS/Fedora-based system"
        sudo mkdir -p "${CERT_DIR}"
        sudo cp "${CA_CERT_PATH}" "${CERT_FILE}"
        sudo update-ca-trust
        
    else
        print_warning "Unable to determine WSL Linux certificate installation method"
        print_warning "Skipping WSL Linux certificate installation"
        return 1
    fi
    
    print_info "CA certificate successfully installed in WSL Linux"
    return 0
}

# Install on Windows host via PowerShell
install_windows_host() {
    print_info "Installing CA certificate on Windows host..."
    
    # Check if PowerShell is available
    if ! command -v powershell.exe >/dev/null 2>&1; then
        print_warning "PowerShell not available. Cannot install certificate on Windows host."
        print_warning "Please run install.ps1 manually from Windows to install the certificate on the host."
        return 1
    fi
    
    # Convert WSL path to Windows path
    WINDOWS_CERT_PATH=$(wslpath -w "${CA_CERT_PATH}")
    
    # PowerShell script to install certificate
    POWERSHELL_SCRIPT="
        try {
            \$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('${WINDOWS_CERT_PATH}')
            \$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
            \$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            # Check if certificate already exists
            \$existingCert = \$store.Certificates | Where-Object { \$_.Thumbprint -eq \$cert.Thumbprint }
            if (\$existingCert) {
                Write-Host 'Certificate already exists in Windows certificate store'
                \$store.Close()
                exit 0
            }
            
            \$store.Add(\$cert)
            \$store.Close()
            Write-Host 'Certificate installed to Windows certificate store'
            exit 0
        }
        catch {
            Write-Host \"Failed to install certificate: \$(\$_.Exception.Message)\"
            exit 1
        }
    "
    
    if powershell.exe -Command "$POWERSHELL_SCRIPT"; then
        print_info "CA certificate successfully installed on Windows host"
        return 0
    else
        print_warning "Failed to install certificate on Windows host"
        print_warning "Please run install.ps1 manually from Windows to install the certificate on the host."
        return 1
    fi
}

# Main installation logic
main() {
    print_info "MyEncrypt CA Certificate Installation for WSL"
    print_info "CA Certificate: ${CA_CERT_PATH}"
    print_info "This script will install the certificate in both WSL and Windows host environments"
    
    WSL_SUCCESS=false
    WINDOWS_SUCCESS=false
    
    # Install in WSL Linux
    if install_wsl_linux; then
        WSL_SUCCESS=true
    fi
    
    # Install on Windows host
    if install_windows_host; then
        WINDOWS_SUCCESS=true
    fi
    
    # Summary
    print_info "Installation Summary:"
    if [ "$WSL_SUCCESS" = true ]; then
        print_info "✓ WSL Linux: Certificate installed successfully"
    else
        print_warning "✗ WSL Linux: Certificate installation failed"
    fi
    
    if [ "$WINDOWS_SUCCESS" = true ]; then
        print_info "✓ Windows Host: Certificate installed successfully"
    else
        print_warning "✗ Windows Host: Certificate installation failed or skipped"
    fi
    
    if [ "$WSL_SUCCESS" = true ] || [ "$WINDOWS_SUCCESS" = true ]; then
        print_info "Installation completed!"
        print_info "You may need to restart your browser or applications to recognize the new CA certificate."
    else
        print_error "Installation failed for both environments!"
        exit 1
    fi
}

# Run main function
main "$@"
`
}

// generateWSLUninstallScript generates uninstall script for WSL environment
func (g *Generator) generateWSLUninstallScript(caCertPath string) string {
	return `#!/bin/bash

# MyEncrypt CA Certificate Uninstallation Script for WSL
# This script removes the MyEncrypt CA certificate from both WSL and Windows host

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Uninstall from WSL Linux
uninstall_wsl_linux() {
    print_info "Removing CA certificate from WSL Linux environment..."
    
    REMOVED=false
    
    # Check Debian/Ubuntu based systems
    if [ -f "/usr/local/share/ca-certificates/myencrypt-ca.crt" ]; then
        print_info "Removing from WSL Debian/Ubuntu-based system"
        sudo rm -f "/usr/local/share/ca-certificates/myencrypt-ca.crt"
        sudo update-ca-certificates --fresh
        REMOVED=true
    fi
    
    # Check RedHat/CentOS/Fedora based systems
    if [ -f "/etc/pki/ca-trust/source/anchors/myencrypt-ca.crt" ]; then
        print_info "Removing from WSL RedHat/CentOS/Fedora-based system"
        sudo rm -f "/etc/pki/ca-trust/source/anchors/myencrypt-ca.crt"
        sudo update-ca-trust
        REMOVED=true
    fi
    
    if [ "$REMOVED" = true ]; then
        print_info "CA certificate successfully removed from WSL Linux"
        return 0
    else
        print_warning "MyEncrypt CA certificate not found in WSL Linux standard locations"
        return 1
    fi
}

# Uninstall from Windows host via PowerShell
uninstall_windows_host() {
    print_info "Removing CA certificate from Windows host..."
    
    # Check if PowerShell is available
    if ! command -v powershell.exe >/dev/null 2>&1; then
        print_warning "PowerShell not available. Cannot remove certificate from Windows host."
        print_warning "Please run uninstall.ps1 manually from Windows to remove the certificate from the host."
        return 1
    fi
    
    # PowerShell script to remove certificate
    POWERSHELL_SCRIPT="
        try {
            \$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
            \$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            # Find MyEncrypt certificates
            \$myencryptCerts = \$store.Certificates | Where-Object { 
                \$_.Subject -like '*MyEncrypt*' -or 
                \$_.Issuer -like '*MyEncrypt*' -or
                \$_.Subject -like '*myencrypt*' -or
                \$_.Issuer -like '*myencrypt*'
            }
            
            \$removed = 0
            foreach (\$cert in \$myencryptCerts) {
                Write-Host \"Removing certificate: \$(\$cert.Subject)\"
                \$store.Remove(\$cert)
                \$removed++
            }
            
            \$store.Close()
            
            if (\$removed -gt 0) {
                Write-Host \"Removed \$removed certificate(s) from Windows certificate store\"
                exit 0
            } else {
                Write-Host \"No MyEncrypt certificates found in Windows certificate store\"
                exit 1
            }
        }
        catch {
            Write-Host \"Failed to remove certificates: \$(\$_.Exception.Message)\"
            exit 1
        }
    "
    
    if powershell.exe -Command "$POWERSHELL_SCRIPT"; then
        print_info "CA certificate successfully removed from Windows host"
        return 0
    else
        print_warning "Failed to remove certificate from Windows host or no certificates found"
        return 1
    fi
}

# Main uninstallation logic
main() {
    print_info "MyEncrypt CA Certificate Uninstallation for WSL"
    print_info "This script will remove the certificate from both WSL and Windows host environments"
    
    WSL_SUCCESS=false
    WINDOWS_SUCCESS=false
    
    # Remove from WSL Linux
    if uninstall_wsl_linux; then
        WSL_SUCCESS=true
    fi
    
    # Remove from Windows host
    if uninstall_windows_host; then
        WINDOWS_SUCCESS=true
    fi
    
    # Summary
    print_info "Uninstallation Summary:"
    if [ "$WSL_SUCCESS" = true ]; then
        print_info "✓ WSL Linux: Certificate removed successfully"
    else
        print_warning "✗ WSL Linux: Certificate removal failed or not found"
    fi
    
    if [ "$WINDOWS_SUCCESS" = true ]; then
        print_info "✓ Windows Host: Certificate removed successfully"
    else
        print_warning "✗ Windows Host: Certificate removal failed or not found"
    fi
    
    if [ "$WSL_SUCCESS" = true ] || [ "$WINDOWS_SUCCESS" = true ]; then
        print_info "Uninstallation completed!"
        print_info "You may need to restart your browser or applications to stop recognizing the removed CA certificate."
    else
        print_warning "No certificates were found or removed from either environment."
    fi
}

# Run main function
main "$@"
`
}

// GetScriptContent returns the script content for a given script type and platform
func (g *Generator) GetScriptContent(scriptType string, targetPlatform platform.Platform) (string, error) {
	switch scriptType {
	case "install":
		return g.GenerateInstallScript("", targetPlatform)
	case "uninstall":
		return g.GenerateUninstallScript("", targetPlatform)
	default:
		return "", fmt.Errorf("unknown script type: %s", scriptType)
	}
}

// GetScriptFilename returns the appropriate filename for a script
func (g *Generator) GetScriptFilename(scriptType string, targetPlatform platform.Platform) string {
	switch targetPlatform {
	case platform.PlatformWindows, platform.PlatformWSL:
		if targetPlatform == platform.PlatformWSL {
			// For WSL, we generate shell scripts
			return fmt.Sprintf("%s.sh", scriptType)
		}
		return fmt.Sprintf("%s.ps1", scriptType)
	case platform.PlatformUnix:
		return fmt.Sprintf("%s.sh", scriptType)
	default:
		return fmt.Sprintf("%s.sh", scriptType)
	}
}

// GetAllScriptFilenames returns all script filenames that should be generated for a platform
func (g *Generator) GetAllScriptFilenames(targetPlatform platform.Platform) []string {
	var filenames []string

	switch targetPlatform {
	case platform.PlatformWindows:
		filenames = []string{"install.ps1", "uninstall.ps1"}
	case platform.PlatformUnix:
		filenames = []string{"install.sh", "uninstall.sh"}
	case platform.PlatformWSL:
		// WSL needs both shell scripts (for WSL) and PowerShell scripts (for Windows host)
		filenames = []string{"install.sh", "uninstall.sh", "install.ps1", "uninstall.ps1"}
	default:
		filenames = []string{"install.sh", "uninstall.sh"}
	}

	return filenames
}
