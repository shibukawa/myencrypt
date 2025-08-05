package management

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"github.com/shibukawa/myencrypt/internal/certmanager"
	"github.com/shibukawa/myencrypt/internal/config"
	"github.com/shibukawa/myencrypt/internal/logger"
)

// Server represents the management server
type Server struct {
	config      *config.Config
	certManager certmanager.Manager
	logger      *logger.Logger
	dbPath      string // SQLite database path
}

// NewServer creates a new management server instance
func NewServer(cfg *config.Config, certMgr certmanager.Manager, log *logger.Logger) *Server {
	dbPath := filepath.Join(cfg.CertStorePath, "myencrypt.db")
	return &Server{
		config:      cfg,
		certManager: certMgr,
		logger:      log.WithComponent("management"),
		dbPath:      dbPath,
	}
}

// RegisterHandlers registers management HTTP handlers with the router
func (s *Server) RegisterHandlers(router *mux.Router) {
	// Health check endpoint
	router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Revocation endpoints
	router.HandleFunc("/revoke-account", s.handleRevokeAccount).Methods("POST")
	router.HandleFunc("/revoke-certificate", s.handleRevokeCertificate).Methods("POST")

	// Download endpoints
	downloadRouter := router.PathPrefix("/download").Subrouter()
	downloadRouter.HandleFunc("/certificate", s.handleDownloadCertificate).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/bundle.zip", s.handleDownloadBundle).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/install.sh", s.handleDownloadInstallSh).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/install.ps1", s.handleDownloadInstallPs1).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/uninstall.sh", s.handleDownloadUninstallSh).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/uninstall.ps1", s.handleDownloadUninstallPs1).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/uninstall-all.sh", s.handleDownloadUninstallAllSh).Methods("GET", "HEAD")
	downloadRouter.HandleFunc("/uninstall-all.ps1", s.handleDownloadUninstallAllPs1).Methods("GET", "HEAD")

	// Download page
	router.HandleFunc("/download/", s.handleWebUI).Methods("GET")

	// Web UI (management interface and download page)
	router.HandleFunc("/", s.handleWebUI).Methods("GET")
}

// Health check handler
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Health check requested", "remote_addr", r.RemoteAddr)

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Revocation handlers
func (s *Server) handleRevokeAccount(w http.ResponseWriter, r *http.Request) {
	accountID := r.FormValue("account_id")
	if accountID == "" {
		http.Error(w, "Missing account_id", http.StatusBadRequest)
		return
	}

	err := s.revokeAccount(accountID)
	if err != nil {
		s.logger.Error("Failed to revoke account", "account_id", accountID, "error", err)
		http.Error(w, "Failed to revoke account", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Account revoked", "account_id", accountID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	certID := r.FormValue("cert_id")
	if certID == "" {
		http.Error(w, "Missing cert_id", http.StatusBadRequest)
		return
	}

	err := s.revokeCertificate(certID)
	if err != nil {
		s.logger.Error("Failed to revoke certificate", "cert_id", certID, "error", err)
		http.Error(w, "Failed to revoke certificate", http.StatusInternalServerError)
		return
	}

	s.logger.Info("Certificate revoked", "cert_id", certID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Web UI handler
func (s *Server) handleWebUI(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		s.serveManagementInterface(w, r)
	case "/download/":
		s.serveDownloadInterface(w, r)
	default:
		http.NotFound(w, r)
	}
}

// Management interface (dashboard)
func (s *Server) serveManagementInterface(w http.ResponseWriter, r *http.Request) {
	// Get statistics
	stats, err := s.getStatistics()
	if err != nil {
		s.logger.Error("Failed to get statistics", "error", err)
		stats = &Statistics{} // Use empty stats on error
	}

	// Get accounts
	accounts, err := s.getAllAccounts()
	if err != nil {
		s.logger.Error("Failed to get accounts", "error", err)
		accounts = []*AccountInfo{} // Use empty slice on error
	}

	// Get certificates
	certificates, err := s.getAllCertificates()
	if err != nil {
		s.logger.Error("Failed to get certificates", "error", err)
		certificates = []*CertificateInfo{} // Use empty slice on error
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>MyEncrypt Management Console</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; color: #333; }
        .status { color: #28a745; font-weight: bold; margin-top: 5px; }
        .nav { background: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .nav a { text-decoration: none; color: #007acc; margin-right: 20px; font-weight: 500; }
        .nav a:hover { text-decoration: underline; }
        .section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { margin-top: 0; color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .empty-state { text-align: center; padding: 40px; color: #666; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007acc; }
        .stat-label { color: #666; margin-top: 5px; }
        table { width: 100%%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; color: #555; }
        .status-badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .status-valid { background: #d4edda; color: #155724; }
        .status-expired { background: #f8d7da; color: #721c24; }
        .status-revoked { background: #fff3cd; color: #856404; }
        .status-deactivated { background: #f8d7da; color: #721c24; }
        .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; text-decoration: none; display: inline-block; margin-right: 5px; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #5a6268; }
        .domains { font-size: 12px; color: #666; }
        .account-id { font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MyEncrypt Management Console</h1>
            <div class="status">🟢 Server Status: Running</div>
        </div>
        
        <div class="nav">
            <a href="/">Dashboard</a>
            <a href="/download/">Downloads</a>
            <a href="/health">API Health</a>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Active Accounts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Valid Certificates</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Expired Certificates</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div class="stat-label">Revoked Certificates</div>
            </div>
        </div>
        
        <div class="section">
            <h2>👤 ACME Accounts</h2>
            %s
        </div>
        
        <div class="section">
            <h2>📄 Certificates</h2>
            %s
        </div>
    </div>
</body>
</html>`,
		stats.ActiveAccounts,
		stats.ValidCertificates,
		stats.ExpiredCertificates,
		stats.RevokedCertificates,
		s.renderAccountsTable(accounts),
		s.renderCertificatesTable(certificates))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Download interface
func (s *Server) serveDownloadInterface(w http.ResponseWriter, r *http.Request) {
	// Detect OS from User-Agent
	userAgent := r.Header.Get("User-Agent")
	isWindows := strings.Contains(strings.ToLower(userAgent), "windows")

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	var oneLineCommand string
	var shellType string

	if isWindows {
		shellType = "PowerShell"
		oneLineCommand = fmt.Sprintf(`iwr -useb http://localhost:%d/download/install.ps1 | iex`, scriptPort)
	} else {
		shellType = "Bash"
		oneLineCommand = fmt.Sprintf(`/bin/bash -c "$(curl -fsSL http://localhost:%d/download/install.sh)"`, scriptPort)
	}

	// Docker-specific commands (same as regular commands now since we detect Docker automatically)
	dockerBashCommand := fmt.Sprintf(`curl -sSL http://localhost:%d/download/install.sh | bash`, scriptPort)
	dockerPowerShellCommand := fmt.Sprintf(`curl http://localhost:%d/download/install.ps1 -o install.ps1; .\\install.ps1`, scriptPort)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>MyEncrypt Downloads</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header h1 { margin: 0; color: #333; }
        .nav { background: white; padding: 15px 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .nav a { text-decoration: none; color: #007acc; margin-right: 20px; font-weight: 500; }
        .nav a:hover { text-decoration: underline; }
        .section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .section h2 { margin-top: 0; color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .api-endpoint { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #007acc; }
        .method { font-weight: bold; color: #007acc; margin-right: 10px; }
        .oneliner { background: #2d3748; color: #e2e8f0; padding: 20px; border-radius: 8px; font-family: 'Courier New', monospace; margin: 15px 0; position: relative; }
        .oneliner code { color: #68d391; font-size: 14px; }
        .copy-btn { 
            position: absolute; 
            top: 15px; 
            right: 15px; 
            background: #4a5568; 
            color: white; 
            border: none; 
            padding: 8px 12px; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 12px; 
            transition: all 0.2s ease;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        .copy-btn:hover { 
            background: #2d3748; 
            transform: translateY(-1px);
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .copy-btn:active {
            transform: translateY(0);
            box-shadow: 0 1px 2px rgba(0,0,0,0.3);
        }
        .highlight { background: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0; }
        .highlight h3 { margin-top: 0; color: #856404; }
        .docker-highlight { background: #e3f2fd; padding: 20px; border-radius: 8px; border-left: 4px solid #2196f3; margin: 20px 0; }
        .docker-highlight h3 { margin-top: 0; color: #1565c0; }
        .platform-tabs { display: flex; margin-bottom: 15px; }
        .platform-tab { background: #f0f0f0; padding: 10px 20px; border: none; cursor: pointer; border-radius: 4px 4px 0 0; margin-right: 5px; }
        .platform-tab.active { background: #007acc; color: white; }
        .platform-content { display: none; }
        .platform-content.active { display: block; }
    </style>
    <script>
        function copyToClipboard(text) {
            // Modern browsers with Clipboard API
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function() {
                    showCopySuccess();
                }).catch(function(err) {
                    console.error('Failed to copy with Clipboard API:', err);
                    fallbackCopyToClipboard(text);
                });
            } else {
                // Fallback for older browsers or non-HTTPS
                fallbackCopyToClipboard(text);
            }
        }
        
        function fallbackCopyToClipboard(text) {
            // Create a temporary textarea element
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    showCopySuccess();
                } else {
                    showCopyError();
                }
            } catch (err) {
                console.error('Fallback copy failed:', err);
                showCopyError();
            } finally {
                document.body.removeChild(textArea);
            }
        }
        
        function showCopySuccess() {
            // Create a temporary success message
            const message = document.createElement('div');
            message.textContent = '✅ Copied to clipboard!';
            message.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #4CAF50; color: white; padding: 12px 20px; border-radius: 4px; z-index: 1000; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; box-shadow: 0 2px 8px rgba(0,0,0,0.2);';
            document.body.appendChild(message);
            
            // Remove message after 3 seconds
            setTimeout(() => {
                if (message.parentNode) {
                    message.parentNode.removeChild(message);
                }
            }, 3000);
        }
        
        function showCopyError() {
            // Create a temporary error message
            const message = document.createElement('div');
            message.textContent = '❌ Failed to copy. Please copy manually.';
            message.style.cssText = 'position: fixed; top: 20px; right: 20px; background: #f44336; color: white; padding: 12px 20px; border-radius: 4px; z-index: 1000; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; box-shadow: 0 2px 8px rgba(0,0,0,0.2);';
            document.body.appendChild(message);
            
            // Remove message after 5 seconds
            setTimeout(() => {
                if (message.parentNode) {
                    message.parentNode.removeChild(message);
                }
            }, 5000);
        }
        
        function showPlatform(platform) {
            document.querySelectorAll('.platform-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.platform-content').forEach(content => content.classList.remove('active'));
            document.querySelector('[data-platform="' + platform + '"]').classList.add('active');
            document.querySelector('#' + platform + '-content').classList.add('active');
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>MyEncrypt Downloads</h1>
        </div>
        
        <div class="nav">
            <a href="/">← Back to Dashboard</a>
            <a href="/download/">Downloads</a>
        </div>
        
        <div class="section">
            <h2>🚀 Quick Setup</h2>
            <div class="highlight">
                <h3>One-line Installation (%s)</h3>
                <p>Run this command to automatically download and install the CA certificate:</p>
                <div class="oneliner">
                    <button class="copy-btn" onclick="copyToClipboard('%s')">Copy</button>
                    <code>%s</code>
                </div>
                <p><small>This script automatically downloads the CA certificate and installs it to your system's trust store.</small></p>
            </div>
        </div>
        
        <div class="section">
            <h2>🐳 Docker Installation Guide</h2>
            <div class="docker-highlight">
                <h3>For Docker Users</h3>
                <p>If you're running MyEncrypt in Docker, use these platform-specific commands:</p>
                
                <div class="platform-tabs">
                    <button class="platform-tab active" data-platform="unix" onclick="showPlatform('unix')">macOS/Linux</button>
                    <button class="platform-tab" data-platform="windows" onclick="showPlatform('windows')">Windows</button>
                </div>
                
                <div id="unix-content" class="platform-content active">
                    <div class="oneliner">
                        <button class="copy-btn" onclick="copyToClipboard('%s')">Copy</button>
                        <code>%s</code>
                    </div>
                    <p><small>One-liner for macOS and Linux systems (automatically downloads and installs)</small></p>
                </div>
                
                <div id="windows-content" class="platform-content">
                    <div class="oneliner">
                        <button class="copy-btn" onclick="copyToClipboard('%s')">Copy</button>
                        <code>%s</code>
                    </div>
                    <p><small>Two-step process for Windows PowerShell (downloads and installs automatically)</small></p>
                </div>
                
                <p><strong>Note:</strong> These commands work when MyEncrypt is running in Docker and exposed on the host port.</p>
            </div>
        </div>
        
        <div class="section">
            <h2>📄 CA Certificate</h2>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/certificate">/download/certificate</a> 
                <span>- Download CA certificate (rootCA.pem)</span>
            </div>
        </div>
        
        <div class="section">
            <h2>📜 Installation Scripts</h2>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/install.sh">/download/install.sh</a> 
                <span>- Unix/Linux installation script</span>
            </div>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/install.ps1">/download/install.ps1</a> 
                <span>- Windows PowerShell installation script</span>
            </div>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/uninstall.sh">/download/uninstall.sh</a> 
                <span>- Unix/Linux uninstallation script</span>
            </div>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/uninstall.ps1">/download/uninstall.ps1</a> 
                <span>- Windows PowerShell uninstallation script</span>
            </div>
        </div>
        
        <div class="section">
            <h2>🗑️ Complete Removal Scripts</h2>
            <p><strong>⚠️ Warning:</strong> These scripts remove ALL MyEncrypt CA certificates from your system, including certificates from other projects.</p>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/uninstall-all.sh">/download/uninstall-all.sh</a> 
                <span>- Unix/Linux complete removal script</span>
            </div>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/uninstall-all.ps1">/download/uninstall-all.ps1</a> 
                <span>- Windows PowerShell complete removal script</span>
            </div>
        </div>
        
        <div class="section">
            <h2>📦 Complete Bundle</h2>
            <div class="api-endpoint">
                <span class="method">GET</span> 
                <a href="/download/bundle.zip">/download/bundle.zip</a> 
                <span>- Download complete bundle (CA cert + scripts + README)</span>
            </div>
        </div>
        
        <div class="section">
            <h2>🔧 ACME Configuration</h2>
            <p>Use the following ACME server URL in your ACME client:</p>
            <div class="oneliner">
                <button class="copy-btn" onclick="copyToClipboard('http://localhost:%d/acme/directory')">Copy</button>
                <code>http://localhost:%d/acme/directory</code>
            </div>
            
            <h3>Example with Certbot:</h3>
            <div class="oneliner">
                <button class="copy-btn" onclick="copyToClipboard('certbot certonly --server http://localhost:%d/acme/directory --standalone -d example.localhost')">Copy</button>
                <code>certbot certonly --server http://localhost:%d/acme/directory --standalone -d example.localhost</code>
            </div>
        </div>
    </div>
</body>
</html>`, shellType, oneLineCommand, oneLineCommand, dockerBashCommand, dockerBashCommand, dockerPowerShellCommand, dockerPowerShellCommand, scriptPort, scriptPort, scriptPort, scriptPort)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// Download handlers (existing implementations)
func (s *Server) handleDownloadCertificate(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("CA certificate download requested", "remote_addr", r.RemoteAddr)

	certPEM, err := s.certManager.GetCACertificatePEM()
	if err != nil {
		s.logger.Error("Failed to get CA certificate", "error", err)
		http.Error(w, "Failed to get CA certificate", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"rootCA.pem\"")
	w.Write(certPEM)
}

func (s *Server) handleDownloadBundle(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Bundle download requested", "remote_addr", r.RemoteAddr)

	// Create a buffer to write our archive to
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// Add CA certificate
	certPEM, err := s.certManager.GetCACertificatePEM()
	if err != nil {
		s.logger.Error("Failed to get CA certificate for bundle", "error", err)
		http.Error(w, "Failed to create bundle", http.StatusInternalServerError)
		return
	}

	certFile, err := zipWriter.Create("rootCA.pem")
	if err != nil {
		http.Error(w, "Failed to create bundle", http.StatusInternalServerError)
		return
	}
	certFile.Write(certPEM)

	// Add README
	readmeContent := fmt.Sprintf(`MyEncrypt CA Bundle
==================

This bundle contains:
- rootCA.pem: CA certificate for manual installation

Installation:
1. Install the CA certificate to your system's trust store
2. Configure your ACME client to use: http://localhost:%d/acme/directory

For more information, visit: https://github.com/myencrypt/myencrypt
`, s.config.HTTPPort)

	readmeFile, err := zipWriter.Create("README.txt")
	if err != nil {
		http.Error(w, "Failed to create bundle", http.StatusInternalServerError)
		return
	}
	readmeFile.Write([]byte(readmeContent))

	zipWriter.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"myencrypt-bundle.zip\"")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Write(buf.Bytes())
}

func (s *Server) handleDownloadInstallSh(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Install script download requested", "remote_addr", r.RemoteAddr)

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	projectName := os.Getenv("MYENCRYPT_PROJECT_NAME")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	// Determine Linux file name
	var linuxFileName string
	if projectName != "" {
		// Docker mode: include project name
		linuxFileName = fmt.Sprintf("myencrypt-%s-rootCA.crt", projectName)
	} else {
		// Service mode: use default name
		linuxFileName = "myencrypt-rootCA.crt"
	}

	script := fmt.Sprintf(`#!/bin/bash
# MyEncrypt CA Installation Script

set -e

echo "Installing MyEncrypt CA certificate..."

# Download CA certificate
curl -fsSL http://localhost:%d/download/certificate -o /tmp/myencrypt-rootCA.pem

# Install to system trust store (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/myencrypt-rootCA.pem
    echo "✅ CA certificate installed to macOS system keychain"
# Install to system trust store (Linux)
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo cp /tmp/myencrypt-rootCA.pem /usr/local/share/ca-certificates/%s
    sudo update-ca-certificates
    echo "✅ CA certificate installed to Linux system trust store"
else
    echo "⚠️  Unsupported OS. Please manually install /tmp/myencrypt-rootCA.pem"
fi

# Install to Java keystore
install_java() {
    local java_home=""
    local keytool=""
    
    # Find Java installation
    if [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/keytool" ]]; then
        keytool="$JAVA_HOME/bin/keytool"
    elif command -v keytool >/dev/null 2>&1; then
        keytool="keytool"
    elif [[ "$OSTYPE" == "darwin"* ]] && [[ -x "/usr/libexec/java_home" ]]; then
        java_home=$(/usr/libexec/java_home 2>/dev/null) && keytool="$java_home/bin/keytool"
    elif [[ -x "/usr/bin/keytool" ]]; then
        keytool="/usr/bin/keytool"
    fi
    
    if [[ -n "$keytool" ]]; then
        # Convert PEM to DER format for Java
        openssl x509 -outform der -in /tmp/myencrypt-rootCA.pem -out /tmp/myencrypt-rootCA.der 2>/dev/null || return 1
        
        # Install to Java keystore (try common locations)
        local installed=false
        for cacerts in \
            "$JAVA_HOME/lib/security/cacerts" \
            "$JAVA_HOME/jre/lib/security/cacerts" \
            "/etc/ssl/certs/java/cacerts" \
            "/usr/lib/jvm/default-java/lib/security/cacerts" \
            "/usr/lib/jvm/java-*/lib/security/cacerts" \
            "/System/Library/Java/Support/CoreDeploy.bundle/Contents/Home/lib/security/cacerts" \
            "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts"; do
            
            if [[ -f "$cacerts" ]] && [[ -w "$cacerts" || -w "$(dirname "$cacerts")" ]]; then
                if sudo "$keytool" -importcert -file /tmp/myencrypt-rootCA.der -alias myencrypt-ca -keystore "$cacerts" -storepass changeit -noprompt 2>/dev/null; then
                    echo "✅ CA certificate installed to Java keystore: $cacerts"
                    installed=true
                    break
                fi
            fi
        done
        
        if [[ "$installed" == false ]]; then
            echo "⚠️  Java keystore found but installation failed (try running as administrator)"
        fi
        
        rm -f /tmp/myencrypt-rootCA.der
    else
        echo "ℹ️  Java not found, skipping Java keystore installation"
    fi
}

# Install to NSS databases (Firefox, Chrome on Linux)
install_nss() {
    if ! command -v certutil >/dev/null 2>&1; then
        echo "ℹ️  NSS tools not found, skipping NSS database installation"
        return
    fi
    
    local installed=false
    
    # Find NSS databases
    local nss_dirs=(
        "$HOME/.pki/nssdb"                    # Chrome/Chromium on Linux
        "$HOME/.mozilla/firefox/*/."         # Firefox profiles
        "$HOME/snap/firefox/common/.mozilla/firefox/*/." # Firefox snap
        "/etc/pki/nssdb"                     # System-wide NSS
    )
    
    for nss_dir in "${nss_dirs[@]}"; do
        # Handle glob patterns
        for dir in $nss_dir; do
            if [[ -d "$dir" ]] && [[ -f "$dir/cert9.db" || -f "$dir/cert8.db" ]]; then
                if certutil -A -n "MyEncrypt Development CA" -t "C,," -i /tmp/myencrypt-rootCA.pem -d "$dir" 2>/dev/null; then
                    echo "✅ CA certificate installed to NSS database: $dir"
                    installed=true
                fi
            fi
        done
    done
    
    if [[ "$installed" == false ]]; then
        echo "ℹ️  No NSS databases found or installation failed"
    fi
}

# Install to additional trust stores
echo ""
echo "Installing to additional trust stores..."
install_java
install_nss

# Cleanup
rm -f /tmp/myencrypt-rootCA.pem

echo ""
echo "🎉 MyEncrypt CA installation completed!"
echo "ACME server URL: http://localhost:%d/acme/directory"
echo ""
echo "To uninstall the CA certificate later:"
echo "   curl -sSL http://localhost:%d/download/uninstall.sh | bash"
echo ""
echo "To remove ALL MyEncrypt CA certificates:"
echo "   curl -sSL http://localhost:%d/download/uninstall-all.sh | bash"
`, scriptPort, linuxFileName, scriptPort, scriptPort, scriptPort)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"install.sh\"")
	w.Write([]byte(script))
}

func (s *Server) handleDownloadInstallPs1(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("PowerShell install script download requested", "remote_addr", r.RemoteAddr)

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	script := fmt.Sprintf(`# MyEncrypt CA Installation Script (PowerShell)

Write-Host "Installing MyEncrypt CA certificate..." -ForegroundColor Green

try {
    # Download CA certificate
    $tempFile = [System.IO.Path]::GetTempFileName() + ".pem"
    Invoke-WebRequest -Uri "http://localhost:%d/download/certificate" -OutFile $tempFile
    
    # Install to Windows certificate store
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempFile)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()
    
    Write-Host "✅ CA certificate installed to Windows certificate store" -ForegroundColor Green
    
    # Install to Java keystore
    function Install-JavaKeystore {
        $javaHome = $env:JAVA_HOME
        $keytool = $null
        
        # Find Java installation
        if ($javaHome -and (Test-Path "$javaHome\bin\keytool.exe")) {
            $keytool = "$javaHome\bin\keytool.exe"
        } elseif (Get-Command keytool -ErrorAction SilentlyContinue) {
            $keytool = "keytool"
        }
        
        if ($keytool) {
            # Convert PEM to DER format for Java
            $derFile = [System.IO.Path]::GetTempFileName() + ".der"
            try {
                $pemContent = Get-Content $tempFile -Raw
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Text.Encoding]::UTF8.GetBytes($pemContent))
                [System.IO.File]::WriteAllBytes($derFile, $cert.RawData)
                
                # Try common Java keystore locations
                $cacertsPaths = @(
                    "$javaHome\lib\security\cacerts",
                    "$javaHome\jre\lib\security\cacerts"
                )
                
                $installed = $false
                foreach ($cacerts in $cacertsPaths) {
                    if (Test-Path $cacerts) {
                        try {
                            & $keytool -importcert -file $derFile -alias myencrypt-ca -keystore $cacerts -storepass changeit -noprompt 2>$null
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "✅ CA certificate installed to Java keystore: $cacerts" -ForegroundColor Green
                                $installed = $true
                                break
                            }
                        } catch { }
                    }
                }
                
                if (-not $installed) {
                    Write-Host "⚠️  Java keystore found but installation failed (try running as administrator)" -ForegroundColor Yellow
                }
            } finally {
                if (Test-Path $derFile) { Remove-Item $derFile -Force }
            }
        } else {
            Write-Host "ℹ️  Java not found, skipping Java keystore installation" -ForegroundColor Cyan
        }
    }
    
    # Install to NSS databases (Firefox)
    function Install-NSSDatabase {
        if (-not (Get-Command certutil -ErrorAction SilentlyContinue)) {
            Write-Host "ℹ️  NSS tools not found, skipping NSS database installation" -ForegroundColor Cyan
            return
        }
        
        $installed = $false
        $appData = $env:APPDATA
        if ($appData) {
            $firefoxProfilesPath = "$appData\Mozilla\Firefox\Profiles"
            if (Test-Path $firefoxProfilesPath) {
                $profiles = Get-ChildItem $firefoxProfilesPath -Directory
                foreach ($profile in $profiles) {
                    if ((Test-Path "$($profile.FullName)\cert9.db") -or (Test-Path "$($profile.FullName)\cert8.db")) {
                        try {
                            & certutil -A -n "MyEncrypt Development CA" -t "C,," -i $tempFile -d $profile.FullName 2>$null
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "✅ CA certificate installed to NSS database: $($profile.FullName)" -ForegroundColor Green
                                $installed = $true
                            }
                        } catch { }
                    }
                }
            }
        }
        
        if (-not $installed) {
            Write-Host "ℹ️  No NSS databases found or installation failed" -ForegroundColor Cyan
        }
    }
    
    # Install to additional trust stores
    Write-Host ""
    Write-Host "Installing to additional trust stores..." -ForegroundColor Green
    Install-JavaKeystore
    Install-NSSDatabase
    
    Write-Host ""
    Write-Host "🎉 MyEncrypt CA installation completed!" -ForegroundColor Green
    Write-Host "ACME server URL: http://localhost:%d/acme/directory" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To uninstall the CA certificate later:" -ForegroundColor Yellow
    Write-Host "   curl http://localhost:%d/download/uninstall.ps1 -o uninstall.ps1; .\\uninstall.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To remove ALL MyEncrypt CA certificates:" -ForegroundColor Yellow
    Write-Host "   curl http://localhost:%d/download/uninstall-all.ps1 -o uninstall-all.ps1; .\\uninstall-all.ps1" -ForegroundColor Cyan
    
    # Cleanup
    Remove-Item $tempFile -Force
}
catch {
    Write-Host "❌ Installation failed: $_" -ForegroundColor Red
    exit 1
}
`, scriptPort, scriptPort, scriptPort, scriptPort)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"install.ps1\"")
	w.Write([]byte(script))
}

func (s *Server) handleDownloadUninstallSh(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Uninstall script download requested", "remote_addr", r.RemoteAddr)

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	projectName := os.Getenv("MYENCRYPT_PROJECT_NAME")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	// Determine CA certificate name
	var caName, linuxFileName string
	if projectName != "" {
		// Docker mode: include project name
		caName = fmt.Sprintf("MyEncrypt Development CA (%s)", projectName)
		linuxFileName = fmt.Sprintf("myencrypt-%s-rootCA.crt", projectName)
	} else {
		// Service mode: use default name
		caName = "MyEncrypt Development CA"
		linuxFileName = "myencrypt-rootCA.crt"
	}

	script := fmt.Sprintf(`#!/bin/bash
# MyEncrypt CA Uninstallation Script

set -e

echo "Uninstalling MyEncrypt CA certificate..."

# Uninstall from system trust store (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    sudo security delete-certificate -c "%s" /Library/Keychains/System.keychain || true
    echo "✅ CA certificate removed from macOS system keychain"
# Uninstall from system trust store (Linux)
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo rm -f /usr/local/share/ca-certificates/%s
    sudo update-ca-certificates
    echo "✅ CA certificate removed from Linux system trust store"
else
    echo "⚠️  Unsupported OS. Please manually remove MyEncrypt CA certificate"
fi

echo "🎉 MyEncrypt CA uninstallation completed!"

# Uninstall from Java keystore
uninstall_java() {
    local keytool=""
    
    # Find Java installation
    if [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/keytool" ]]; then
        keytool="$JAVA_HOME/bin/keytool"
    elif command -v keytool >/dev/null 2>&1; then
        keytool="keytool"
    elif [[ "$OSTYPE" == "darwin"* ]] && [[ -x "/usr/libexec/java_home" ]]; then
        java_home=$(/usr/libexec/java_home 2>/dev/null) && keytool="$java_home/bin/keytool"
    elif [[ -x "/usr/bin/keytool" ]]; then
        keytool="/usr/bin/keytool"
    fi
    
    if [[ -n "$keytool" ]]; then
        local removed=false
        for cacerts in \
            "$JAVA_HOME/lib/security/cacerts" \
            "$JAVA_HOME/jre/lib/security/cacerts" \
            "/etc/ssl/certs/java/cacerts" \
            "/usr/lib/jvm/default-java/lib/security/cacerts" \
            "/usr/lib/jvm/java-*/lib/security/cacerts" \
            "/System/Library/Java/Support/CoreDeploy.bundle/Contents/Home/lib/security/cacerts" \
            "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts"; do
            
            if [[ -f "$cacerts" ]] && [[ -w "$cacerts" || -w "$(dirname "$cacerts")" ]]; then
                if sudo "$keytool" -delete -alias myencrypt-ca -keystore "$cacerts" -storepass changeit -noprompt 2>/dev/null; then
                    echo "✅ CA certificate removed from Java keystore: $cacerts"
                    removed=true
                fi
            fi
        done
        
        if [[ "$removed" == false ]]; then
            echo "ℹ️  No MyEncrypt CA certificates found in Java keystores"
        fi
    else
        echo "ℹ️  Java not found, skipping Java keystore removal"
    fi
}

# Uninstall from NSS databases
uninstall_nss() {
    if ! command -v certutil >/dev/null 2>&1; then
        echo "ℹ️  NSS tools not found, skipping NSS database removal"
        return
    fi
    
    local removed=false
    local nss_dirs=(
        "$HOME/.pki/nssdb"
        "$HOME/.mozilla/firefox/*/."
        "$HOME/snap/firefox/common/.mozilla/firefox/*/."
        "/etc/pki/nssdb"
    )
    
    for nss_dir in "${nss_dirs[@]}"; do
        for dir in $nss_dir; do
            if [[ -d "$dir" ]] && [[ -f "$dir/cert9.db" || -f "$dir/cert8.db" ]]; then
                if certutil -D -n "MyEncrypt Development CA" -d "$dir" 2>/dev/null; then
                    echo "✅ CA certificate removed from NSS database: $dir"
                    removed=true
                fi
            fi
        done
    done
    
    if [[ "$removed" == false ]]; then
        echo "ℹ️  No MyEncrypt CA certificates found in NSS databases"
    fi
}

echo ""
echo "Removing from additional trust stores..."
uninstall_java
uninstall_nss

echo ""
echo "To reinstall the CA certificate:"
echo "   curl -sSL http://localhost:%d/download/install.sh | bash"
echo ""
echo "To remove ALL MyEncrypt CA certificates:"
echo "   curl -sSL http://localhost:%d/download/uninstall-all.sh | bash"
`, caName, linuxFileName, scriptPort, scriptPort)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"uninstall.sh\"")
	w.Write([]byte(script))
}

func (s *Server) handleDownloadUninstallPs1(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("PowerShell uninstall script download requested", "remote_addr", r.RemoteAddr)

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	projectName := os.Getenv("MYENCRYPT_PROJECT_NAME")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	// Determine CA certificate name
	var caName string
	if projectName != "" {
		// Docker mode: include project name
		caName = fmt.Sprintf("MyEncrypt Development CA (%s)", projectName)
	} else {
		// Service mode: use default name
		caName = "MyEncrypt Development CA"
	}

	script := fmt.Sprintf(`# MyEncrypt CA Uninstallation Script (PowerShell)

Write-Host "Uninstalling MyEncrypt CA certificate..." -ForegroundColor Green

try {
    # Remove from Windows certificate store
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    
    $certs = $store.Certificates | Where-Object { $_.Subject -like "*%s*" }
    foreach ($cert in $certs) {
        $store.Remove($cert)
        Write-Host "Removed certificate: $($cert.Subject)" -ForegroundColor Yellow
    }
    
    $store.Close()
    
    Write-Host "✅ CA certificate removed from Windows certificate store" -ForegroundColor Green
    Write-Host "🎉 MyEncrypt CA uninstallation completed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To reinstall the CA certificate:" -ForegroundColor Yellow
    Write-Host "   curl http://localhost:%d/download/install.ps1 -o install.ps1; .\\install.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To remove ALL MyEncrypt CA certificates:" -ForegroundColor Yellow
    Write-Host "   curl http://localhost:%d/download/uninstall-all.ps1 -o uninstall-all.ps1; .\\uninstall-all.ps1" -ForegroundColor Cyan
}
catch {
    Write-Host "❌ Uninstallation failed: $_" -ForegroundColor Red
    exit 1
}
`, caName, scriptPort, scriptPort)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"uninstall.ps1\"")
	w.Write([]byte(script))
}

func (s *Server) handleDownloadUninstallAllSh(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Uninstall-all script download requested", "remote_addr", r.RemoteAddr)

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	script := fmt.Sprintf(`#!/bin/bash
# MyEncrypt CA Complete Uninstallation Script
# This script removes ALL MyEncrypt CA certificates from the system

set -e

echo "Uninstalling ALL MyEncrypt CA certificates..."
echo "⚠️  This will remove all MyEncrypt CA certificates from your system trust store."
echo ""

# Uninstall from system trust store (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Removing all MyEncrypt CA certificates from macOS system keychain..."
    # Remove all certificates containing "MyEncrypt Development CA"
    while IFS= read -r cert_name; do
        if [[ -n "$cert_name" ]]; then
            sudo security delete-certificate -c "$cert_name" /Library/Keychains/System.keychain || true
            echo "  ✅ Removed: $cert_name"
        fi
    done < <(security find-certificate -a -c "MyEncrypt Development CA" /Library/Keychains/System.keychain 2>/dev/null | grep "alis" | sed 's/.*"alis"<blob>="\([^"]*\)".*/\1/' || true)
    echo "✅ All MyEncrypt CA certificates removed from macOS system keychain"

# Uninstall from system trust store (Linux)
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Removing all MyEncrypt CA certificates from Linux system trust store..."
    # Remove all myencrypt-*.crt files
    sudo rm -f /usr/local/share/ca-certificates/myencrypt*.crt
    sudo rm -f /usr/local/share/ca-certificates/myencrypt-*-rootCA.crt
    sudo update-ca-certificates
    echo "✅ All MyEncrypt CA certificates removed from Linux system trust store"
else
    echo "⚠️  Unsupported OS. Please manually remove all MyEncrypt CA certificates"
fi

echo ""
echo "🎉 Complete MyEncrypt CA uninstallation completed!"
echo ""
echo "To install a new CA certificate:"
echo "   curl -sSL http://localhost:%d/download/install.sh | bash"
`, scriptPort)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"uninstall-all.sh\"")
	w.Write([]byte(script))
}

func (s *Server) handleDownloadUninstallAllPs1(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("PowerShell uninstall-all script download requested", "remote_addr", r.RemoteAddr)

	// Detect Docker environment and get exposed port
	exposePort := os.Getenv("MYENCRYPT_EXPOSE_PORT")
	var scriptPort int
	if exposePort != "" {
		// Docker mode: use exposed port for scripts
		if p, err := strconv.Atoi(exposePort); err == nil {
			scriptPort = p
		} else {
			scriptPort = s.config.HTTPPort
		}
	} else {
		// Development mode: use configured port
		scriptPort = s.config.HTTPPort
	}

	script := fmt.Sprintf(`# MyEncrypt CA Complete Uninstallation Script (PowerShell)
# This script removes ALL MyEncrypt CA certificates from the Windows certificate store

Write-Host "Uninstalling ALL MyEncrypt CA certificates..." -ForegroundColor Green
Write-Host "⚠️  This will remove all MyEncrypt CA certificates from your system trust store." -ForegroundColor Yellow
Write-Host ""

try {
    # Remove from Windows certificate store
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    
    Write-Host "Searching for MyEncrypt CA certificates..." -ForegroundColor Green
    $certs = $store.Certificates | Where-Object { $_.Subject -like "*MyEncrypt Development CA*" }
    
    if ($certs.Count -eq 0) {
        Write-Host "No MyEncrypt CA certificates found." -ForegroundColor Yellow
    } else {
        Write-Host "Found $($certs.Count) MyEncrypt CA certificate(s). Removing..." -ForegroundColor Green
        foreach ($cert in $certs) {
            $store.Remove($cert)
            Write-Host "  ✅ Removed certificate: $($cert.Subject)" -ForegroundColor Yellow
        }
    }
    
    $store.Close()
    
    Write-Host ""
    Write-Host "✅ All MyEncrypt CA certificates removed from Windows certificate store" -ForegroundColor Green
    Write-Host "🎉 Complete MyEncrypt CA uninstallation completed!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To install a new CA certificate:" -ForegroundColor Yellow
    Write-Host "   curl http://localhost:%d/download/install.ps1 -o install.ps1; .\\install.ps1" -ForegroundColor Cyan
}
catch {
    Write-Host "❌ Uninstallation failed: $_" -ForegroundColor Red
    exit 1
}
`, scriptPort)

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=\"uninstall-all.ps1\"")
	w.Write([]byte(script))
}

// Helper types for management interface
type AccountInfo struct {
	ID        string    `json:"id"`
	Contact   []string  `json:"contact"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	CertCount int       `json:"cert_count"`
}

type CertificateInfo struct {
	ID             string     `json:"id"`
	AccountID      string     `json:"account_id"`
	SerialNumber   string     `json:"serial_number"`
	Domains        []string   `json:"domains"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Status         string     `json:"status"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	AccountContact []string   `json:"account_contact,omitempty"`
}

type Statistics struct {
	ActiveAccounts      int `json:"active_accounts"`
	ValidCertificates   int `json:"valid_certificates"`
	ExpiredCertificates int `json:"expired_certificates"`
	RevokedCertificates int `json:"revoked_certificates"`
}

// Database helper methods
func (s *Server) openDB() (*sql.DB, error) {
	return sql.Open("sqlite3", s.dbPath)
}

func (s *Server) getStatistics() (*Statistics, error) {
	db, err := s.openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	stats := &Statistics{}

	// Count active accounts
	err = db.QueryRow("SELECT COUNT(*) FROM accounts WHERE status = 'valid'").Scan(&stats.ActiveAccounts)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Count valid certificates
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'valid'").Scan(&stats.ValidCertificates)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Count expired certificates
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE expires_at < CURRENT_TIMESTAMP AND status = 'valid'").Scan(&stats.ExpiredCertificates)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Count revoked certificates
	err = db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'").Scan(&stats.RevokedCertificates)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	return stats, nil
}

func (s *Server) getAllAccounts() ([]*AccountInfo, error) {
	db, err := s.openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
		SELECT a.id, a.contact, a.status, a.created_at, 
		       COALESCE(cert_count.count, 0) as cert_count
		FROM accounts a
		LEFT JOIN (
			SELECT account_id, COUNT(*) as count 
			FROM certificates 
			WHERE status = 'valid' 
			GROUP BY account_id
		) cert_count ON a.id = cert_count.account_id
		ORDER BY a.created_at DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*AccountInfo
	for rows.Next() {
		var account AccountInfo
		var contactJSON string

		err := rows.Scan(
			&account.ID,
			&contactJSON,
			&account.Status,
			&account.CreatedAt,
			&account.CertCount,
		)
		if err != nil {
			continue
		}

		// Parse contact JSON
		if contactJSON != "" {
			json.Unmarshal([]byte(contactJSON), &account.Contact)
		}

		accounts = append(accounts, &account)
	}

	return accounts, nil
}

func (s *Server) getAllCertificates() ([]*CertificateInfo, error) {
	db, err := s.openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	query := `
		SELECT c.id, c.account_id, c.serial_number, c.domains, c.issued_at, c.expires_at, 
		       c.status, c.revoked_at, a.contact
		FROM certificates c
		LEFT JOIN accounts a ON c.account_id = a.id
		ORDER BY c.issued_at DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*CertificateInfo
	for rows.Next() {
		var cert CertificateInfo
		var domainsJSON, contactJSON sql.NullString

		err := rows.Scan(
			&cert.ID,
			&cert.AccountID,
			&cert.SerialNumber,
			&domainsJSON,
			&cert.IssuedAt,
			&cert.ExpiresAt,
			&cert.Status,
			&cert.RevokedAt,
			&contactJSON,
		)
		if err != nil {
			continue
		}

		// Parse domains JSON
		if domainsJSON.Valid {
			json.Unmarshal([]byte(domainsJSON.String), &cert.Domains)
		}

		// Parse contact JSON
		if contactJSON.Valid {
			json.Unmarshal([]byte(contactJSON.String), &cert.AccountContact)
		}

		certificates = append(certificates, &cert)
	}

	return certificates, nil
}

func (s *Server) revokeAccount(accountID string) error {
	db, err := s.openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	query := `UPDATE accounts SET status = 'deactivated', updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err = db.Exec(query, accountID)
	return err
}

func (s *Server) revokeCertificate(certID string) error {
	db, err := s.openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	query := `UPDATE certificates SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err = db.Exec(query, certID)
	return err
}

// HTML rendering helpers
func (s *Server) renderAccountsTable(accounts []*AccountInfo) string {
	if len(accounts) == 0 {
		return `<div class="empty-state">
			<p>No ACME accounts found.</p>
			<p><small>Accounts will appear here when clients register via the ACME protocol.</small></p>
		</div>`
	}

	html := `<table>
		<thead>
			<tr>
				<th>Account ID</th>
				<th>Contact</th>
				<th>Status</th>
				<th>Created</th>
				<th>Certificates</th>
				<th>Actions</th>
			</tr>
		</thead>
		<tbody>`

	for _, account := range accounts {
		statusClass := "status-valid"
		if account.Status == "deactivated" {
			statusClass = "status-deactivated"
		}

		contact := ""
		if len(account.Contact) > 0 {
			contact = account.Contact[0]
		}

		html += fmt.Sprintf(`
			<tr>
				<td><span class="account-id">%s</span></td>
				<td>%s</td>
				<td><span class="status-badge %s">%s</span></td>
				<td>%s</td>
				<td>%d</td>
				<td>
					<form method="POST" action="/revoke-account" style="display: inline;">
						<input type="hidden" name="account_id" value="%s">
						<button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to revoke this account?')">Revoke</button>
					</form>
				</td>
			</tr>`,
			account.ID[:8]+"...",
			contact,
			statusClass,
			strings.Title(account.Status),
			account.CreatedAt.Format("2006-01-02 15:04"),
			account.CertCount,
			account.ID)
	}

	html += `</tbody></table>`
	return html
}

func (s *Server) renderCertificatesTable(certificates []*CertificateInfo) string {
	if len(certificates) == 0 {
		return `<div class="empty-state">
			<p>No certificates found.</p>
			<p><small>Certificates will appear here when issued via the ACME protocol.</small></p>
		</div>`
	}

	html := `<table>
		<thead>
			<tr>
				<th>Serial Number</th>
				<th>Domains</th>
				<th>Account</th>
				<th>Status</th>
				<th>Issued</th>
				<th>Expires</th>
				<th>Actions</th>
			</tr>
		</thead>
		<tbody>`

	for _, cert := range certificates {
		statusClass := "status-valid"
		switch cert.Status {
		case "revoked":
			statusClass = "status-revoked"
		case "valid":
			if time.Now().After(cert.ExpiresAt) {
				statusClass = "status-expired"
			}
		}

		domains := strings.Join(cert.Domains, ", ")
		if len(domains) > 50 {
			domains = domains[:47] + "..."
		}

		contact := ""
		if len(cert.AccountContact) > 0 {
			contact = cert.AccountContact[0]
		}

		html += fmt.Sprintf(`
			<tr>
				<td><span class="account-id">%s</span></td>
				<td><span class="domains">%s</span></td>
				<td><span class="account-id">%s</span><br><small>%s</small></td>
				<td><span class="status-badge %s">%s</span></td>
				<td>%s</td>
				<td>%s</td>
				<td>
					<form method="POST" action="/revoke-certificate" style="display: inline;">
						<input type="hidden" name="cert_id" value="%s">
						<button type="submit" class="btn btn-danger" onclick="return confirm('Are you sure you want to revoke this certificate?')">Revoke</button>
					</form>
				</td>
			</tr>`,
			cert.SerialNumber[:8]+"...",
			domains,
			cert.AccountID[:8]+"...",
			contact,
			statusClass,
			strings.Title(cert.Status),
			cert.IssuedAt.Format("2006-01-02 15:04"),
			cert.ExpiresAt.Format("2006-01-02 15:04"),
			cert.ID)
	}

	html += `</tbody></table>`
	return html
}
