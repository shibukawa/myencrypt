package main

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MyEncrypt Autocert Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .info-box { background: #e8f4fd; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #3498db; }
        .cert-info { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #28a745; }
        .status { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .status.secure { background: #28a745; }
        .footer { text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 MyEncrypt Autocert Demo</h1>
            <p>Automatic HTTPS with MyEncrypt ACME Server</p>
        </div>

        <div class="info-box">
            <h3>Connection Status</h3>
            <p><span class="status secure">HTTPS SECURE</span></p>
            <p>This application automatically obtained an SSL certificate from MyEncrypt ACME server using Go's autocert package.</p>
        </div>

        <div class="cert-info">
            <h3>Certificate Information</h3>
            <table>
                <tr><th>Domain</th><td>{{.Domain}}</td></tr>
                <tr><th>Server Time</th><td>{{.ServerTime}}</td></tr>
                <tr><th>ACME Directory URL</th><td>{{.ACMEDirectoryURL}}</td></tr>
                <tr><th>Port</th><td>{{.Port}}</td></tr>
                <tr><th>TLS Version</th><td>{{.TLSVersion}}</td></tr>
            </table>
        </div>

        <div class="info-box">
            <h3>How it works</h3>
            <ol>
                <li>This Go application uses <code>golang.org/x/crypto/acme/autocert</code></li>
                <li>It automatically requests certificates from MyEncrypt ACME server</li>
                <li>Certificates are cached and automatically renewed</li>
                <li>The application serves HTTPS traffic with valid certificates</li>
            </ol>
        </div>

        <div class="footer">
            <p>Powered by MyEncrypt ACME Server | Go Autocert Demo</p>
        </div>
    </div>
</body>
</html>
`

type PageData struct {
	Domain           string
	ServerTime       string
	ACMEDirectoryURL string
	Port             string
	TLSVersion       string
}

func main() {
	// Get configuration from environment variables
	domain := getEnvWithDefault("DOMAIN", "app.local")
	port := getEnvWithDefault("PORT", "8443")
	acmeDirectoryURL := getEnvWithDefault("ACME_DIRECTORY_URL", "http://myencrypt:14000/acme/directory")
	cacheDir := getEnvWithDefault("CACHE_DIR", "/tmp/autocert-cache")

	log.Printf("Starting autocert demo application")
	log.Printf("Domain: %s", domain)
	log.Printf("Port: %s", port)
	log.Printf("ACME Directory URL: %s", acmeDirectoryURL)
	log.Printf("Cache Directory: %s", cacheDir)

	// Create cache directory
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		log.Fatalf("Failed to create cache directory: %v", err)
	}

	// Configure autocert manager
	m := &autocert.Manager{
		Cache:       autocert.DirCache(cacheDir),
		Prompt:      autocert.AcceptTOS,
		HostPolicy:  autocert.HostWhitelist(domain),
		RenewBefore: 3 * time.Hour, // Renew 3 hours before expiration (for 31-day certs)
		Client: &acme.Client{
			DirectoryURL: acmeDirectoryURL,
		},
	}

	// Create HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("page").Parse(htmlTemplate))

		tlsVersion := "Unknown"
		if r.TLS != nil {
			switch r.TLS.Version {
			case tls.VersionTLS10:
				tlsVersion = "TLS 1.0"
			case tls.VersionTLS11:
				tlsVersion = "TLS 1.1"
			case tls.VersionTLS12:
				tlsVersion = "TLS 1.2"
			case tls.VersionTLS13:
				tlsVersion = "TLS 1.3"
			}
		}

		data := PageData{
			Domain:           domain,
			ServerTime:       time.Now().Format("2006-01-02 15:04:05 MST"),
			ACMEDirectoryURL: acmeDirectoryURL,
			Port:             port,
			TLSVersion:       tlsVersion,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","domain":"%s","time":"%s"}`,
			domain, time.Now().Format(time.RFC3339))
	})

	// Configure HTTPS server
	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: m.TLSConfig(),
		Handler:   http.DefaultServeMux,
	}

	log.Printf("Starting HTTPS server on port %s for domain %s", port, domain)
	log.Printf("Visit: https://%s:%s", domain, port)

	// Start HTTPS server
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS server failed: %v", err)
	}
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
