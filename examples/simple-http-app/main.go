package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"
)

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Simple HTTP Demo App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c3e50; margin-bottom: 30px; }
        .info-box { background: #fff3cd; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107; }
        .status { display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .status.http { background: #ffc107; color: #212529; }
        .footer { text-align: center; margin-top: 30px; color: #7f8c8d; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .proxy-info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #007bff; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Simple HTTP Demo App</h1>
            <p>HTTP Application for Reverse Proxy HTTPS Demo</p>
        </div>

        <div class="info-box">
            <h3>Connection Status</h3>
            <p><span class="status http">HTTP</span></p>
            <p>This is a simple HTTP application that can be proxied through Caddy or Traefik with automatic HTTPS.</p>
        </div>

        <div class="proxy-info">
            <h3>Application Information</h3>
            <table>
                <tr><th>App Name</th><td>{{.AppName}}</td></tr>
                <tr><th>Server Time</th><td>{{.ServerTime}}</td></tr>
                <tr><th>Port</th><td>{{.Port}}</td></tr>
                <tr><th>Protocol</th><td>HTTP</td></tr>
                <tr><th>Request Headers</th><td>{{.RequestHeaders}}</td></tr>
            </table>
        </div>

        <div class="info-box">
            <h3>Reverse Proxy Setup</h3>
            <p>This application is designed to work behind reverse proxies like:</p>
            <ul>
                <li><strong>Caddy</strong> - Automatic HTTPS with MyEncrypt ACME</li>
                <li><strong>Traefik</strong> - Dynamic reverse proxy with ACME support</li>
            </ul>
            <p>The reverse proxy handles SSL termination and certificate management.</p>
        </div>

        <div class="footer">
            <p>Simple HTTP Demo App | Designed for Reverse Proxy HTTPS</p>
        </div>
    </div>
</body>
</html>
`

type PageData struct {
	AppName        string
	ServerTime     string
	Port           string
	RequestHeaders string
}

func main() {
	// Get configuration from environment variables
	appName := getEnvWithDefault("APP_NAME", "Simple HTTP Demo")
	port := getEnvWithDefault("PORT", "8080")

	log.Printf("Starting simple HTTP application")
	log.Printf("App Name: %s", appName)
	log.Printf("Port: %s", port)

	// Create HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("page").Parse(htmlTemplate))
		
		// Get some request headers for display
		headers := fmt.Sprintf("Host: %s, User-Agent: %s, X-Forwarded-For: %s", 
			r.Header.Get("Host"),
			r.Header.Get("User-Agent")[:min(50, len(r.Header.Get("User-Agent")))],
			r.Header.Get("X-Forwarded-For"))

		data := PageData{
			AppName:        appName,
			ServerTime:     time.Now().Format("2006-01-02 15:04:05 MST"),
			Port:           port,
			RequestHeaders: headers,
		}

		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"healthy","app":"%s","time":"%s"}`, 
			appName, time.Now().Format(time.RFC3339))
	})

	// API endpoint
	http.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"app_name": "%s",
			"port": "%s",
			"protocol": "HTTP",
			"time": "%s",
			"headers": {
				"host": "%s",
				"user_agent": "%s",
				"x_forwarded_for": "%s"
			}
		}`, 
			appName, port, time.Now().Format(time.RFC3339),
			r.Header.Get("Host"),
			r.Header.Get("User-Agent"),
			r.Header.Get("X-Forwarded-For"))
	})

	log.Printf("Starting HTTP server on port %s", port)
	log.Printf("Visit: http://localhost:%s", port)
	
	// Start HTTP server
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
