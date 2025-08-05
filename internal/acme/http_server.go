package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/shibukawayoshiki/myencrypt2/internal/certmanager"
	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// HTTPServer represents the HTTP server that hosts the ACME endpoints
type HTTPServer struct {
	server      *http.Server
	acmeServer  *Server
	config      *config.Config
	logger      *logger.Logger
	certManager certmanager.Manager
}

// NewHTTPServer creates a new HTTP server for ACME protocol
func NewHTTPServer(cfg *config.Config, certMgr certmanager.Manager, log *logger.Logger) *HTTPServer {
	acmeServer := NewServer(cfg, certMgr, log)
	
	return &HTTPServer{
		acmeServer:  acmeServer,
		config:      cfg,
		logger:      log,
		certManager: certMgr,
	}
}

// Start starts the HTTP server
func (h *HTTPServer) Start(ctx context.Context) error {
	router := mux.NewRouter()
	
	// Register ACME handlers
	h.acmeServer.RegisterHandlers(router)
	
	// Add middleware
	router.Use(h.loggingMiddleware)
	router.Use(h.corsMiddleware)
	router.Use(h.securityHeadersMiddleware)
	
	// Health check endpoint
	router.HandleFunc("/health", h.handleHealth).Methods("GET")
	
	// Root endpoint with basic information
	router.HandleFunc("/", h.handleRoot).Methods("GET")
	
	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", h.config.BindAddress, h.config.HTTPPort)
	h.server = &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	h.logger.Info("Starting ACME HTTP server", "address", addr)
	
	// Start the ACME server
	if err := h.acmeServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start ACME server: %w", err)
	}
	
	// Start HTTP server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := h.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()
	
	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		h.logger.Info("Shutting down ACME HTTP server")
		return h.Shutdown()
	case err := <-errChan:
		return err
	}
}

// Shutdown gracefully shuts down the HTTP server
func (h *HTTPServer) Shutdown() error {
	if h.server == nil {
		return nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	return h.server.Shutdown(ctx)
}

// handleHealth handles health check requests
func (h *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"version":   "1.0.0",
		"services": map[string]string{
			"acme": "running",
		},
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode health response", "error", err)
	}
}

// handleRoot handles root endpoint requests
func (h *HTTPServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	response := map[string]interface{}{
		"name":        "MyEncrypt ACME Server",
		"version":     "1.0.0",
		"description": "Local ACME certificate authority for development",
		"endpoints": map[string]string{
			"directory": "/acme/directory",
			"health":    "/health",
		},
		"documentation": "https://github.com/shibukawayoshiki/myencrypt2",
	}
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("Failed to encode root response", "error", err)
	}
}

// Middleware functions

// loggingMiddleware logs HTTP requests
func (h *HTTPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapper := &responseWriterWrapper{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		
		next.ServeHTTP(wrapper, r)
		
		duration := time.Since(start)
		
		h.logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapper.statusCode,
			"duration", duration.String(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

// corsMiddleware adds CORS headers for development
func (h *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers for development
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Expose-Headers", "Replay-Nonce, Location")
		
		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds security headers
func (h *HTTPServer) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// For development, we don't enforce HTTPS
		// In production, you might want to add HSTS headers
		
		next.ServeHTTP(w, r)
	})
}

// responseWriterWrapper wraps http.ResponseWriter to capture status code
type responseWriterWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriterWrapper) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriterWrapper) Write(data []byte) (int, error) {
	return w.ResponseWriter.Write(data)
}
