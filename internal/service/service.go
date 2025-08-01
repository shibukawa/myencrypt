package service

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/shibukawayoshiki/myencrypt2/internal/acme"
	"github.com/shibukawayoshiki/myencrypt2/internal/certmanager"
	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
	"github.com/shibukawayoshiki/myencrypt2/internal/management"

	"github.com/kardianos/service"
)

// Manager handles OS service management operations
type Manager struct {
	config  *config.Config
	logger  *logger.Logger
	service service.Service
}

// ServiceStatus represents the current status of the service
type ServiceStatus struct {
	Name        string
	Status      service.Status
	IsInstalled bool
	IsRunning   bool
}

// New creates a new service manager
func New(cfg *config.Config, log *logger.Logger) (*Manager, error) {
	manager := &Manager{
		config: cfg,
		logger: log,
	}

	// Get current user information for service configuration
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = os.Getenv("USERNAME") // Windows fallback
	}

	// Get the executable path
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Create service configuration
	serviceConfig := &service.Config{
		Name:        cfg.ServiceName,
		DisplayName: cfg.ServiceDisplayName,
		Description: cfg.ServiceDescription,
		Arguments:   []string{"service", "run"},
		Executable:  execPath,
		Option: map[string]interface{}{
			"UserService": true, // Install as user service (LaunchAgent on macOS)
		},
	}

	// On Unix systems, configure the service to run as the current user
	if currentUser != "" && currentUser != "root" {
		serviceConfig.UserName = currentUser
	}

	// Create the service
	svc, err := service.New(manager, serviceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %w", err)
	}

	manager.service = svc
	return manager, nil
}

// Install installs the service in the OS
func (m *Manager) Install(configPath string) error {
	m.logger.Info("Installing service", "name", m.config.ServiceName, "configPath", configPath)

	// Pass the config path as an argument to the service
	serviceConfig := &service.Config{
		Name:        m.config.ServiceName,
		DisplayName: m.config.ServiceDisplayName,
		Description: m.config.ServiceDescription,
		Arguments:   []string{"--config", configPath},
	}

	s, err := service.New(m, serviceConfig)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	if err := s.Install(); err != nil {
		return fmt.Errorf("failed to install service: %w", err)
	}

	m.logger.Info("Service installed successfully", "name", m.config.ServiceName)
	return nil
}

// Uninstall removes the service from the OS
func (m *Manager) Uninstall() error {
	m.logger.Info("Uninstalling service", "name", m.config.ServiceName)

	// Stop the service first if it's running
	if status, err := m.service.Status(); err == nil && status == service.StatusRunning {
		m.logger.Info("Stopping service before uninstall")
		if err := m.service.Stop(); err != nil {
			m.logger.Error("Failed to stop service before uninstall", "error", err)
		}
		// Wait a moment for the service to stop
		time.Sleep(2 * time.Second)
	}

	if err := m.service.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service: %w", err)
	}

	m.logger.Info("Service uninstalled successfully", "name", m.config.ServiceName)
	return nil
}

// StartService starts the service
func (m *Manager) StartService() error {
	m.logger.Info("Starting service", "name", m.config.ServiceName)

	if err := m.service.Start(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	m.logger.Info("Service started successfully", "name", m.config.ServiceName)
	return nil
}

// StopService stops the service
func (m *Manager) StopService() error {
	m.logger.Info("Stopping service", "name", m.config.ServiceName)

	if err := m.service.Stop(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	m.logger.Info("Service stopped successfully", "name", m.config.ServiceName)
	return nil
}

// Restart restarts the service
func (m *Manager) Restart() error {
	m.logger.Info("Restarting service", "name", m.config.ServiceName)

	if err := m.service.Restart(); err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}

	m.logger.Info("Service restarted successfully", "name", m.config.ServiceName)
	return nil
}

// Status returns the current status of the service
func (m *Manager) Status() (*ServiceStatus, error) {
	status, err := m.service.Status()
	if err != nil {
		return nil, fmt.Errorf("failed to get service status: %w", err)
	}

	// Check if service is installed by trying to get its status
	// If we get here without error, the service is installed
	isInstalled := true
	isRunning := status == service.StatusRunning

	return &ServiceStatus{
		Name:        m.config.ServiceName,
		Status:      status,
		IsInstalled: isInstalled,
		IsRunning:   isRunning,
	}, nil
}

// IsInstalled checks if the service is installed
func (m *Manager) IsInstalled() bool {
	_, err := m.service.Status()
	return err == nil
}

// IsRunning checks if the service is currently running
func (m *Manager) IsRunning() bool {
	status, err := m.service.Status()
	if err != nil {
		return false
	}
	return status == service.StatusRunning
}

// Run is the main service loop - implements service.Interface
func (m *Manager) Run() error {
	m.logger.Info("Service starting", "name", m.config.ServiceName)

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start the main service logic in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- m.runMainLoop(ctx)
	}()

	// Wait for either an error or a shutdown signal
	select {
	case err := <-errChan:
		if err != nil {
			m.logger.Error("Service error", "error", err)
			return err
		}
	case sig := <-sigChan:
		m.logger.Info("Received shutdown signal", "signal", sig)
		cancel()
		// Wait for main loop to finish
		<-errChan
	}

	m.logger.Info("Service stopped", "name", m.config.ServiceName)
	return nil
}

// Start is called when the service is started - implements service.Interface
func (m *Manager) Start(s service.Service) error {
	m.logger.Info("Service start requested", "name", m.config.ServiceName)
	// The actual service logic runs in Run(), this just acknowledges the start
	go m.Run()
	return nil
}

// Stop is called when the service is stopped - implements service.Interface
func (m *Manager) Stop(s service.Service) error {
	m.logger.Info("Service stop requested", "name", m.config.ServiceName)
	// Signal handling in Run() will handle the actual shutdown
	return nil
}

// runMainLoop contains the main service logic
func (m *Manager) runMainLoop(ctx context.Context) error {
	m.logger.Info("Starting main service loop")

	// Verify that we can access the certificate store directory
	if err := m.verifyCertStoreAccess(); err != nil {
		return fmt.Errorf("certificate store access verification failed: %w", err)
	}

	// Initialize certificate manager
	certManager, err := m.initializeCertManager()
	if err != nil {
		return fmt.Errorf("failed to initialize certificate manager: %w", err)
	}

	// Start unified server (ACME + Management)
	unifiedServer, err := m.startUnifiedServer(ctx, certManager)
	if err != nil {
		return fmt.Errorf("failed to start unified server: %w", err)
	}

	m.logger.Info("All servers started successfully")

	// Wait for context cancellation
	<-ctx.Done()
	m.logger.Info("Service loop shutting down")

	// Shutdown server gracefully
	if unifiedServer != nil {
		if err := unifiedServer.Shutdown(); err != nil {
			m.logger.Error("Error shutting down unified server", "error", err)
		}
	}

	return nil
}

// verifyCertStoreAccess verifies that the service can access the certificate store
func (m *Manager) verifyCertStoreAccess() error {
	certStorePath := m.config.GetCertStorePath()

	// Check if directory exists and is accessible
	if _, err := os.Stat(certStorePath); err != nil {
		if os.IsNotExist(err) {
			m.logger.Info("Certificate store directory does not exist, attempting to create", "path", certStorePath)
			if err := os.MkdirAll(certStorePath, 0755); err != nil {
				return fmt.Errorf("failed to create certificate store directory %s: %w", certStorePath, err)
			}
		} else {
			return fmt.Errorf("failed to access certificate store directory %s: %w", certStorePath, err)
		}
	}

	// Test write access by creating a temporary file
	testFile := filepath.Join(certStorePath, ".service_access_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("no write access to certificate store directory %s: %w", certStorePath, err)
	}

	// Clean up test file
	os.Remove(testFile)

	m.logger.Info("Certificate store access verified", "path", certStorePath)
	return nil
}

// GetServiceConfig returns the service configuration for external use
func (m *Manager) GetServiceConfig() *service.Config {
	return &service.Config{
		Name:        m.config.ServiceName,
		DisplayName: m.config.ServiceDisplayName,
		Description: m.config.ServiceDescription,
		Arguments:   []string{"service", "run"},
	}
}

// initializeCertManager initializes the certificate manager
func (m *Manager) initializeCertManager() (certmanager.Manager, error) {
	m.logger.Info("Initializing certificate manager")
	
	certMgr := certmanager.New(m.config, m.logger)
	
	// Ensure CA certificate exists
	if err := certMgr.InitializeCA(); err != nil {
		return nil, fmt.Errorf("failed to initialize CA: %w", err)
	}
	
	// Load allowed domains
	if err := certMgr.LoadAllowedDomains(); err != nil {
		return nil, fmt.Errorf("failed to load allowed domains: %w", err)
	}
	
	m.logger.Info("Certificate manager initialized successfully")
	return certMgr, nil
}

// startACMEServer starts the ACME protocol server
func (m *Manager) startACMEServer(ctx context.Context, certMgr certmanager.Manager) (*acme.HTTPServer, error) {
	m.logger.Info("Starting ACME server", "port", m.config.HTTPPort)
	
	acmeServer := acme.NewHTTPServer(m.config, certMgr, m.logger)
	
	// Start the server in a goroutine
	go func() {
		if err := acmeServer.Start(ctx); err != nil {
			m.logger.Error("ACME server error", "error", err)
		}
	}()
	
	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)
	
	m.logger.Info("ACME server started successfully")
	return acmeServer, nil
}

// startUnifiedServer starts a unified server with both ACME and management features
func (m *Manager) startUnifiedServer(ctx context.Context, certMgr certmanager.Manager) (*UnifiedServer, error) {
	m.logger.Info("Starting unified server", "port", m.config.HTTPPort)
	
	unifiedServer := &UnifiedServer{
		config:      m.config,
		logger:      m.logger,
		certManager: certMgr,
	}
	
	// Start the server in a goroutine
	go func() {
		if err := unifiedServer.Start(ctx); err != nil {
			m.logger.Error("Unified server error", "error", err)
		}
	}()
	
	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)
	
	m.logger.Info("Unified server started successfully")
	return unifiedServer, nil
}

// UnifiedServer combines ACME and management functionality in one server
type UnifiedServer struct {
	config      *config.Config
	logger      *logger.Logger
	certManager certmanager.Manager
	httpServer  *http.Server
}

// Start starts the unified server
func (u *UnifiedServer) Start(ctx context.Context) error {
	// Create router
	router := mux.NewRouter()
	
	// Add ACME server handlers
	acmeServer := acme.NewServer(u.config, u.certManager, u.logger)
	acmeServer.RegisterHandlers(router)
	
	// Add management server handlers
	mgmtServer := management.NewServer(u.config, u.certManager, u.logger)
	mgmtServer.RegisterHandlers(router)
	
	// Create HTTP server
	u.httpServer = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", u.config.BindAddress, u.config.HTTPPort),
		Handler: router,
	}
	
	u.logger.Info("Starting unified HTTP server", "address", u.httpServer.Addr)
	
	// Start server
	if err := u.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("unified server failed: %w", err)
	}
	
	return nil
}

// Shutdown shuts down the unified server
func (u *UnifiedServer) Shutdown() error {
	u.logger.Info("Shutting down unified server")
	
	if u.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		if err := u.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown unified server: %w", err)
		}
	}
	
	return nil
}
