package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	_ "github.com/mattn/go-sqlite3"
	"github.com/gorilla/mux"

	myacme "github.com/shibukawayoshiki/myencrypt2/internal/acme"
	"github.com/shibukawayoshiki/myencrypt2/internal/certmanager"
	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
	"github.com/shibukawayoshiki/myencrypt2/internal/management"
)

// TestServer represents a test server instance
type TestServer struct {
	Config      *config.Config
	Server      *http.Server
	ACMEServer  *myacme.Server
	MgmtServer  *management.Server
	CertManager certmanager.Manager
	Logger      logger.Logger
	TmpDir      string
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewTestServer creates a new test server instance
func NewTestServer(t *testing.T, port int) *TestServer {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "myencrypt-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Test configuration
	cfg := &config.Config{
		BindAddress:        "127.0.0.1",
		HTTPPort:          port,
		CertStorePath:     tmpDir,
		IndividualCertTTL: 24 * time.Hour,
		CACertTTL:         800 * 24 * time.Hour,
		DefaultAllowedDomains: []string{"localhost", "*.localhost", "*.test"},
	}

	// Initialize components
	log := logger.New()
	certMgr := certmanager.New(cfg, log)

	// Initialize CA
	if err := certMgr.InitializeCA(); err != nil {
		t.Fatalf("CA initialization failed: %v", err)
	}

	// Create allowed domains file
	allowedDomainsPath := filepath.Join(tmpDir, "allowed-domains.txt")
	allowedDomainsContent := "localhost\n*.localhost\nexample.localhost\ntest.localhost\n"
	if err := os.WriteFile(allowedDomainsPath, []byte(allowedDomainsContent), 0644); err != nil {
		t.Fatalf("Failed to create allowed domains: %v", err)
	}

	if err := certMgr.LoadAllowedDomains(); err != nil {
		t.Fatalf("Failed to load allowed domains: %v", err)
	}

	// Initialize servers
	acmeServer := myacme.NewServer(cfg, certMgr, log)
	mgmtServer := management.NewServer(cfg, certMgr, log)

	// Create HTTP server
	router := mux.NewRouter()
	acmeServer.RegisterHandlers(router)
	mgmtServer.RegisterHandlers(router)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.HTTPPort),
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TestServer{
		Config:      cfg,
		Server:      server,
		ACMEServer:  acmeServer,
		MgmtServer:  mgmtServer,
		CertManager: certMgr,
		Logger:      *log,
		TmpDir:      tmpDir,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start starts the test server in goroutines
func (ts *TestServer) Start(t *testing.T) {
	// Start HTTP server
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		if err := ts.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	}()

	// Start ACME server background tasks
	ts.wg.Add(1)
	go func() {
		defer ts.wg.Done()
		if err := ts.ACMEServer.Start(); err != nil {
			t.Errorf("ACME server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(2 * time.Second)

	// Verify server is running
	if !ts.isHealthy() {
		t.Fatal("Server failed to start properly")
	}
}

// Stop stops the test server and cleans up
func (ts *TestServer) Stop() {
	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	
	if err := ts.Server.Shutdown(shutdownCtx); err != nil {
		fmt.Printf("Server shutdown error: %v\n", err)
	}

	// Cancel ACME server context
	ts.cancel()

	// Wait for goroutines to finish
	done := make(chan struct{})
	go func() {
		ts.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines finished
	case <-time.After(10 * time.Second):
		fmt.Println("Warning: Goroutines did not finish within timeout")
	}

	// Clean up temporary directory
	os.RemoveAll(ts.TmpDir)
}

// isHealthy checks if the server is responding
func (ts *TestServer) isHealthy() bool {
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/health", ts.Config.HTTPPort))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// GetDatabaseStats returns database statistics
func (ts *TestServer) GetDatabaseStats() (map[string]int, error) {
	dbPath := filepath.Join(ts.TmpDir, "myencrypt.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	stats := make(map[string]int)
	tables := []string{"accounts", "orders", "certificates", "authorizations", "challenges", "nonces"}
	
	for _, table := range tables {
		var count int
		err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			return nil, err
		}
		stats[table] = count
	}

	return stats, nil
}

// ACMEClient represents a test ACME client
type ACMEClient struct {
	client *acme.Client
	port   int
}

// NewACMEClient creates a new test ACME client
func NewACMEClient(port int) (*ACMEClient, error) {
	// Generate account key
	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %w", err)
	}

	// Create ACME client
	client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: fmt.Sprintf("http://localhost:%d/acme/directory", port),
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 30 * time.Second,
		},
	}

	return &ACMEClient{
		client: client,
		port:   port,
	}, nil
}

// RegisterAccount registers an ACME account
func (ac *ACMEClient) RegisterAccount(ctx context.Context) (*acme.Account, error) {
	account := &acme.Account{
		Contact: []string{"mailto:test@example.com"},
	}
	
	return ac.client.Register(ctx, account, acme.AcceptTOS)
}

// CreateOrder creates a certificate order
func (ac *ACMEClient) CreateOrder(ctx context.Context, domains []string) (*acme.Order, error) {
	var authzIDs []acme.AuthzID
	for _, domain := range domains {
		authzIDs = append(authzIDs, acme.AuthzID{Type: "dns", Value: domain})
	}
	
	return ac.client.AuthorizeOrder(ctx, authzIDs)
}

// TestIntegration tests the complete ACME flow
func TestIntegration(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14005)
	defer server.Stop()

	// Start server in goroutines
	server.Start(t)

	t.Run("ServerHealth", func(t *testing.T) {
		if !server.isHealthy() {
			t.Fatal("Server health check failed")
		}
		t.Log("✅ Server is healthy")
	})

	t.Run("ACMEDirectory", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/acme/directory", server.Config.HTTPPort))
		if err != nil {
			t.Fatalf("ACME directory request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ACME directory returned status %d", resp.StatusCode)
		}
		t.Log("✅ ACME directory is working")
	})

	t.Run("ACMEClientFlow", func(t *testing.T) {
		// Create ACME client in goroutine
		clientDone := make(chan error, 1)
		var account *acme.Account
		var order *acme.Order

		go func() {
			defer close(clientDone)
			
			// Create ACME client
			client, err := NewACMEClient(server.Config.HTTPPort)
			if err != nil {
				clientDone <- fmt.Errorf("failed to create ACME client: %w", err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Register account
			t.Log("👤 Registering ACME account...")
			account, err = client.RegisterAccount(ctx)
			if err != nil {
				clientDone <- fmt.Errorf("failed to register account: %w", err)
				return
			}
			t.Logf("✅ Account registered: %s", account.URI)

			// Create order
			t.Log("📋 Creating certificate order...")
			order, err = client.CreateOrder(ctx, []string{"example.localhost"})
			if err != nil {
				clientDone <- fmt.Errorf("failed to create order: %w", err)
				return
			}
			t.Logf("✅ Order created: %s", order.URI)

			clientDone <- nil
		}()

		// Wait for client to complete
		select {
		case err := <-clientDone:
			if err != nil {
				t.Fatalf("ACME client error: %v", err)
			}
		case <-time.After(45 * time.Second):
			t.Fatal("ACME client timeout")
		}

		// Verify account and order were created
		if account == nil {
			t.Fatal("Account was not created")
		}
		if order == nil {
			t.Fatal("Order was not created")
		}
	})

	t.Run("DatabaseVerification", func(t *testing.T) {
		// Wait for database writes
		time.Sleep(2 * time.Second)

		stats, err := server.GetDatabaseStats()
		if err != nil {
			t.Fatalf("Failed to get database stats: %v", err)
		}

		t.Logf("📊 Database statistics: %+v", stats)

		if stats["accounts"] == 0 {
			t.Error("No accounts found in database")
		} else {
			t.Logf("✅ Found %d accounts in database", stats["accounts"])
		}

		if stats["orders"] == 0 {
			t.Error("No orders found in database")
		} else {
			t.Logf("✅ Found %d orders in database", stats["orders"])
		}
	})

	t.Run("ManagementInterface", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://localhost:%d/", server.Config.HTTPPort))
		if err != nil {
			t.Fatalf("Management interface request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Management interface returned status %d", resp.StatusCode)
		}
		t.Log("✅ Management interface is accessible")
	})
}

// TestConcurrentClients tests multiple ACME clients running concurrently
func TestConcurrentClients(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14006)
	defer server.Stop()

	// Start server
	server.Start(t)

	const numClients = 3
	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	// Start multiple ACME clients concurrently
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			client, err := NewACMEClient(server.Config.HTTPPort)
			if err != nil {
				errors <- fmt.Errorf("client %d: failed to create ACME client: %w", clientID, err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Register account
			account, err := client.RegisterAccount(ctx)
			if err != nil {
				errors <- fmt.Errorf("client %d: failed to register account: %w", clientID, err)
				return
			}

			t.Logf("Client %d: Account registered: %s", clientID, account.URI)

			// Create order
			domain := fmt.Sprintf("client%d.localhost", clientID)
			order, err := client.CreateOrder(ctx, []string{domain})
			if err != nil {
				errors <- fmt.Errorf("client %d: failed to create order: %w", clientID, err)
				return
			}

			t.Logf("Client %d: Order created: %s", clientID, order.URI)
		}(i)
	}

	// Wait for all clients to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All clients completed
	case <-time.After(60 * time.Second):
		t.Fatal("Concurrent clients test timeout")
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	// Verify database has multiple accounts
	time.Sleep(2 * time.Second)
	stats, err := server.GetDatabaseStats()
	if err != nil {
		t.Fatalf("Failed to get database stats: %v", err)
	}

	t.Logf("📊 Final database statistics: %+v", stats)

	if stats["accounts"] < numClients {
		t.Errorf("Expected at least %d accounts, got %d", numClients, stats["accounts"])
	}
}
