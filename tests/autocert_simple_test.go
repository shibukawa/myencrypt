package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// TestAutocertBasicCompatibility tests basic autocert compatibility
func TestAutocertBasicCompatibility(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14011)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("AutocertSetup", func(t *testing.T) {
		// Create cache directory
		cacheDir := filepath.Join(server.TmpDir, "autocert-cache")
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			t.Fatalf("Failed to create cache dir: %v", err)
		}

		// Create autocert manager
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist("test.localhost", "example.localhost"),
			Client: &acme.Client{
				DirectoryURL: fmt.Sprintf("http://localhost:%d/acme/directory", server.Config.HTTPPort),
			},
		}

		// Test manager creation
		if m == nil {
			t.Fatal("Failed to create autocert manager")
		}
		t.Log("✅ Autocert manager created")

		// Test TLS config
		tlsConfig := m.TLSConfig()
		if tlsConfig == nil {
			t.Fatal("Failed to create TLS config")
		}
		t.Log("✅ TLS config created")

		// Test HTTP handler
		handler := m.HTTPHandler(nil)
		if handler == nil {
			t.Fatal("Failed to create HTTP handler")
		}
		t.Log("✅ HTTP handler created")
	})

	t.Run("ACMEClientOperations", func(t *testing.T) {
		// Create ACME client with proper key setup
		client, err := NewACMEClient(server.Config.HTTPPort)
		if err != nil {
			t.Fatalf("Failed to create ACME client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// 1. Directory discovery
		dir, err := client.client.Discover(ctx)
		if err != nil {
			t.Fatalf("Directory discovery failed: %v", err)
		}
		t.Logf("✅ Directory: %s", dir.RegURL)

		// 2. Account registration
		registeredAccount, err := client.RegisterAccount(ctx)
		if err != nil {
			t.Fatalf("Account registration failed: %v", err)
		}
		t.Logf("✅ Account registered: %s", registeredAccount.URI)

		// 3. Order creation
		order, err := client.CreateOrder(ctx, []string{"test.localhost"})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}
		t.Logf("✅ Order created: %s", order.URI)

		// 4. Test what happens when we try to get authorization
		// (This will fail, but we can test the error handling)
		if len(order.AuthzURLs) > 0 {
			_, err := client.client.GetAuthorization(ctx, order.AuthzURLs[0])
			if err != nil {
				t.Logf("⚠️  Authorization failed as expected: %v", err)
			} else {
				t.Log("🎉 Authorization succeeded (unexpected but good!)")
			}
		}
	})

	t.Run("DatabasePersistence", func(t *testing.T) {
		// Verify that ACME operations are persisted
		time.Sleep(1 * time.Second) // Wait for DB writes

		stats, err := server.GetDatabaseStats()
		if err != nil {
			t.Fatalf("Failed to get database stats: %v", err)
		}

		t.Logf("📊 Database stats: %+v", stats)

		if stats["accounts"] == 0 {
			t.Error("No accounts found in database")
		}
		if stats["orders"] == 0 {
			t.Error("No orders found in database")
		}

		t.Log("✅ ACME operations persisted to database")
	})
}

// TestAutocertErrorScenarios tests error handling scenarios
func TestAutocertErrorScenarios(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14012)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("InvalidDomainRejection", func(t *testing.T) {
		client, err := NewACMEClient(server.Config.HTTPPort)
		if err != nil {
			t.Fatalf("Failed to create ACME client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Register account
		_, err = client.RegisterAccount(ctx)
		if err != nil {
			t.Fatalf("Account registration failed: %v", err)
		}

		// Try to create order for disallowed domain
		_, err = client.CreateOrder(ctx, []string{"forbidden.domain.com"})

		if err == nil {
			t.Error("Expected error for forbidden domain, but got none")
		} else {
			t.Logf("✅ Forbidden domain rejected: %v", err)
		}
	})

	t.Run("ServerUnavailability", func(t *testing.T) {
		// Test with non-existent server
		client := &acme.Client{
			DirectoryURL: "http://localhost:99999/acme/directory",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := client.Discover(ctx)
		if err == nil {
			t.Error("Expected error for unavailable server, but got none")
		} else {
			t.Logf("✅ Server unavailability handled: %v", err)
		}
	})
}

// TestAutocertConcurrency tests concurrent autocert operations
func TestAutocertConcurrency(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14013)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("ConcurrentAccountRegistration", func(t *testing.T) {
		const numClients = 3
		results := make(chan error, numClients)

		// Start multiple clients concurrently
		for i := 0; i < numClients; i++ {
			go func(clientID int) {
				client, err := NewACMEClient(server.Config.HTTPPort)
				if err != nil {
					results <- err
					return
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				// Register account
				_, err = client.RegisterAccount(ctx)
				results <- err
			}(i)
		}

		// Wait for all clients
		var errors []error
		for i := 0; i < numClients; i++ {
			if err := <-results; err != nil {
				errors = append(errors, err)
			}
		}

		if len(errors) > 0 {
			t.Errorf("Some concurrent registrations failed: %v", errors)
		} else {
			t.Logf("✅ All %d concurrent registrations succeeded", numClients)
		}

		// Verify database has all accounts
		time.Sleep(1 * time.Second)
		stats, err := server.GetDatabaseStats()
		if err != nil {
			t.Fatalf("Failed to get database stats: %v", err)
		}

		if stats["accounts"] < numClients {
			t.Errorf("Expected at least %d accounts, got %d", numClients, stats["accounts"])
		}
	})
}

// BenchmarkAutocertOperations benchmarks basic ACME operations
func BenchmarkAutocertOperations(b *testing.B) {
	// Create test server
	server := NewTestServer(&testing.T{}, 14014)
	defer server.Stop()

	// Start server
	server.Start(&testing.T{})

	b.Run("DirectoryDiscovery", func(b *testing.B) {
		ctx := context.Background()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			client, err := NewACMEClient(server.Config.HTTPPort)
			if err != nil {
				b.Fatalf("Failed to create ACME client: %v", err)
			}

			_, err = client.client.Discover(ctx)
			if err != nil {
				b.Fatalf("Directory discovery failed: %v", err)
			}
		}
	})

	b.Run("AccountRegistration", func(b *testing.B) {
		ctx := context.Background()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			client, err := NewACMEClient(server.Config.HTTPPort)
			if err != nil {
				b.Fatalf("Failed to create ACME client: %v", err)
			}

			_, err = client.RegisterAccount(ctx)
			if err != nil {
				b.Fatalf("Account registration failed: %v", err)
			}
		}
	})
}
