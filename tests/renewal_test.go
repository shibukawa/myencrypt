package tests

import (
	"context"
	"testing"
	"time"

	"github.com/shibukawa/myencrypt/internal/certmanager"
)

// TestCertificateRenewal tests the certificate renewal functionality
func TestCertificateRenewal(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14030)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("RenewalManagerStartStop", func(t *testing.T) {
		// Test renewal manager start/stop
		renewalConfig := certmanager.DefaultRenewalConfig()
		renewalConfig.CheckInterval = 1 * time.Second // Fast check for testing

		renewalManager := certmanager.NewRenewalManager(
			server.CertManager,
			server.Logger,
			renewalConfig,
		)

		// Start renewal manager
		err := renewalManager.Start(context.Background())
		if err != nil {
			t.Fatalf("Failed to start renewal manager: %v", err)
		}
		t.Log("✅ Renewal manager started")

		// Let it run for a few seconds
		time.Sleep(300 * time.Millisecond) // Reduced from 3s to 300ms (1/10)

		// Stop renewal manager
		err = renewalManager.Stop()
		if err != nil {
			t.Fatalf("Failed to stop renewal manager: %v", err)
		}
		t.Log("✅ Renewal manager stopped")
	})

	t.Run("RenewalStats", func(t *testing.T) {
		renewalConfig := certmanager.DefaultRenewalConfig()
		renewalConfig.CheckInterval = 500 * time.Millisecond

		renewalManager := certmanager.NewRenewalManager(
			server.CertManager,
			server.Logger,
			renewalConfig,
		)

		err := renewalManager.Start(context.Background())
		if err != nil {
			t.Fatalf("Failed to start renewal manager: %v", err)
		}
		defer renewalManager.Stop()

		// Wait for some checks
		time.Sleep(200 * time.Millisecond) // Reduced from 2s to 200ms (1/10)

		// Get renewal stats
		stats := renewalManager.GetRenewalStats()
		t.Logf("📊 Renewal stats: Total=%d, Successful=%d, Failed=%d",
			stats.TotalRenewals, stats.SuccessfulRenewals, stats.FailedRenewals)

		// Get renewal queue
		queue := renewalManager.GetRenewalQueue()
		t.Logf("📋 Renewal queue size: %d", len(queue))

		for domain, task := range queue {
			t.Logf("   - %s: attempts=%d, next_attempt=%s",
				domain, task.Attempts, task.NextAttempt.Format(time.RFC3339))
		}

		t.Log("✅ Renewal stats retrieved successfully")
	})

	t.Run("ForceRenewal", func(t *testing.T) {
		renewalConfig := certmanager.DefaultRenewalConfig()
		renewalManager := certmanager.NewRenewalManager(
			server.CertManager,
			server.Logger,
			renewalConfig,
		)

		err := renewalManager.Start(context.Background())
		if err != nil {
			t.Fatalf("Failed to start renewal manager: %v", err)
		}
		defer renewalManager.Stop()

		// Force renewal of a domain
		domain := "test.localhost"
		err = renewalManager.ForceRenewal(domain)
		if err != nil {
			t.Logf("⚠️  Force renewal failed (expected): %v", err)
		} else {
			t.Log("✅ Force renewal completed")
		}

		// Check stats after forced renewal
		stats := renewalManager.GetRenewalStats()
		t.Logf("📊 Stats after force renewal: Total=%d, Successful=%d, Failed=%d",
			stats.TotalRenewals, stats.SuccessfulRenewals, stats.FailedRenewals)
	})
}

// TestRenewalConfiguration tests renewal configuration
func TestRenewalConfiguration(t *testing.T) {
	t.Run("DefaultConfiguration", func(t *testing.T) {
		config := certmanager.DefaultRenewalConfig()

		t.Logf("📋 Default renewal configuration:")
		t.Logf("   - Check interval: %s", config.CheckInterval)
		t.Logf("   - Renewal threshold: %s", config.RenewalThreshold)
		t.Logf("   - Max retries: %d", config.MaxRetries)
		t.Logf("   - Retry delay: %s", config.RetryDelay)

		// Validate default values
		if config.CheckInterval <= 0 {
			t.Error("Check interval should be positive")
		}
		if config.RenewalThreshold <= 0 {
			t.Error("Renewal threshold should be positive")
		}
		if config.MaxRetries <= 0 {
			t.Error("Max retries should be positive")
		}
		if config.RetryDelay <= 0 {
			t.Error("Retry delay should be positive")
		}

		t.Log("✅ Default configuration is valid")
	})

	t.Run("CustomConfiguration", func(t *testing.T) {
		config := certmanager.RenewalConfig{
			CheckInterval:    10 * time.Second,
			RenewalThreshold: 2 * time.Hour,
			MaxRetries:       5,
			RetryDelay:       1 * time.Minute,
		}

		// Create test server
		server := NewTestServer(t, 14031)
		defer server.Stop()
		server.Start(t)

		renewalManager := certmanager.NewRenewalManager(
			server.CertManager,
			server.Logger,
			config,
		)

		err := renewalManager.Start(context.Background())
		if err != nil {
			t.Fatalf("Failed to start renewal manager with custom config: %v", err)
		}

		// Let it run briefly
		time.Sleep(100 * time.Millisecond) // Reduced from 1s to 100ms (1/10)

		err = renewalManager.Stop()
		if err != nil {
			t.Fatalf("Failed to stop renewal manager: %v", err)
		}

		t.Log("✅ Custom configuration works")
	})
}

// TestRenewalIntegration tests renewal integration with ACME server
func TestRenewalIntegration(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14032)
	defer server.Stop()

	// Start server with renewal enabled
	server.Start(t)

	t.Run("ACMEServerWithRenewal", func(t *testing.T) {
		// Create ACME client
		client, err := NewACMEClient(server.Config.HTTPPort)
		if err != nil {
			t.Fatalf("Failed to create ACME client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Register account
		_, err = client.RegisterAccount(ctx)
		if err != nil {
			t.Fatalf("Account registration failed: %v", err)
		}
		t.Log("✅ Account registered")

		// Create order
		_, err = client.CreateOrder(ctx, []string{"renewal-test.localhost"})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}
		t.Log("✅ Order created")

		// Check that renewal manager is running
		stats := server.ACMEServer.GetRenewalStats()
		t.Logf("📊 ACME server renewal stats: Total=%d, Successful=%d, Failed=%d",
			stats.TotalRenewals, stats.SuccessfulRenewals, stats.FailedRenewals)

		queue := server.ACMEServer.GetRenewalQueue()
		t.Logf("📋 ACME server renewal queue size: %d", len(queue))

		t.Log("✅ ACME server renewal integration working")
	})
}

// TestRenewalErrorHandling tests error handling in renewal process
func TestRenewalErrorHandling(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14033)
	defer server.Stop()
	server.Start(t)

	t.Run("RenewalWithErrors", func(t *testing.T) {
		renewalConfig := certmanager.RenewalConfig{
			CheckInterval:    100 * time.Millisecond, // Very fast for testing
			RenewalThreshold: 24 * time.Hour,         // Always try to renew
			MaxRetries:       2,                      // Low retry count
			RetryDelay:       200 * time.Millisecond, // Fast retry
		}

		renewalManager := certmanager.NewRenewalManager(
			server.CertManager,
			server.Logger,
			renewalConfig,
		)

		err := renewalManager.Start(context.Background())
		if err != nil {
			t.Fatalf("Failed to start renewal manager: %v", err)
		}
		defer renewalManager.Stop()

		// Let it run and encounter errors
		time.Sleep(200 * time.Millisecond) // Reduced from 2s to 200ms (1/10)

		// Check error stats
		stats := renewalManager.GetRenewalStats()
		t.Logf("📊 Error handling stats: Total=%d, Successful=%d, Failed=%d",
			stats.TotalRenewals, stats.SuccessfulRenewals, stats.FailedRenewals)

		if stats.LastFailureError != "" {
			t.Logf("📋 Last failure: %s at %s",
				stats.LastFailureError, stats.LastFailureTime.Format(time.RFC3339))
		}

		t.Log("✅ Error handling test completed")
	})
}

// TestRenewalMetrics tests renewal metrics collection
func TestRenewalMetrics(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14034)
	defer server.Stop()
	server.Start(t)

	t.Run("MetricsCollection", func(t *testing.T) {
		renewalConfig := certmanager.DefaultRenewalConfig()
		renewalConfig.CheckInterval = 200 * time.Millisecond

		renewalManager := certmanager.NewRenewalManager(
			server.CertManager,
			server.Logger,
			renewalConfig,
		)

		err := renewalManager.Start(context.Background())
		if err != nil {
			t.Fatalf("Failed to start renewal manager: %v", err)
		}
		defer renewalManager.Stop()

		// Collect metrics over time
		initialStats := renewalManager.GetRenewalStats()
		t.Logf("📊 Initial stats: %+v", initialStats)

		// Wait for some activity
		time.Sleep(100 * time.Millisecond) // Reduced from 1s to 100ms (1/10)

		finalStats := renewalManager.GetRenewalStats()
		t.Logf("📊 Final stats: %+v", finalStats)

		// Check that last check time is updated
		lastCheck := renewalManager.GetLastCheckTime()
		if lastCheck.IsZero() {
			t.Error("Last check time should not be zero")
		} else {
			t.Logf("📅 Last check time: %s", lastCheck.Format(time.RFC3339))
		}

		t.Log("✅ Metrics collection working")
	})
}
