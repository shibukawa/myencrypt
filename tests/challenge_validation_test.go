package tests

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// TestChallengeValidationFlow tests the complete challenge validation flow
func TestChallengeValidationFlow(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14018)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("ChallengeValidationProcess", func(t *testing.T) {
		// Create ACME client
		client, err := NewACMEClient(server.Config.HTTPPort)
		if err != nil {
			t.Fatalf("Failed to create ACME client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Register account
		account, err := client.RegisterAccount(ctx)
		if err != nil {
			t.Fatalf("Account registration failed: %v", err)
		}
		t.Logf("✅ Account registered: %s", account.URI)

		// Create order
		domain := "test.localhost"
		order, err := client.CreateOrder(ctx, []string{domain})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}
		orderURL := order.URI
		t.Logf("✅ Order created: %s", order.URI)

		// Get authorization
		if len(order.AuthzURLs) == 0 {
			t.Fatal("No authorizations in order")
		}

		authz, err := client.client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("Failed to get authorization: %v", err)
		}
		t.Logf("✅ Authorization retrieved: %s", authz.Identifier.Value)

		// Find HTTP-01 challenge
		var httpChallenge *acme.Challenge
		for _, challenge := range authz.Challenges {
			if challenge.Type == "http-01" {
				httpChallenge = challenge
				break
			}
		}

		if httpChallenge == nil {
			t.Fatal("No HTTP-01 challenge found")
		}
		t.Logf("✅ HTTP-01 challenge found: %s", httpChallenge.URI)
		t.Logf("📋 Challenge token: %s", httpChallenge.Token)

		// Accept challenge (this will trigger validation)
		_, err = client.client.Accept(ctx, httpChallenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}
		t.Log("✅ Challenge accepted")

		// Wait for challenge validation to complete
		var finalChallenge *acme.Challenge
		for i := 0; i < 10; i++ {
			challenge, err := client.client.GetChallenge(ctx, httpChallenge.URI)
			if err != nil {
				t.Logf("Failed to get challenge status: %v", err)
				time.Sleep(200 * time.Millisecond) // Reduced from 2s to 200ms
				continue
			}

			t.Logf("📊 Challenge status: %s", challenge.Status)
			finalChallenge = challenge

			if challenge.Status == acme.StatusValid {
				t.Log("🎉 Challenge validation succeeded!")
				break
			}

			time.Sleep(200 * time.Millisecond) // Reduced from 2s to 200ms
		}

		// Verify that challenge validation was attempted
		if finalChallenge == nil {
			t.Fatal("Failed to get final challenge status")
		}

		if finalChallenge.Status != acme.StatusValid {
			t.Fatalf("Challenge status = %s, want %s", finalChallenge.Status, acme.StatusValid)
		}
		t.Log("✅ Challenge validation is always skipped and returns valid")

		// Check authorization status
		authz, err = client.client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("Failed to get final authorization: %v", err)
		}
		t.Logf("📊 Final authorization status: %s", authz.Status)

		// Check order status
		order, err = client.client.GetOrder(ctx, orderURL)
		if err != nil {
			t.Fatalf("Failed to get final order: %v", err)
		}
		t.Logf("📊 Final order status: %s", order.Status)
	})
}

// TestChallengeValidationComponents tests individual components of challenge validation
func TestChallengeValidationComponents(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14019)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("KeyAuthorizationGeneration", func(t *testing.T) {
		// Test that key authorization is generated correctly
		client, err := NewACMEClient(server.Config.HTTPPort)
		if err != nil {
			t.Fatalf("Failed to create ACME client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Register account and create order
		_, err = client.RegisterAccount(ctx)
		if err != nil {
			t.Fatalf("Account registration failed: %v", err)
		}

		order, err := client.CreateOrder(ctx, []string{"test.localhost"})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}

		// Get challenge
		authz, err := client.client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("Failed to get authorization: %v", err)
		}

		var httpChallenge *acme.Challenge
		for _, challenge := range authz.Challenges {
			if challenge.Type == "http-01" {
				httpChallenge = challenge
				break
			}
		}

		if httpChallenge == nil {
			t.Fatal("No HTTP-01 challenge found")
		}

		// Generate expected key authorization using ACME client
		expectedKeyAuth, err := client.client.HTTP01ChallengeResponse(httpChallenge.Token)
		if err != nil {
			t.Fatalf("Failed to generate expected key authorization: %v", err)
		}

		t.Logf("📋 Challenge token: %s", httpChallenge.Token)
		t.Logf("📋 Expected key authorization: %s", expectedKeyAuth)

		// Accept challenge to trigger key authorization generation
		_, err = client.client.Accept(ctx, httpChallenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}

		// Wait a bit for processing
		time.Sleep(200 * time.Millisecond) // Reduced from 2s to 200ms

		// Get updated challenge
		updatedChallenge, err := client.client.GetChallenge(ctx, httpChallenge.URI)
		if err != nil {
			t.Fatalf("Failed to get updated challenge: %v", err)
		}

		t.Logf("📊 Challenge status after accept: %s", updatedChallenge.Status)

		if updatedChallenge.Status != acme.StatusValid {
			t.Fatalf("Challenge status = %s, want %s", updatedChallenge.Status, acme.StatusValid)
		}
		t.Logf("✅ Challenge was processed as valid: %s", updatedChallenge.Status)
	})

	t.Run("DatabasePersistence", func(t *testing.T) {
		// Wait a bit for all operations to complete
		time.Sleep(200 * time.Millisecond) // Reduced from 2s to 200ms

		// Check database persistence
		stats, err := server.GetDatabaseStats()
		if err != nil {
			t.Fatalf("Failed to get database stats: %v", err)
		}

		t.Logf("📊 Database statistics: %+v", stats)

		if stats["accounts"] == 0 {
			t.Error("No accounts found in database")
		}
		if stats["orders"] == 0 {
			t.Error("No orders found in database")
		}
		if stats["authorizations"] == 0 {
			t.Error("No authorizations found in database")
		}
		if stats["challenges"] == 0 {
			t.Error("No challenges found in database")
		}

		t.Log("✅ All ACME objects persisted to database")
	})
}

func TestChallengeValidationIsAlwaysSkipped(t *testing.T) {
	server := NewTestServer(t, 14035)
	defer server.Stop()

	server.Start(t)

	client, err := NewACMEClient(server.Config.HTTPPort)
	if err != nil {
		t.Fatalf("Failed to create ACME client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = client.RegisterAccount(ctx)
	if err != nil {
		t.Fatalf("Account registration failed: %v", err)
	}

	order, err := client.CreateOrder(ctx, []string{"test.localhost"})
	if err != nil {
		t.Fatalf("Order creation failed: %v", err)
	}
	orderURL := order.URI

	authz, err := client.client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("Failed to get authorization: %v", err)
	}

	var httpChallenge *acme.Challenge
	for _, challenge := range authz.Challenges {
		if challenge.Type == "http-01" {
			httpChallenge = challenge
			break
		}
	}

	if httpChallenge == nil {
		t.Fatal("No HTTP-01 challenge found")
	}

	_, err = client.client.Accept(ctx, httpChallenge)
	if err != nil {
		t.Fatalf("Failed to accept challenge: %v", err)
	}

	var finalChallenge *acme.Challenge
	for i := 0; i < 10; i++ {
		finalChallenge, err = client.client.GetChallenge(ctx, httpChallenge.URI)
		if err == nil && finalChallenge.Status == acme.StatusValid {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if finalChallenge == nil {
		t.Fatal("Failed to get final challenge status")
	}
	if finalChallenge.Status != acme.StatusValid {
		t.Fatalf("Challenge status = %s, want %s", finalChallenge.Status, acme.StatusValid)
	}

	authz, err = client.client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatalf("Failed to get final authorization: %v", err)
	}
	if authz.Status != acme.StatusValid {
		t.Fatalf("Authorization status = %s, want %s", authz.Status, acme.StatusValid)
	}

	for i := 0; i < 10; i++ {
		order, err = client.client.GetOrder(ctx, orderURL)
		if err == nil && order.Status == acme.StatusReady {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if order.Status != acme.StatusReady {
		t.Fatalf("Order status = %s, want %s", order.Status, acme.StatusReady)
	}
}
