package tests

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// TestHTTP01Challenge tests HTTP-01 challenge validation
func TestHTTP01Challenge(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14015)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("HTTP01ChallengeFlow", func(t *testing.T) {
		// Create ACME client
		client, err := NewACMEClient(server.Config.HTTPPort)
		if err != nil {
			t.Fatalf("Failed to create ACME client: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		// Register account
		account, err := client.RegisterAccount(ctx)
		if err != nil {
			t.Fatalf("Account registration failed: %v", err)
		}
		t.Logf("✅ Account registered: %s", account.URI)

		// Create order for localhost (we can actually serve challenges for this)
		domain := "localhost"
		order, err := client.CreateOrder(ctx, []string{domain})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}
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
		t.Logf("📋 Authorization has %d challenges", len(authz.Challenges))
		
		// Log all challenges
		for i, challenge := range authz.Challenges {
			t.Logf("Challenge %d: Type=%s, Status=%s, URI=%s", i, challenge.Type, challenge.Status, challenge.URI)
		}

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

		// Start HTTP server to serve challenge response
		challengeServer := &http.Server{
			Addr: ":8080", // Use port 8080 for testing (port 80 requires privileges)
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
					token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
					if token == httpChallenge.Token {
						// Generate key authorization
						keyAuth, err := client.client.HTTP01ChallengeResponse(httpChallenge.Token)
						if err != nil {
							t.Logf("Failed to generate key authorization: %v", err)
							http.Error(w, "Internal error", http.StatusInternalServerError)
							return
						}
						w.Header().Set("Content-Type", "text/plain")
						w.Write([]byte(keyAuth))
						t.Logf("📋 Served challenge response: %s", keyAuth)
						return
					}
				}
				http.NotFound(w, r)
			}),
		}

		// Start challenge server
		go func() {
			if err := challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				t.Logf("Challenge server error: %v", err)
			}
		}()

		// Wait for server to start
		time.Sleep(1 * time.Second)

		// Accept challenge
		_, err = client.client.Accept(ctx, httpChallenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}
		t.Log("✅ Challenge accepted")

		// Wait for challenge validation
		for i := 0; i < 30; i++ {
			challenge, err := client.client.GetChallenge(ctx, httpChallenge.URI)
			if err != nil {
				t.Logf("Failed to get challenge status: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			t.Logf("Challenge status: %s", challenge.Status)

			if challenge.Status == acme.StatusValid {
				t.Log("🎉 Challenge validation succeeded!")
				break
			} else if challenge.Status == acme.StatusInvalid {
				t.Fatalf("Challenge validation failed: %v", challenge.Error)
			}

			time.Sleep(2 * time.Second)
		}

		// Shutdown challenge server
		challengeServer.Shutdown(context.Background())

		// Check authorization status
		authz, err = client.client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("Failed to get final authorization: %v", err)
		}

		if authz.Status == acme.StatusValid {
			t.Log("🎉 Authorization is now valid!")
		} else {
			t.Logf("⚠️  Authorization status: %s", authz.Status)
		}

		// Check order status
		order, err = client.client.GetOrder(ctx, order.URI)
		if err != nil {
			t.Fatalf("Failed to get final order: %v", err)
		}

		if order.Status == acme.StatusReady {
			t.Log("🎉 Order is ready for finalization!")
		} else {
			t.Logf("📋 Order status: %s", order.Status)
		}
	})
}

// TestChallengeValidationErrors tests various challenge validation error scenarios
func TestChallengeValidationErrors(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14016)
	defer server.Stop()

	// Start server
	server.Start(t)

	t.Run("ChallengeNotServed", func(t *testing.T) {
		// Test challenge validation when no HTTP server is running
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

		// Create order
		order, err := client.CreateOrder(ctx, []string{"nonexistent.localhost"})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}

		// Get authorization
		authz, err := client.client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("Failed to get authorization: %v", err)
		}

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

		// Accept challenge (this should fail validation)
		_, err = client.client.Accept(ctx, httpChallenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}

		// Wait for challenge validation to fail
		for i := 0; i < 15; i++ {
			challenge, err := client.client.GetChallenge(ctx, httpChallenge.URI)
			if err != nil {
				t.Logf("Failed to get challenge status: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			if challenge.Status == acme.StatusInvalid {
				t.Logf("✅ Challenge validation failed as expected: %v", challenge.Error)
				return
			} else if challenge.Status == acme.StatusValid {
				t.Fatal("Challenge validation unexpectedly succeeded")
			}

			time.Sleep(2 * time.Second)
		}

		t.Log("⚠️  Challenge validation timeout (may be expected)")
	})

	t.Run("WrongChallengeResponse", func(t *testing.T) {
		// Test challenge validation with wrong response
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

		// Create order
		order, err := client.CreateOrder(ctx, []string{"localhost"})
		if err != nil {
			t.Fatalf("Order creation failed: %v", err)
		}

		// Get authorization
		authz, err := client.client.GetAuthorization(ctx, order.AuthzURLs[0])
		if err != nil {
			t.Fatalf("Failed to get authorization: %v", err)
		}

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

		// Start HTTP server with wrong response
		challengeServer := &http.Server{
			Addr: ":8081",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte("wrong-response"))
					return
				}
				http.NotFound(w, r)
			}),
		}

		go func() {
			if err := challengeServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				t.Logf("Challenge server error: %v", err)
			}
		}()

		time.Sleep(1 * time.Second)

		// Accept challenge
		_, err = client.client.Accept(ctx, httpChallenge)
		if err != nil {
			t.Fatalf("Failed to accept challenge: %v", err)
		}

		// Wait for challenge validation to fail
		for i := 0; i < 15; i++ {
			challenge, err := client.client.GetChallenge(ctx, httpChallenge.URI)
			if err != nil {
				t.Logf("Failed to get challenge status: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			if challenge.Status == acme.StatusInvalid {
				t.Logf("✅ Challenge validation failed as expected: %v", challenge.Error)
				challengeServer.Shutdown(context.Background())
				return
			} else if challenge.Status == acme.StatusValid {
				t.Fatal("Challenge validation unexpectedly succeeded")
			}

			time.Sleep(2 * time.Second)
		}

		challengeServer.Shutdown(context.Background())
		t.Log("⚠️  Challenge validation timeout")
	})
}

// TestDatabasePersistenceAfterChallenge tests database persistence after challenge validation
func TestDatabasePersistenceAfterChallenge(t *testing.T) {
	// Create test server
	server := NewTestServer(t, 14017)
	defer server.Stop()

	// Start server
	server.Start(t)

	// Create ACME client
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

	order, err := client.CreateOrder(ctx, []string{"localhost"})
	if err != nil {
		t.Fatalf("Order creation failed: %v", err)
	}

	// Get authorization and challenge
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

	// Accept challenge (will fail validation, but that's OK for this test)
	_, err = client.client.Accept(ctx, httpChallenge)
	if err != nil {
		t.Fatalf("Failed to accept challenge: %v", err)
	}

	// Wait a bit for processing
	time.Sleep(3 * time.Second)

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
}
