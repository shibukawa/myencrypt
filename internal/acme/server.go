package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
	"github.com/shibukawayoshiki/myencrypt2/internal/certmanager"
	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// Server represents the ACME server
// Server represents the ACME server
type Server struct {
	config         *config.Config
	certManager    certmanager.Manager
	renewalManager *certmanager.RenewalManager
	logger         *logger.Logger
	baseURL        string
	storage        Storage
	
	// Legacy in-memory storage for backward compatibility (optional)
	// These will be deprecated in favor of persistent storage
	accounts       map[string]*ServerAccount
	orders         map[string]*ServerOrder
	authorizations map[string]*ServerAuthorization
	challenges     map[string]*ServerChallenge
	certificates   map[string][]byte // Certificate storage (orderID -> PEM chain)
	nonces         map[string]time.Time
	
	// Mutexes for thread safety (for legacy storage)
	accountsMu       sync.RWMutex
	ordersMu         sync.RWMutex
	authorizationsMu sync.RWMutex
	challengesMu     sync.RWMutex
	certificatesMu   sync.RWMutex
	noncesMu         sync.RWMutex
}

// NewServer creates a new ACME server instance
func NewServer(cfg *config.Config, certMgr certmanager.Manager, log *logger.Logger) *Server {
	baseURL := fmt.Sprintf("http://%s:%d", cfg.BindAddress, cfg.HTTPPort)
	if cfg.BindAddress == "0.0.0.0" {
		// In Docker environment, use container name for inter-container communication
		if projectName := os.Getenv("MYENCRYPT_PROJECT_NAME"); projectName != "" {
			// Use the project name as hostname for Docker networking
			baseURL = fmt.Sprintf("http://%s:%d", projectName, cfg.HTTPPort)
		} else {
			// Default to 'myencrypt' for Docker Compose networking
			baseURL = fmt.Sprintf("http://myencrypt:%d", cfg.HTTPPort)
		}
	}
	
	// Initialize SQLite storage
	var storage Storage
	sqliteStorage, err := NewSQLiteStorage(cfg, log, baseURL)
	if err != nil {
		log.Error("Failed to initialize SQLite storage, falling back to file storage", "error", err)
		// Fallback to file storage
		fileStorage, err := NewFileStorage(cfg, log)
		if err != nil {
			log.Error("Failed to initialize file storage, using memory only", "error", err)
			storage = nil
		} else {
			storage = fileStorage
		}
	} else {
		storage = sqliteStorage
	}
	
	// Initialize renewal manager
	renewalConfig := certmanager.DefaultRenewalConfig()
	renewalManager := certmanager.NewRenewalManager(certMgr, *log, renewalConfig)
	
	return &Server{
		config:         cfg,
		certManager:    certMgr,
		renewalManager: renewalManager,
		logger:         log,
		baseURL:        baseURL,
		storage:        storage,
		// Legacy in-memory storage for backward compatibility
		accounts:       make(map[string]*ServerAccount),
		orders:         make(map[string]*ServerOrder),
		authorizations: make(map[string]*ServerAuthorization),
		challenges:     make(map[string]*ServerChallenge),
		certificates:   make(map[string][]byte),
		nonces:         make(map[string]time.Time),
	}
}

// GetDirectory returns the ACME directory
func (s *Server) GetDirectory() *Directory {
	return &Directory{
		NewNonce:   s.baseURL + "/acme/new-nonce",
		NewAccount: s.baseURL + "/acme/new-account",
		NewOrder:   s.baseURL + "/acme/new-order",
		RevokeCert: s.baseURL + "/acme/revoke-cert",
		KeyChange:  s.baseURL + "/acme/key-change",
		Meta: &DirectoryMeta{
			Website:                 "https://github.com/shibukawayoshiki/myencrypt2",
			ExternalAccountRequired: false,
		},
		ExternalAccountRequired: false,
	}
}

// GenerateNonce generates a new nonce for ACME requests
func (s *Server) GenerateNonce() (string, error) {
	// Generate 16 random bytes
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	nonce := base64.URLEncoding.EncodeToString(bytes)
	
	// Store nonce with expiration time (5 minutes)
	s.noncesMu.Lock()
	s.nonces[nonce] = time.Now().Add(5 * time.Minute)
	s.noncesMu.Unlock()
	
	// Clean up expired nonces
	go s.cleanupExpiredNonces()
	
	return nonce, nil
}

// ValidateNonce validates and consumes a nonce
func (s *Server) ValidateNonce(nonce string) error {
	s.noncesMu.Lock()
	defer s.noncesMu.Unlock()
	
	expiry, exists := s.nonces[nonce]
	if !exists {
		return &ProblemDetails{
			Type:   ErrorTypeBadNonce,
			Title:  "Bad nonce",
			Status: http.StatusBadRequest,
			Detail: "The nonce is invalid or has already been used",
		}
	}
	
	if time.Now().After(expiry) {
		delete(s.nonces, nonce)
		return &ProblemDetails{
			Type:   ErrorTypeBadNonce,
			Title:  "Bad nonce",
			Status: http.StatusBadRequest,
			Detail: "The nonce has expired",
		}
	}
	
	// Consume the nonce (one-time use)
	delete(s.nonces, nonce)
	return nil
}

// cleanupExpiredNonces removes expired nonces from memory
func (s *Server) cleanupExpiredNonces() {
	s.noncesMu.Lock()
	defer s.noncesMu.Unlock()
	
	now := time.Now()
	for nonce, expiry := range s.nonces {
		if now.After(expiry) {
			delete(s.nonces, nonce)
		}
	}
}

// CreateAccount creates a new ACME account
func (s *Server) CreateAccount(req *AccountRequest, jwk *JSONWebKey) (*Account, error) {
	// Generate account ID
	accountID, err := s.generateID("acct")
	if err != nil {
		return nil, fmt.Errorf("failed to generate account ID: %w", err)
	}
	
	account := &Account{
		ID:        accountID,
		Key:       jwk,
		Contact:   req.Contact,
		Status:    StatusValid,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	serverAccount := &ServerAccount{
		Account: *account,
	}
	
	// Store in persistent storage first
	if s.storage != nil {
		if err := s.storage.StoreAccount(accountID, serverAccount); err != nil {
			s.logger.Error("Failed to store account in persistent storage", "error", err, "account_id", accountID)
		} else {
			s.logger.Debug("Account stored in persistent storage", "account_id", accountID)
		}
	}
	
	// Also store in memory for backward compatibility
	s.accountsMu.Lock()
	s.accounts[accountID] = serverAccount
	s.accountsMu.Unlock()
	
	s.logger.Info("Created new ACME account", "accountId", accountID, "contact", req.Contact)
	
	return account, nil
}

// getAuthorizationForChallenge retrieves the authorization for a given challenge
func (s *Server) getAuthorizationForChallenge(authzID string) (*ServerAuthorization, error) {
	// Try persistent storage first
	if s.storage != nil {
		authz, err := s.storage.GetAuthorization(authzID)
		if err == nil {
			return authz, nil
		}
		s.logger.Debug("Authorization not found in persistent storage, checking memory", "authz_id", authzID)
	}
	
	// Fallback to memory storage
	s.authorizationsMu.RLock()
	authz, exists := s.authorizations[authzID]
	s.authorizationsMu.RUnlock()
	
	if !exists {
		return nil, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Authorization not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Authorization %s not found", authzID),
		}
	}
	
	return authz, nil
}

// getOrderForAuthorization retrieves the order for a given authorization
func (s *Server) getOrderForAuthorization(orderID string) (*ServerOrder, error) {
	// Try persistent storage first
	if s.storage != nil {
		order, err := s.storage.GetOrder(orderID)
		if err == nil {
			return order, nil
		}
		s.logger.Debug("Order not found in persistent storage, checking memory", "order_id", orderID)
	}
	
	// Fallback to memory storage
	s.ordersMu.RLock()
	order, exists := s.orders[orderID]
	s.ordersMu.RUnlock()
	
	if !exists {
		return nil, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Order not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Order %s not found", orderID),
		}
	}
	
	return order, nil
}

// generateKeyAuthorization generates the key authorization for a challenge
func (s *Server) generateKeyAuthorization(token string, jwk *JSONWebKey) (string, error) {
	// Convert our JSONWebKey to jose.JSONWebKey
	joseJWK, err := s.convertToJoseJWK(jwk)
	if err != nil {
		return "", fmt.Errorf("failed to convert JWK: %w", err)
	}
	
	// Create JWK thumbprint
	thumbprint, err := joseJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to generate JWK thumbprint: %w", err)
	}
	
	// Encode thumbprint as base64url
	thumbprintB64 := base64.RawURLEncoding.EncodeToString(thumbprint)
	
	// Create key authorization: token + "." + base64url(JWK_thumbprint)
	keyAuth := token + "." + thumbprintB64
	
	return keyAuth, nil
}

// convertToJoseJWK converts our JSONWebKey to jose.JSONWebKey
func (s *Server) convertToJoseJWK(jwk *JSONWebKey) (*jose.JSONWebKey, error) {
	s.logger.Debug("Converting JWK", "kty", jwk.Kty, "alg", jwk.Alg, "use", jwk.Use)
	
	// Check if JWK has required fields
	if jwk.Kty == "" {
		return nil, fmt.Errorf("JWK missing key type (kty)")
	}
	
	// Convert to JSON and back to jose.JSONWebKey
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}
	
	s.logger.Debug("JWK JSON", "json", string(jwkBytes))
	
	var joseJWK jose.JSONWebKey
	if err := json.Unmarshal(jwkBytes, &joseJWK); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to jose.JSONWebKey: %w", err)
	}
	
	return &joseJWK, nil
}

// updateChallengeInStorage updates a challenge in both persistent and memory storage
func (s *Server) updateChallengeInStorage(challenge *ServerChallenge) {
	// Update in persistent storage
	if s.storage != nil {
		if err := s.storage.StoreChallenge(challenge.ID, challenge); err != nil {
			s.logger.Error("Failed to update challenge in persistent storage", "error", err, "challenge_id", challenge.ID)
		}
	}
	
	// Update in memory storage
	s.challengesMu.Lock()
	s.challenges[challenge.ID] = challenge
	s.challengesMu.Unlock()
}

// validateChallenge performs the actual challenge validation
func (s *Server) validateChallenge(challenge *ServerChallenge, authz *ServerAuthorization) {
	s.logger.Info("Starting challenge validation", "challenge_id", challenge.ID, "type", challenge.Type, "domain", authz.Identifier.Value)
	
	// Update challenge status to processing at the start of validation
	challenge.Status = StatusProcessing
	challenge.UpdatedAt = time.Now()
	s.updateChallengeInStorage(challenge)
	
	var validationErr error
	
	switch challenge.Type {
	case ChallengeTypeHTTP01:
		validationErr = s.validateHTTP01Challenge(challenge, authz)
	case ChallengeTypeDNS01:
		validationErr = s.validateDNS01Challenge(challenge, authz)
	case ChallengeTypeTLSALPN01:
		validationErr = s.validateTLSALPN01Challenge(challenge, authz)
	default:
		validationErr = fmt.Errorf("unsupported challenge type: %s", challenge.Type)
	}
	
	// Update challenge status based on validation result
	now := time.Now()
	if validationErr != nil {
		s.logger.Error("Challenge validation failed", "challenge_id", challenge.ID, "error", validationErr)
		challenge.Status = StatusInvalid
		challenge.Error = &ProblemDetails{
			Type:   ErrorTypeIncorrectResponse,
			Title:  "Challenge validation failed",
			Status: http.StatusBadRequest,
			Detail: validationErr.Error(),
		}
	} else {
		s.logger.Info("Challenge validation succeeded", "challenge_id", challenge.ID)
		challenge.Status = StatusValid
		challenge.Validated = &now
		challenge.Error = nil
	}
	
	challenge.UpdatedAt = now
	s.updateChallengeInStorage(challenge)
	
	// Update the challenge in the authorization object
	for i, authzChallenge := range authz.Challenges {
		if authzChallenge.Type == challenge.Type && authzChallenge.Token == challenge.Token {
			// Update the challenge in the authorization
			authz.Challenges[i].Status = challenge.Status
			authz.Challenges[i].Validated = challenge.Validated
			authz.Challenges[i].Error = challenge.Error
			break
		}
	}
	
	// Update authorization status after challenge status is updated
	if challenge.Status == StatusValid {
		s.updateAuthorizationStatus(authz)
	}
}

// validateHTTP01Challenge validates an HTTP-01 challenge with retry and exponential backoff
func (s *Server) validateHTTP01Challenge(challenge *ServerChallenge, authz *ServerAuthorization) error {
	domain := authz.Identifier.Value
	token := challenge.Token
	expectedKeyAuth := challenge.KeyAuthorization
	
	// Construct the validation URL
	validationURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, token)
	
	s.logger.Debug("Validating HTTP-01 challenge", 
		"url", validationURL, 
		"expected", expectedKeyAuth,
		"domain", domain,
		"token", token)
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	
	// Retry configuration
	maxRetries := 5
	baseDelay := 1 * time.Second
	maxDelay := 30 * time.Second
	initialDelay := 5 * time.Second // Increased delay to give ACME client more time
	
	// Wait before first attempt to give the ACME client time to set up the challenge response
	s.logger.Debug("Waiting before HTTP-01 challenge validation", "initial_delay", initialDelay, "url", validationURL)
	time.Sleep(initialDelay)
	
	var lastErr error
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Calculate exponential backoff delay
			delay := time.Duration(float64(baseDelay) * math.Pow(2, float64(attempt-1)))
			if delay > maxDelay {
				delay = maxDelay
			}
			
			s.logger.Debug("Retrying HTTP-01 challenge validation", 
				"attempt", attempt+1, 
				"max_retries", maxRetries, 
				"delay", delay,
				"url", validationURL)
			
			time.Sleep(delay)
		}
		
		// Make HTTP request
		s.logger.Debug("Making HTTP-01 challenge request", 
			"attempt", attempt+1, 
			"url", validationURL)
		
		resp, err := client.Get(validationURL)
		if err != nil {
			lastErr = fmt.Errorf("failed to fetch challenge response (attempt %d/%d): %w", attempt+1, maxRetries, err)
			s.logger.Debug("HTTP-01 challenge request failed", 
				"attempt", attempt+1, 
				"error", err,
				"url", validationURL)
			continue
		}
		
		func() {
			defer resp.Body.Close()
			
			if resp.StatusCode != http.StatusOK {
				// Read response body for debugging
				body, _ := io.ReadAll(resp.Body)
				bodyStr := strings.TrimSpace(string(body))
				if len(bodyStr) > 200 {
					bodyStr = bodyStr[:200] + "..."
				}
				
				lastErr = fmt.Errorf("challenge response returned status %d (attempt %d/%d)", resp.StatusCode, attempt+1, maxRetries)
				s.logger.Debug("HTTP-01 challenge returned non-200 status", 
					"attempt", attempt+1, 
					"status", resp.StatusCode,
					"response_body", bodyStr,
					"content_type", resp.Header.Get("Content-Type"),
					"url", validationURL)
				return
			}
			
			// Read response body
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				lastErr = fmt.Errorf("failed to read challenge response (attempt %d/%d): %w", attempt+1, maxRetries, err)
				s.logger.Debug("HTTP-01 challenge response read failed", "attempt", attempt+1, "error", err)
				return
			}
			
			// Trim whitespace and compare
			actualKeyAuth := strings.TrimSpace(string(body))
			if actualKeyAuth != expectedKeyAuth {
				lastErr = fmt.Errorf("key authorization mismatch (attempt %d/%d): expected %s, got %s", attempt+1, maxRetries, expectedKeyAuth, actualKeyAuth)
				s.logger.Debug("HTTP-01 challenge key authorization mismatch", 
					"attempt", attempt+1,
					"expected", expectedKeyAuth,
					"actual", actualKeyAuth)
				return
			}
			
			// Success!
			s.logger.Debug("HTTP-01 challenge validation successful", 
				"attempt", attempt+1,
				"url", validationURL)
			lastErr = nil
		}()
		
		// If no error, validation succeeded
		if lastErr == nil {
			return nil
		}
	}
	
	// All retries failed
	return fmt.Errorf("HTTP-01 challenge validation failed after %d attempts: %w", maxRetries, lastErr)
}

// validateDNS01Challenge validates a DNS-01 challenge
func (s *Server) validateDNS01Challenge(challenge *ServerChallenge, authz *ServerAuthorization) error {
	domain := authz.Identifier.Value
	expectedKeyAuth := challenge.KeyAuthorization
	
	// Calculate expected DNS record value
	// DNS-01 uses SHA256 hash of key authorization
	hash := crypto.SHA256.New()
	hash.Write([]byte(expectedKeyAuth))
	expectedValue := base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
	
	// DNS record name: _acme-challenge.{domain}
	recordName := "_acme-challenge." + domain
	
	s.logger.Debug("Validating DNS-01 challenge", "domain", domain, "record", recordName, "expected", expectedValue)
	
	// Query DNS TXT record
	txtRecords, err := s.queryDNSTXTRecords(recordName)
	if err != nil {
		return fmt.Errorf("failed to query DNS TXT records for %s: %w", recordName, err)
	}
	
	// Check if any TXT record matches expected value
	for _, record := range txtRecords {
		if record == expectedValue {
			s.logger.Info("DNS-01 challenge validation successful", "domain", domain, "record", recordName)
			return nil
		}
	}
	
	return fmt.Errorf("DNS TXT record not found or incorrect: expected %s in %s", expectedValue, recordName)
}

// validateTLSALPN01Challenge validates a TLS-ALPN-01 challenge
func (s *Server) validateTLSALPN01Challenge(challenge *ServerChallenge, authz *ServerAuthorization) error {
	domain := authz.Identifier.Value
	expectedKeyAuth := challenge.KeyAuthorization
	
	s.logger.Debug("Validating TLS-ALPN-01 challenge", "domain", domain, "expected", expectedKeyAuth)
	
	// Calculate expected certificate extension value
	hash := crypto.SHA256.New()
	hash.Write([]byte(expectedKeyAuth))
	expectedExtValue := hash.Sum(nil)
	
	s.logger.Debug("Expected extension value", "domain", domain, "value", fmt.Sprintf("%x", expectedExtValue))
	
	// Connect to domain on port 443 with ALPN extension
	conn, err := s.connectTLSALPN(domain, "acme-tls/1")
	if err != nil {
		return fmt.Errorf("failed to establish TLS-ALPN connection to %s: %w", domain, err)
	}
	defer conn.Close()
	
	// Get peer certificate
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates received")
	}
	
	cert := state.PeerCertificates[0]
	
	s.logger.Debug("Certificate details", "domain", domain, "subject", cert.Subject.String(), "extensions_count", len(cert.Extensions))
	
	// Check for ACME extension (1.3.6.1.5.5.7.1.31)
	acmeExtOID := []int{1, 3, 6, 1, 5, 5, 7, 1, 31}
	var foundExtValue []byte
	
	for i, ext := range cert.Extensions {
		s.logger.Debug("Certificate extension", "domain", domain, "index", i, "oid", ext.Id.String(), "critical", ext.Critical, "value_hex", fmt.Sprintf("%x", ext.Value))
		if ext.Id.Equal(acmeExtOID) {
			foundExtValue = ext.Value
			break
		}
	}
	
	if foundExtValue == nil {
		return fmt.Errorf("ACME extension not found in certificate")
	}
	
	s.logger.Debug("Found extension value", "domain", domain, "value", fmt.Sprintf("%x", foundExtValue))
	
	// The extension value might be ASN.1 encoded as OCTET STRING
	// Try to decode it if it starts with 0x04 (OCTET STRING tag)
	actualExtValue := foundExtValue
	if len(foundExtValue) > 2 && foundExtValue[0] == 0x04 {
		// This is an ASN.1 OCTET STRING, extract the actual value
		length := int(foundExtValue[1])
		if len(foundExtValue) >= 2+length {
			actualExtValue = foundExtValue[2 : 2+length]
			s.logger.Debug("Decoded ASN.1 OCTET STRING", "domain", domain, "decoded_value", fmt.Sprintf("%x", actualExtValue))
		}
	}
	
	// Compare extension value
	if !bytes.Equal(actualExtValue, expectedExtValue) {
		s.logger.Error("Extension value mismatch", "domain", domain, "expected", fmt.Sprintf("%x", expectedExtValue), "found", fmt.Sprintf("%x", actualExtValue))
		return fmt.Errorf("ACME extension value mismatch")
	}
	
	s.logger.Info("TLS-ALPN-01 challenge validation successful", "domain", domain)
	return nil
}

// updateAuthorizationStatus updates the authorization status based on challenge results
func (s *Server) updateAuthorizationStatus(authz *ServerAuthorization) {
	s.logger.Info("Updating authorization status", "authz_id", authz.ID, "current_status", authz.Status)
	
	allValid := true
	anyValid := false
	
	for i, challenge := range authz.Challenges {
		s.logger.Info("Challenge status check", "authz_id", authz.ID, "challenge_index", i, "challenge_type", challenge.Type, "status", challenge.Status)
		if challenge.Status == StatusValid {
			anyValid = true
		} else if challenge.Status != StatusInvalid {
			allValid = false
		}
	}
	
	s.logger.Info("Authorization status calculation", "authz_id", authz.ID, "all_valid", allValid, "any_valid", anyValid)
	
	var newStatus string
	if anyValid {
		// In ACME, if any challenge is valid, the authorization is valid
		newStatus = StatusValid
	} else if !anyValid {
		// Check if any challenges are still pending
		anyPending := false
		for _, challenge := range authz.Challenges {
			if challenge.Status == StatusPending || challenge.Status == StatusProcessing {
				anyPending = true
				break
			}
		}
		if !anyPending {
			newStatus = StatusInvalid
		} else {
			newStatus = StatusPending
		}
	} else {
		newStatus = StatusPending
	}
	
	s.logger.Info("Authorization status decision", "authz_id", authz.ID, "old_status", authz.Status, "new_status", newStatus)
	
	if newStatus != authz.Status {
		s.logger.Info("Updating authorization status", "authz_id", authz.ID, "old_status", authz.Status, "new_status", newStatus)
		authz.Status = newStatus
		authz.UpdatedAt = time.Now()
		
		// Update in persistent storage
		if s.storage != nil {
			if err := s.storage.StoreAuthorization(authz.ID, authz); err != nil {
				s.logger.Error("Failed to update authorization in persistent storage", "error", err, "authz_id", authz.ID)
			}
		}
		
		// Update in memory storage
		s.authorizationsMu.Lock()
		s.authorizations[authz.ID] = authz
		s.authorizationsMu.Unlock()
		
		// Check if we need to update the order status
		s.updateOrderStatusForAuthorization(authz)
	} else {
		s.logger.Info("Authorization status unchanged", "authz_id", authz.ID, "status", authz.Status)
	}
}

// updateOrderStatusForAuthorization updates the order status when an authorization changes
func (s *Server) updateOrderStatusForAuthorization(authz *ServerAuthorization) {
	s.logger.Debug("Updating order status for authorization", "authz_id", authz.ID, "order_id", authz.OrderID, "authz_status", authz.Status)
	
	order, err := s.getOrderForAuthorization(authz.OrderID)
	if err != nil {
		s.logger.Error("Failed to get order for authorization update", "error", err, "authz_id", authz.ID)
		return
	}
	
	s.logger.Debug("Current order status", "order_id", order.ID, "status", order.Status, "authorizations_count", len(order.Authorizations))
	
	// Check if all authorizations for this order are valid
	allAuthzValid := true
	validCount := 0
	for _, authzURL := range order.Authorizations {
		// Extract authz ID from URL
		parts := strings.Split(authzURL, "/")
		if len(parts) == 0 {
			continue
		}
		authzID := parts[len(parts)-1]
		
		authzForOrder, err := s.getAuthorizationForChallenge(authzID)
		if err != nil {
			s.logger.Debug("Failed to get authorization for order check", "authz_id", authzID, "error", err)
			allAuthzValid = false
			break
		}
		
		s.logger.Debug("Authorization status check", "authz_id", authzID, "status", authzForOrder.Status)
		
		if authzForOrder.Status != StatusValid {
			allAuthzValid = false
		} else {
			validCount++
		}
	}
	
	s.logger.Debug("Authorization validation summary", "order_id", order.ID, "all_valid", allAuthzValid, "valid_count", validCount, "total_count", len(order.Authorizations))
	
	if allAuthzValid && order.Status == StatusPending {
		s.logger.Info("All authorizations valid, updating order to ready", "order_id", order.ID)
		order.Status = StatusReady
		order.UpdatedAt = time.Now()
		
		// Update in persistent storage
		if s.storage != nil {
			if err := s.storage.StoreOrder(order.ID, order); err != nil {
				s.logger.Error("Failed to update order in persistent storage", "error", err, "order_id", order.ID)
			} else {
				s.logger.Debug("Order updated in persistent storage", "order_id", order.ID, "status", order.Status)
			}
		}
		
		// Update in memory storage
		s.ordersMu.Lock()
		s.orders[order.ID] = order
		s.ordersMu.Unlock()
		
		s.logger.Info("Order status updated to ready", "order_id", order.ID)
	} else {
		s.logger.Debug("Order status not updated", "order_id", order.ID, "all_valid", allAuthzValid, "current_status", order.Status)
	}
}

// validateCSR validates a Certificate Signing Request against an order
func (s *Server) validateCSR(csr *x509.CertificateRequest, order *ServerOrder) error {
	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return &ProblemDetails{
			Type:   ErrorTypeBadCSR,
			Title:  "Bad CSR",
			Status: http.StatusBadRequest,
			Detail: "CSR signature verification failed",
		}
	}

	// Extract domains from CSR
	var csrDomains []string
	
	// Add Common Name if present
	if csr.Subject.CommonName != "" {
		csrDomains = append(csrDomains, csr.Subject.CommonName)
	}
	
	// Add Subject Alternative Names
	csrDomains = append(csrDomains, csr.DNSNames...)
	
	// Remove duplicates
	domainSet := make(map[string]bool)
	var uniqueDomains []string
	for _, domain := range csrDomains {
		if !domainSet[domain] {
			domainSet[domain] = true
			uniqueDomains = append(uniqueDomains, domain)
		}
	}
	
	// Check that CSR domains match order identifiers
	if len(uniqueDomains) != len(order.Identifiers) {
		return &ProblemDetails{
			Type:   ErrorTypeBadCSR,
			Title:  "Bad CSR",
			Status: http.StatusBadRequest,
			Detail: "CSR domain count does not match order identifiers",
		}
	}
	
	orderDomains := make(map[string]bool)
	for _, identifier := range order.Identifiers {
		orderDomains[identifier.Value] = true
	}
	
	for _, domain := range uniqueDomains {
		if !orderDomains[domain] {
			return &ProblemDetails{
				Type:   ErrorTypeBadCSR,
				Title:  "Bad CSR",
				Status: http.StatusBadRequest,
				Detail: fmt.Sprintf("CSR contains domain %s not in order", domain),
			}
		}
	}
	
	s.logger.Debug("CSR validation successful", "domains", uniqueDomains)
	return nil
}

// generateCertificate generates a certificate from a CSR
func (s *Server) generateCertificate(csr *x509.CertificateRequest, order *ServerOrder) ([]byte, error) {
	// Use the certificate manager to generate the certificate
	domains := make([]string, len(order.Identifiers))
	for i, identifier := range order.Identifiers {
		domains[i] = identifier.Value
	}
	
	s.logger.Info("Generating certificate", "domains", domains, "order_id", order.ID)
	
	// Generate certificate using the certificate manager (use first domain as primary)
	cert, err := s.certManager.GenerateCertificate(domains[0])
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}
	
	// Get certificate chain in PEM format
	certPEM, err := s.certManager.GetCertificateChain(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate chain: %w", err)
	}
	
	s.logger.Info("Certificate generated successfully", "order_id", order.ID, "primary_domain", domains[0])
	return certPEM, nil
}

// storeCertificate stores a certificate in both persistent and memory storage
func (s *Server) storeCertificate(certID string, certBytes []byte) error {
	// Store in persistent storage
	if s.storage != nil {
		if err := s.storage.StoreCertificate(certID, certBytes); err != nil {
			s.logger.Error("Failed to store certificate in persistent storage", "error", err, "cert_id", certID)
			return err
		}
		s.logger.Debug("Certificate stored in persistent storage", "cert_id", certID)
	}
	
	// Store in memory storage
	s.certificatesMu.Lock()
	s.certificates[certID] = certBytes
	s.certificatesMu.Unlock()
	
	s.logger.Debug("Certificate stored in memory", "cert_id", certID, "size", len(certBytes))
	return nil
}

// queryDNSTXTRecords queries DNS TXT records for a given name
func (s *Server) queryDNSTXTRecords(name string) ([]string, error) {
	// Use net package for DNS lookup
	txtRecords, err := net.LookupTXT(name)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}
	
	s.logger.Debug("DNS TXT records found", "name", name, "records", txtRecords)
	return txtRecords, nil
}

// connectTLSALPN establishes a TLS connection with ALPN extension
func (s *Server) connectTLSALPN(domain, alpnProto string) (*tls.Conn, error) {
	config := &tls.Config{
		NextProtos:         []string{alpnProto},
		InsecureSkipVerify: true, // For development/testing
		ServerName:         domain,
	}
	
	// Connect to domain:443
	conn, err := tls.Dial("tcp", domain+":443", config)
	if err != nil {
		return nil, fmt.Errorf("TLS dial failed: %w", err)
	}
	
	// Verify ALPN negotiation
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != alpnProto {
		conn.Close()
		return nil, fmt.Errorf("ALPN negotiation failed: expected %s, got %s", alpnProto, state.NegotiatedProtocol)
	}
	
	return conn, nil
}

// Start starts the ACME server and renewal manager
func (s *Server) Start() error {
	s.logger.Info("Starting ACME server", "base_url", s.baseURL)
	
	// Start renewal manager
	if err := s.renewalManager.Start(); err != nil {
		return fmt.Errorf("failed to start renewal manager: %w", err)
	}
	
	s.logger.Info("ACME server started successfully")
	return nil
}

// Stop stops the ACME server and renewal manager
func (s *Server) Stop() error {
	s.logger.Info("Stopping ACME server")
	
	// Stop renewal manager
	if err := s.renewalManager.Stop(); err != nil {
		s.logger.Error("Failed to stop renewal manager", "error", err)
		// Continue with shutdown
	}
	
	s.logger.Info("ACME server stopped")
	return nil
}

// GetRenewalStats returns renewal statistics
func (s *Server) GetRenewalStats() certmanager.RenewalStats {
	return s.renewalManager.GetRenewalStats()
}

// GetRenewalQueue returns current renewal queue
func (s *Server) GetRenewalQueue() map[string]certmanager.RenewalTask {
	return s.renewalManager.GetRenewalQueue()
}

// ForceRenewal forces renewal of a specific domain
func (s *Server) ForceRenewal(domain string) error {
	return s.renewalManager.ForceRenewal(domain)
}

// GetAccount retrieves an account by ID
func (s *Server) GetAccount(accountID string) (*Account, error) {
	// Try persistent storage first
	if s.storage != nil {
		serverAccount, err := s.storage.GetAccount(accountID)
		if err == nil && serverAccount != nil {
			s.logger.Debug("Account retrieved from persistent storage", "account_id", accountID)
			
			// Also update memory cache for performance
			s.accountsMu.Lock()
			s.accounts[accountID] = serverAccount
			s.accountsMu.Unlock()
			
			return &serverAccount.Account, nil
		}
		s.logger.Debug("Account not found in persistent storage", "account_id", accountID, "error", err)
	}
	
	// Fallback to memory storage
	s.accountsMu.RLock()
	serverAccount, exists := s.accounts[accountID]
	s.accountsMu.RUnlock()
	
	if !exists {
		return nil, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Account does not exist",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Account with ID %s does not exist", accountID),
		}
	}
	
	return &serverAccount.Account, nil
}

// CreateOrder creates a new certificate order
func (s *Server) CreateOrder(accountID string, req *OrderRequest) (*Order, error) {
	// Validate account exists
	_, err := s.GetAccount(accountID)
	if err != nil {
		return nil, err
	}
	
	// Validate identifiers
	for _, identifier := range req.Identifiers {
		if identifier.Type != "dns" {
			return nil, &ProblemDetails{
				Type:   ErrorTypeUnsupportedIdentifier,
				Title:  "Unsupported identifier type",
				Status: http.StatusBadRequest,
				Detail: fmt.Sprintf("Identifier type %s is not supported", identifier.Type),
			}
		}
		
		// Check if domain is allowed
		if !s.certManager.IsAllowedDomain(identifier.Value) {
			return nil, &ProblemDetails{
				Type:   ErrorTypeRejectedIdentifier,
				Title:  "Rejected identifier",
				Status: http.StatusBadRequest,
				Detail: fmt.Sprintf("Domain %s is not allowed", identifier.Value),
			}
		}
	}
	
	// Generate order ID
	orderID, err := s.generateID("order")
	if err != nil {
		return nil, fmt.Errorf("failed to generate order ID: %w", err)
	}
	
	// Create authorizations for each identifier
	var authzURLs []string
	for _, identifier := range req.Identifiers {
		authzID, err := s.generateID("authz")
		if err != nil {
			return nil, fmt.Errorf("failed to generate authorization ID: %w", err)
		}
		
		authz := &ServerAuthorization{
			Authorization: Authorization{
				ID:         authzID,
				Identifier: identifier,
				Status:     StatusPending,
				Expires:    time.Now().Add(24 * time.Hour),
				Challenges: []Challenge{},
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			},
			OrderID: orderID,
		}
		
		// Create challenges for this authorization
		// Temporarily only enable HTTP-01 for debugging
		challengeTypes := []string{ChallengeTypeHTTP01}
		var challenges []Challenge
		
		for _, challengeType := range challengeTypes {
			challengeID, err := s.generateID("chall")
			if err != nil {
				return nil, fmt.Errorf("failed to generate challenge ID: %w", err)
			}
			
			token, err := s.generateToken()
			if err != nil {
				return nil, fmt.Errorf("failed to generate challenge token: %w", err)
			}
			
			// Create RFC 8555 compliant challenge object (for client response)
			challenge := Challenge{
				Type:   challengeType,
				URL:    fmt.Sprintf("%s/acme/chall/%s", s.baseURL, challengeID),
				Status: StatusPending,
				Token:  token,
			}
			
			challenges = append(challenges, challenge)
			
			// Create server challenge with additional internal fields
			serverChallenge := &ServerChallenge{
				Challenge: challenge,
				ID:        challengeID,
				AuthzID:   authzID,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			
			if s.storage != nil {
				if err := s.storage.StoreChallenge(challengeID, serverChallenge); err != nil {
					s.logger.Error("Failed to store challenge in persistent storage", "error", err, "challenge_id", challengeID)
				} else {
					s.logger.Debug("Challenge stored in persistent storage", "challenge_id", challengeID, "type", challengeType)
				}
			}
			
			// Store challenge in memory for backward compatibility
			s.challengesMu.Lock()
			s.challenges[challengeID] = serverChallenge
			s.challengesMu.Unlock()
		}
		
		authz.Challenges = challenges
		
		// Store authorization in persistent storage first
		if s.storage != nil {
			if err := s.storage.StoreAuthorization(authzID, authz); err != nil {
				s.logger.Error("Failed to store authorization in persistent storage", "error", err, "authz_id", authzID)
			} else {
				s.logger.Debug("Authorization stored in persistent storage", "authz_id", authzID)
			}
		}
		
		// Store authorization in memory for backward compatibility
		s.authorizationsMu.Lock()
		s.authorizations[authzID] = authz
		s.authorizationsMu.Unlock()
		
		authzURLs = append(authzURLs, fmt.Sprintf("%s/acme/authz/%s", s.baseURL, authzID))
	}
	
	// Create order
	order := &Order{
		ID:             orderID,
		AccountID:      accountID,
		Status:         StatusPending,
		Expires:        time.Now().Add(24 * time.Hour),
		Identifiers:    req.Identifiers,
		NotBefore:      req.NotBefore,
		NotAfter:       req.NotAfter,
		Authorizations: authzURLs,
		Finalize:       fmt.Sprintf("%s/acme/order/%s/finalize", s.baseURL, orderID),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	
	s.logger.Info("Order finalize URL", "order_id", orderID, "finalize_url", order.Finalize, "base_url", s.baseURL)
	
	serverOrder := &ServerOrder{
		Order: *order,
	}
	
	// Store in persistent storage first
	if s.storage != nil {
		if err := s.storage.StoreOrder(orderID, serverOrder); err != nil {
			s.logger.Error("Failed to store order in persistent storage", "error", err, "order_id", orderID)
		} else {
			s.logger.Debug("Order stored in persistent storage", "order_id", orderID)
		}
	}
	
	// Also store in memory for backward compatibility
	s.ordersMu.Lock()
	s.orders[orderID] = serverOrder
	s.ordersMu.Unlock()
	
	s.logger.Info("Created new certificate order", "orderId", orderID, "accountId", accountID, "identifiers", req.Identifiers)
	
	return order, nil
}

// GetOrder retrieves an order by ID
func (s *Server) GetOrder(orderID string) (*Order, error) {
	s.logger.Debug("GetOrder called", "orderID", orderID)
	
	// Try persistent storage first
	if s.storage != nil {
		s.logger.Debug("Checking persistent storage for order", "orderID", orderID)
		serverOrder, err := s.storage.GetOrder(orderID)
		if err == nil {
			s.logger.Info("Order found in persistent storage", "orderID", orderID, "status", serverOrder.Status, "finalize_url", serverOrder.Finalize)
			return &serverOrder.Order, nil
		}
		s.logger.Debug("Order not found in persistent storage, checking memory", "orderID", orderID, "error", err)
	}
	
	// Fallback to memory storage
	s.logger.Debug("Checking memory storage for order", "orderID", orderID)
	s.ordersMu.RLock()
	serverOrder, exists := s.orders[orderID]
	s.ordersMu.RUnlock()
	
	if !exists {
		s.logger.Debug("Order not found in memory storage", "orderID", orderID)
		return nil, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Order not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Order with ID %s does not exist", orderID),
		}
	}
	
	s.logger.Info("Order found in memory storage", "orderID", orderID, "status", serverOrder.Status, "finalize_url", serverOrder.Finalize)
	return &serverOrder.Order, nil
}

// generateID generates a random ID with the given prefix
func (s *Server) generateID(prefix string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Use base64 URL encoding without padding for consistency
	return fmt.Sprintf("%s_%s", prefix, base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)), nil
}

// generateToken generates a random token for challenges (RFC 8555 compliant)
func (s *Server) generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Use base64 URL encoding without padding (RFC 8555 requirement)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes), nil
}

// startNonceCleanup starts a routine to periodically clean up expired nonces
func (s *Server) startNonceCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredNonces()
		}
	}
}

// Shutdown gracefully shuts down the ACME server
func (s *Server) Shutdown() error {
	s.logger.Info("Shutting down ACME server")
	
	// Close persistent storage
	if s.storage != nil {
		if err := s.storage.Close(); err != nil {
			s.logger.Error("Error closing persistent storage", "error", err)
		}
	}
	
	return nil
}
