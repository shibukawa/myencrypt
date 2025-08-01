package acme

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/shibukawayoshiki/myencrypt2/internal/certmanager"
	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// Server represents the ACME server
// Server represents the ACME server
type Server struct {
	config      *config.Config
	certManager certmanager.Manager
	logger      *logger.Logger
	baseURL     string
	storage     Storage
	
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
		baseURL = fmt.Sprintf("http://localhost:%d", cfg.HTTPPort)
	}
	
	// Initialize SQLite storage
	var storage Storage
	sqliteStorage, err := NewSQLiteStorage(cfg, log)
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
	
	return &Server{
		config:         cfg,
		certManager:    certMgr,
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

// GetAccount retrieves an account by ID
func (s *Server) GetAccount(accountID string) (*Account, error) {
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
		
		// Create HTTP-01 challenge
		challengeID, err := s.generateID("chall")
		if err != nil {
			return nil, fmt.Errorf("failed to generate challenge ID: %w", err)
		}
		
		token, err := s.generateToken()
		if err != nil {
			return nil, fmt.Errorf("failed to generate challenge token: %w", err)
		}
		
		challenge := Challenge{
			ID:        challengeID,
			Type:      ChallengeTypeHTTP01,
			URL:       fmt.Sprintf("%s/acme/challenge/%s", s.baseURL, challengeID),
			Status:    StatusPending,
			Token:     token,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		
		authz.Challenges = append(authz.Challenges, challenge)
		
		// Store authorization and challenge
		s.authorizationsMu.Lock()
		s.authorizations[authzID] = authz
		s.authorizationsMu.Unlock()
		
		s.challengesMu.Lock()
		s.challenges[challengeID] = &ServerChallenge{
			Challenge: challenge,
			AuthzID:   authzID,
		}
		s.challengesMu.Unlock()
		
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
	s.ordersMu.RLock()
	serverOrder, exists := s.orders[orderID]
	s.ordersMu.RUnlock()
	
	if !exists {
		return nil, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Order not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Order with ID %s does not exist", orderID),
		}
	}
	
	return &serverOrder.Order, nil
}

// generateID generates a random ID with the given prefix
func (s *Server) generateID(prefix string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s_%s", prefix, base64.URLEncoding.EncodeToString(bytes)), nil
}

// generateToken generates a random token for challenges
func (s *Server) generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Start starts the ACME server
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting ACME server", "port", s.config.HTTPPort, "baseURL", s.baseURL)
	
	// Start nonce cleanup routine
	go s.startNonceCleanup(ctx)
	
	return nil
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
