package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// RegisterHandlers registers ACME HTTP handlers with the router
func (s *Server) RegisterHandlers(router *mux.Router) {
	// ACME endpoints
	acmeRouter := router.PathPrefix("/acme").Subrouter()

	// Directory endpoint (RFC 8555 Section 7.1.1)
	acmeRouter.HandleFunc("/directory", s.handleDirectory).Methods("GET", "HEAD")

	// Nonce endpoint (RFC 8555 Section 7.2)
	acmeRouter.HandleFunc("/new-nonce", s.handleNewNonce).Methods("HEAD", "GET")

	// Account management (RFC 8555 Section 7.3)
	acmeRouter.HandleFunc("/new-account", s.handleNewAccount).Methods("POST")
	acmeRouter.HandleFunc("/account/{accountId}", s.handleAccount).Methods("POST")

	// Order management (RFC 8555 Section 7.4)
	acmeRouter.HandleFunc("/new-order", s.handleNewOrder).Methods("POST")
	acmeRouter.HandleFunc("/order/{orderId}", s.handleOrder).Methods("POST", "GET")
	acmeRouter.HandleFunc("/order/{orderId}/finalize", s.handleFinalize).Methods("POST")

	// Authorization and challenge endpoints (RFC 8555 Section 7.5)
	acmeRouter.HandleFunc("/authz/{authzId}", s.handleAuthorization).Methods("POST", "GET")
	acmeRouter.HandleFunc("/chall/{challengeId}", s.handleChallenge).Methods("POST", "GET")

	// Certificate endpoint (RFC 8555 Section 7.4.2)
	acmeRouter.HandleFunc("/cert/{certId}", s.handleCertificate).Methods("POST", "GET")

	// Key change endpoint (RFC 8555 Section 7.3.5)
	acmeRouter.HandleFunc("/key-change", s.handleKeyChange).Methods("POST")

	// Certificate revocation (RFC 8555 Section 7.6)
	acmeRouter.HandleFunc("/revoke-cert", s.handleRevokeCert).Methods("POST")
}

// handleDirectory handles the ACME directory endpoint
func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling directory request", "method", r.Method, "url", r.URL.String())

	directory := s.GetDirectory()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Add Link header for ACME directory (RFC 8555 Section 7.1.1)
	// The "up" link points to the directory itself as per ACME specification
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/directory>;rel=\"index\"", s.baseURL))

	// Add CORS headers for development
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if err := json.NewEncoder(w).Encode(directory); err != nil {
		s.logger.Error("Failed to encode directory response", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to encode directory response",
		})
		return
	}

	s.logger.Debug("Directory response sent successfully")
}

// handleNewNonce handles nonce generation requests
func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling new nonce request", "method", r.Method)

	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate nonce", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to generate nonce",
		})
		return
	}

	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")

	// Add CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Replay-Nonce")

	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
	}

	s.logger.Debug("Nonce generated successfully", "nonce", nonce)
}

// handleNewAccount handles new account creation
func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling new account request")

	// Parse JWS request
	jws, err := s.parseJWSRequest(r)
	if err != nil {
		s.logger.Error("Failed to parse JWS request", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	// Parse account request
	var accountReq AccountRequest
	if err := json.Unmarshal([]byte(jws.Payload), &accountReq); err != nil {
		s.logger.Error("Failed to parse account request", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Invalid account request format",
		})
		return
	}

	// Extract JWK from JWS header
	header, err := s.parseJWSHeader(jws.Protected)
	if err != nil {
		s.logger.Error("Failed to parse JWS header", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	if header.JWK == nil {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "JWK is required for new account requests",
		})
		return
	}

	// Create account
	account, err := s.CreateAccount(&accountReq, header.JWK)
	if err != nil {
		s.logger.Error("Failed to create account", "error", err)
		if problemDetails, ok := err.(*ProblemDetails); ok {
			s.writeError(w, problemDetails)
		} else {
			s.writeError(w, &ProblemDetails{
				Type:   ErrorTypeServerInternal,
				Title:  "Internal server error",
				Status: http.StatusInternalServerError,
				Detail: "Failed to create account",
			})
		}
		return
	}

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", fmt.Sprintf("%s/acme/account/%s", s.baseURL, account.ID))
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(account); err != nil {
		s.logger.Error("Failed to encode account response", "error", err)
		return
	}

	s.logger.Info("Account created successfully", "accountId", account.ID)
}

// handleAccount handles account operations
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	accountID := vars["accountId"]

	s.logger.Debug("Handling account request", "accountId", accountID, "method", r.Method)

	if r.Method == "GET" {
		account, err := s.GetAccount(accountID)
		if err != nil {
			if problemDetails, ok := err.(*ProblemDetails); ok {
				s.writeError(w, problemDetails)
			} else {
				s.writeError(w, &ProblemDetails{
					Type:   ErrorTypeServerInternal,
					Title:  "Internal server error",
					Status: http.StatusInternalServerError,
					Detail: "Failed to retrieve account",
				})
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(account)
		return
	}

	// POST method for account updates would be implemented here
	s.writeError(w, &ProblemDetails{
		Type:   ErrorTypeServerInternal,
		Title:  "Not implemented",
		Status: http.StatusNotImplemented,
		Detail: "Account updates are not yet implemented",
	})
}

// handleNewOrder handles new order creation
func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling new order request")

	// Parse JWS request
	jws, err := s.parseJWSRequest(r)
	if err != nil {
		s.logger.Error("Failed to parse JWS request", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	// Extract account ID from JWS header
	header, err := s.parseJWSHeader(jws.Protected)
	if err != nil {
		s.logger.Error("Failed to parse JWS header", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	// For simplicity, we'll extract account ID from the kid field
	// In a real implementation, this would be more sophisticated
	accountID := s.extractAccountIDFromKid(header.Kid)
	if accountID == "" {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeUnauthorized,
			Title:  "Unauthorized",
			Status: http.StatusUnauthorized,
			Detail: "Invalid or missing account identifier",
		})
		return
	}

	// Parse order request
	var orderReq OrderRequest
	if err := json.Unmarshal([]byte(jws.Payload), &orderReq); err != nil {
		s.logger.Error("Failed to parse order request", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Invalid order request format",
		})
		return
	}

	// Create order
	order, err := s.CreateOrder(accountID, &orderReq)
	if err != nil {
		s.logger.Error("Failed to create order", "error", err)
		if problemDetails, ok := err.(*ProblemDetails); ok {
			s.writeError(w, problemDetails)
		} else {
			s.writeError(w, &ProblemDetails{
				Type:   ErrorTypeServerInternal,
				Title:  "Internal server error",
				Status: http.StatusInternalServerError,
				Detail: "Failed to create order",
			})
		}
		return
	}

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", fmt.Sprintf("%s/acme/order/%s", s.baseURL, order.ID))
	w.WriteHeader(http.StatusCreated)

	if err := json.NewEncoder(w).Encode(order); err != nil {
		s.logger.Error("Failed to encode order response", "error", err)
		return
	}

	s.logger.Info("Order created successfully", "orderId", order.ID, "accountId", accountID)
}

// handleOrder handles order operations
func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["orderId"]

	s.logger.Info("Handling order request", "orderId", orderID, "method", r.Method, "url", r.URL.String())

	// Handle different HTTP methods
	switch r.Method {
	case "GET":
		s.handleOrderGet(w, r, orderID)
	case "POST":
		s.handleOrderPost(w, r, orderID)
	default:
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Method not allowed",
			Status: http.StatusMethodNotAllowed,
			Detail: fmt.Sprintf("Method %s not allowed for order endpoint", r.Method),
		})
	}
}

// handleOrderGet handles GET requests for orders (status polling)
func (s *Server) handleOrderGet(w http.ResponseWriter, r *http.Request, orderID string) {
	s.logger.Info("Handling order GET request", "orderId", orderID)

	order, err := s.GetOrder(orderID)
	if err != nil {
		s.logger.Error("Failed to get order", "orderId", orderID, "error", err)
		if problemDetails, ok := err.(*ProblemDetails); ok {
			s.writeError(w, problemDetails)
		} else {
			s.writeError(w, &ProblemDetails{
				Type:   ErrorTypeServerInternal,
				Title:  "Internal server error",
				Status: http.StatusInternalServerError,
				Detail: "Failed to retrieve order",
			})
		}
		return
	}

	s.logger.Info("Order retrieved successfully", "orderId", orderID, "status", order.Status, "identifiers", len(order.Identifiers))

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(order); err != nil {
		s.logger.Error("Failed to encode order response", "orderId", orderID, "error", err)
		return
	}

	s.logger.Debug("Order response sent successfully", "orderId", orderID)
}

// handleOrderPost handles POST requests for orders (order updates)
func (s *Server) handleOrderPost(w http.ResponseWriter, r *http.Request, orderID string) {
	s.logger.Info("Handling order POST request", "orderId", orderID)

	// For now, POST to order endpoint just returns the current order status
	// In a full ACME implementation, this might handle order updates
	s.handleOrderGet(w, r, orderID)
}

// Placeholder handlers for endpoints not yet implemented

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["orderId"]

	s.logger.Info("Processing finalize request", "order_id", orderID, "method", r.Method, "url", r.URL.String())

	// Parse JWS request
	payload, err := s.parseJWSPayload(r)
	if err != nil {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Invalid JWS",
			Status: http.StatusBadRequest,
			Detail: fmt.Sprintf("Failed to parse JWS: %v", err),
		})
		return
	}

	// Parse CSR from payload
	var finalizeRequest struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &finalizeRequest); err != nil {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Invalid finalize request",
			Status: http.StatusBadRequest,
			Detail: "Failed to parse finalize request body",
		})
		return
	}

	// Decode base64url CSR
	csrBytes, err := base64.RawURLEncoding.DecodeString(finalizeRequest.CSR)
	if err != nil {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Invalid CSR",
			Status: http.StatusBadRequest,
			Detail: "Failed to decode CSR",
		})
		return
	}

	// Parse CSR
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Invalid CSR",
			Status: http.StatusBadRequest,
			Detail: "Failed to parse certificate request",
		})
		return
	}

	// Get the order (try persistent storage first, then fallback to memory)
	var order *ServerOrder
	var exists bool

	if s.storage != nil {
		var storageErr error
		order, storageErr = s.storage.GetOrder(orderID)
		exists = (storageErr == nil)
		if !exists {
			s.logger.Debug("Order not found in persistent storage, checking memory", "order_id", orderID)
		}
	}

	// Fallback to memory storage if persistent storage fails or order not found
	if !exists {
		s.ordersMu.RLock()
		order, exists = s.orders[orderID]
		s.ordersMu.RUnlock()
	}

	if !exists {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeOrderNotFound,
			Title:  "Order not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Order %s not found", orderID),
		})
		return
	}

	// Check if order is ready for finalization
	if order.Status != OrderStatusReady {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeOrderNotReady,
			Title:  "Order not ready",
			Status: http.StatusForbidden,
			Detail: fmt.Sprintf("Order status is %s, expected ready", order.Status),
		})
		return
	}

	// Validate CSR matches order identifiers
	if err := s.validateCSR(csr, order); err != nil {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeBadCSR,
			Title:  "Invalid CSR",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		})
		return
	}

	// Generate certificate for the first domain in the order
	// In a real implementation, you'd handle multiple domains
	var domain string
	if len(order.Identifiers) > 0 {
		domain = order.Identifiers[0].Value
	} else {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "No identifiers",
			Status: http.StatusInternalServerError,
			Detail: "Order has no identifiers",
		})
		return
	}

	// Check if domain is allowed
	if !s.certManager.IsAllowedDomain(domain) {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeUnauthorized,
			Title:  "Domain not allowed",
			Status: http.StatusForbidden,
			Detail: fmt.Sprintf("Domain %s is not in the allowed domains list", domain),
		})
		return
	}

	s.logger.Info("Generating certificate for finalized order", "domain", domain, "order_id", orderID)

	// Generate certificate using CSR from the client
	cert, err := s.certManager.GenerateCertificateFromCSR(csr)
	if err != nil {
		s.logger.Error("Failed to generate certificate from CSR", "error", err, "domain", domain)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Certificate generation failed",
			Status: http.StatusInternalServerError,
			Detail: "Failed to generate certificate",
		})
		return
	}

	// Get certificate chain
	certChain, err := s.certManager.GetCertificateChain(cert)
	if err != nil {
		s.logger.Error("Failed to get certificate chain", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Certificate chain failed",
			Status: http.StatusInternalServerError,
			Detail: "Failed to get certificate chain",
		})
		return
	}

	// Update order status and add certificate URL
	certificateURL := fmt.Sprintf("%s/acme/cert/%s", s.baseURL, orderID)
	s.logger.Info("Setting certificate URL", "order_id", orderID, "certificate_url", certificateURL)

	// Update in persistent storage first
	if s.storage != nil {
		if err := s.storage.UpdateOrderStatus(orderID, OrderStatusValid, certificateURL); err != nil {
			s.logger.Error("Failed to update order status in persistent storage", "error", err, "order_id", orderID)
		}

		// Store certificate in persistent storage
		if err := s.storage.StoreCertificate(orderID, certChain); err != nil {
			s.logger.Error("Failed to store certificate in persistent storage", "error", err, "order_id", orderID)
		}
	}

	// Update in memory storage as fallback
	s.ordersMu.Lock()
	if memOrder, exists := s.orders[orderID]; exists {
		memOrder.Status = OrderStatusValid
		memOrder.Certificate = certificateURL
	}
	s.ordersMu.Unlock()

	// Store certificate in memory storage as fallback
	s.certificatesMu.Lock()
	s.certificates[orderID] = certChain
	s.certificatesMu.Unlock()

	// Update the order object for response
	order.Status = OrderStatusValid
	order.Certificate = certificateURL

	s.logger.Info("Certificate generated and order finalized",
		"domain", domain,
		"order_id", orderID,
		"cert_serial", cert.Certificate.SerialNumber.String())

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	// Return updated order
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (s *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling authorization request", "method", r.Method)

	// Extract authorization ID from URL
	vars := mux.Vars(r)
	authzID := vars["authzId"]
	if authzID == "" {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Missing authorization ID",
		})
		return
	}

	// Get authorization from storage (try persistent storage first, then fallback to memory)
	var authz *ServerAuthorization
	var exists bool

	if s.storage != nil {
		var storageErr error
		authz, storageErr = s.storage.GetAuthorization(authzID)
		exists = (storageErr == nil)
		if !exists {
			s.logger.Debug("Authorization not found in persistent storage, checking memory", "authz_id", authzID)
		}
	}

	// Fallback to memory storage if persistent storage fails or authorization not found
	if !exists {
		s.authorizationsMu.RLock()
		authz, exists = s.authorizations[authzID]
		s.authorizationsMu.RUnlock()
	}

	if !exists {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Authorization not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Authorization %s not found", authzID),
		})
		return
	}

	// Handle different HTTP methods
	switch r.Method {
	case "GET":
		s.handleGetAuthorization(w, r, authz)
	case "POST":
		s.handlePostAuthorization(w, r, authz)
	default:
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Method not allowed",
			Status: http.StatusMethodNotAllowed,
			Detail: fmt.Sprintf("Method %s not allowed", r.Method),
		})
	}
}

func (s *Server) handleGetAuthorization(w http.ResponseWriter, r *http.Request, authz *ServerAuthorization) {
	s.logger.Debug("Getting authorization", "authz_id", authz.ID)

	// Update challenge URLs to include full URLs
	// The challenges in authz.Challenges already have the correct URLs set during creation
	// No need to modify them here

	// Debug: Log challenge URLs
	for i, challenge := range authz.Challenges {
		s.logger.Debug("Authorization challenge",
			"index", i,
			"type", challenge.Type,
			"url", challenge.URL,
			"status", challenge.Status,
			"token", challenge.Token)
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	// Return authorization
	if err := json.NewEncoder(w).Encode(authz.Authorization); err != nil {
		s.logger.Error("Failed to encode authorization response", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to encode response",
		})
		return
	}

	s.logger.Debug("Authorization retrieved successfully", "authz_id", authz.ID, "status", authz.Status)
}

func (s *Server) handlePostAuthorization(w http.ResponseWriter, r *http.Request, authz *ServerAuthorization) {
	s.logger.Debug("Updating authorization", "authz_id", authz.ID)

	// Parse JWS request
	jws, err := s.parseJWSRequest(r)
	if err != nil {
		s.logger.Error("Failed to parse JWS request", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	// For now, we don't support authorization updates via POST
	// This is mainly used for deactivation, which we'll implement later
	s.logger.Debug("Authorization POST request received", "authz_id", authz.ID, "payload", string(jws.Payload))

	// Just return the current authorization status
	s.handleGetAuthorization(w, r, authz)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling challenge request", "method", r.Method)

	// Extract challenge ID from URL
	vars := mux.Vars(r)
	challengeID := vars["challengeId"]
	if challengeID == "" {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Missing challenge ID",
		})
		return
	}

	// Get challenge from storage (try persistent storage first, then fallback to memory)
	var challenge *ServerChallenge
	var exists bool

	if s.storage != nil {
		var storageErr error
		challenge, storageErr = s.storage.GetChallenge(challengeID)
		exists = (storageErr == nil)
		if !exists {
			s.logger.Debug("Challenge not found in persistent storage, checking memory", "challenge_id", challengeID)
		}
	}

	// Fallback to memory storage if persistent storage fails or challenge not found
	if !exists {
		s.challengesMu.RLock()
		challenge, exists = s.challenges[challengeID]
		s.challengesMu.RUnlock()
	}

	if !exists {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeAccountDoesNotExist,
			Title:  "Challenge not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Challenge %s not found", challengeID),
		})
		return
	}

	// Handle different HTTP methods
	switch r.Method {
	case "GET":
		s.handleGetChallenge(w, r, challenge)
	case "POST":
		s.handlePostChallenge(w, r, challenge)
	default:
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Method not allowed",
			Status: http.StatusMethodNotAllowed,
			Detail: fmt.Sprintf("Method %s not allowed", r.Method),
		})
	}
}

func (s *Server) handleGetChallenge(w http.ResponseWriter, r *http.Request, challenge *ServerChallenge) {
	s.logger.Debug("Getting challenge", "challenge_id", challenge.ID)

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	// Add "up" Link header pointing to the authorization (RFC 8555 Section 7.5.1)
	w.Header().Set("Link", fmt.Sprintf("<%s/acme/authz/%s>;rel=\"up\"", s.baseURL, challenge.AuthzID))

	// Log challenge response for debugging
	s.logger.Debug("Returning challenge response",
		"challenge_id", challenge.ID,
		"status", challenge.Status,
		"type", challenge.Type,
		"token", challenge.Token,
		"has_key_auth", challenge.KeyAuthorization != "")

	// Return challenge
	if err := json.NewEncoder(w).Encode(challenge.Challenge); err != nil {
		s.logger.Error("Failed to encode challenge response", "error", err)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to encode response",
		})
		return
	}

	s.logger.Debug("Challenge retrieved successfully", "challenge_id", challenge.ID, "status", challenge.Status)
}

func (s *Server) handlePostChallenge(w http.ResponseWriter, r *http.Request, challenge *ServerChallenge) {
	s.logger.Debug("Processing challenge", "challenge_id", challenge.ID)

	// Parse JWS request
	jws, err := s.parseJWSRequest(r)
	if err != nil {
		s.logger.Error("Failed to parse JWS request", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	// Get account from JWS
	account, err := s.getAccountFromJWS(jws)
	if err != nil {
		s.logger.Error("Failed to get account from JWS", "error", err)
		s.writeError(w, err.(*ProblemDetails))
		return
	}

	// Verify that the account owns this challenge
	authz, err := s.getAuthorizationForChallenge(challenge.AuthzID)
	if err != nil {
		s.logger.Error("Failed to get authorization for challenge", "error", err, "challenge_id", challenge.ID)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to get authorization",
		})
		return
	}

	// Get the order to verify account ownership
	order, err := s.getOrderForAuthorization(authz.OrderID)
	if err != nil {
		s.logger.Error("Failed to get order for authorization", "error", err, "authz_id", authz.ID)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to get order",
		})
		return
	}

	if order.AccountID != account.ID {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeUnauthorized,
			Title:  "Unauthorized",
			Status: http.StatusForbidden,
			Detail: "Account does not own this challenge",
		})
		return
	}

	// If challenge is already valid, invalid, or processing, return current status
	if challenge.Status == StatusValid || challenge.Status == StatusInvalid || challenge.Status == StatusProcessing {
		s.handleGetChallenge(w, r, challenge)
		return
	}

	// Start challenge validation
	s.logger.Debug("Challenge POST received", "challenge_id", challenge.ID, "type", challenge.Type)

	// Don't update challenge status to processing immediately
	// Keep it as pending until validation completes
	// This prevents UnexpectedUpdate errors in ACME clients

	// Generate key authorization using account's JWK
	keyAuth, err := s.generateKeyAuthorization(challenge.Token, account.Key)
	if err != nil {
		s.logger.Error("Failed to generate key authorization", "error", err)
		// Log JWK details for debugging
		if account.Key != nil {
			s.logger.Debug("Account JWK details", "kty", account.Key.Kty, "alg", account.Key.Alg)
		} else {
			s.logger.Debug("Account JWK is nil")
		}
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeServerInternal,
			Title:  "Internal server error",
			Status: http.StatusInternalServerError,
			Detail: "Failed to generate key authorization",
		})
		return
	}

	challenge.KeyAuthorization = keyAuth

	// Update challenge in storage
	s.updateChallengeInStorage(challenge)

	// Start validation in background
	go s.validateChallenge(challenge, authz)

	// Return updated challenge
	s.handleGetChallenge(w, r, challenge)
}

// getAccountFromJWS extracts account information from JWS
func (s *Server) getAccountFromJWS(jws *JWS) (*ServerAccount, error) {
	// Parse JWS header if not already parsed
	if jws.Header == nil {
		header, err := s.parseJWSHeader(jws.Protected)
		if err != nil {
			return nil, &ProblemDetails{
				Type:   ErrorTypeMalformed,
				Title:  "Malformed JWS header",
				Status: http.StatusBadRequest,
				Detail: "Failed to parse JWS header",
			}
		}
		jws.Header = header
	}

	// Extract account ID from kid field
	accountID := s.extractAccountIDFromKid(jws.Header.Kid)
	if accountID == "" {
		return nil, &ProblemDetails{
			Type:   ErrorTypeUnauthorized,
			Title:  "Account not found",
			Status: http.StatusUnauthorized,
			Detail: "No valid account found in JWS",
		}
	}

	// Get account
	account, err := s.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	// Convert to ServerAccount
	serverAccount := &ServerAccount{
		Account: *account,
	}

	return serverAccount, nil
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID := vars["certId"]

	s.logger.Info("Certificate retrieval request", "cert_id", certID, "method", r.Method, "url", r.URL.String())

	// Get certificate from storage (try persistent storage first, then fallback to memory)
	var certChain []byte
	var exists bool

	if s.storage != nil {
		var storageErr error
		certChain, storageErr = s.storage.GetCertificate(certID)
		exists = (storageErr == nil)
		if !exists {
			s.logger.Debug("Certificate not found in persistent storage, checking memory", "cert_id", certID, "error", storageErr)
		} else {
			s.logger.Debug("Certificate found in persistent storage", "cert_id", certID, "size", len(certChain))
		}
	}

	// Fallback to memory storage if persistent storage fails or certificate not found
	if !exists {
		s.certificatesMu.RLock()
		certChain, exists = s.certificates[certID]
		s.certificatesMu.RUnlock()
		if exists {
			s.logger.Debug("Certificate found in memory storage", "cert_id", certID, "size", len(certChain))
		} else {
			s.logger.Debug("Certificate not found in memory storage", "cert_id", certID)
		}
	}

	if !exists {
		s.logger.Warn("Certificate not found", "cert_id", certID)
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeOrderNotFound,
			Title:  "Certificate not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Certificate %s not found", certID),
		})
		return
	}

	s.logger.Info("Certificate retrieved successfully", "cert_id", certID, "size", len(certChain))

	// Generate new nonce for response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	// Return certificate chain in PEM format
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(certChain)
}

func (s *Server) handleKeyChange(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, &ProblemDetails{
		Type:   ErrorTypeServerInternal,
		Title:  "Not implemented",
		Status: http.StatusNotImplemented,
		Detail: "Key change is not yet implemented",
	})
}

func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, &ProblemDetails{
		Type:   ErrorTypeServerInternal,
		Title:  "Not implemented",
		Status: http.StatusNotImplemented,
		Detail: "Certificate revocation is not yet implemented",
	})
}

// Helper methods

// writeError writes an ACME problem details error response
func (s *Server) writeError(w http.ResponseWriter, problem *ProblemDetails) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")

	// Generate new nonce for error response
	nonce, err := s.GenerateNonce()
	if err != nil {
		s.logger.Error("Failed to generate response nonce for error", "error", err)
	} else {
		w.Header().Set("Replay-Nonce", nonce)
	}

	w.WriteHeader(problem.Status)

	if err := json.NewEncoder(w).Encode(problem); err != nil {
		s.logger.Error("Failed to encode error response", "error", err)
	}
}

// extractAccountIDFromKid extracts account ID from the kid field
// This is a simplified implementation for development
func (s *Server) extractAccountIDFromKid(kid string) string {
	// Kid format: http://localhost:14000/acme/account/{accountId}
	parts := strings.Split(kid, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// validateCSR validates that the CSR matches the order identifiers
