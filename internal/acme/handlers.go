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
	acmeRouter.HandleFunc("/directory", s.handleDirectory).Methods("GET")
	
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
	acmeRouter.HandleFunc("/challenge/{challengeId}", s.handleChallenge).Methods("POST", "GET")
	
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
	
	s.logger.Debug("Handling order request", "orderId", orderID, "method", r.Method)
	
	order, err := s.GetOrder(orderID)
	if err != nil {
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
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

// Placeholder handlers for endpoints not yet implemented

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	orderID := vars["orderId"]

	s.logger.Info("Processing finalize request", "order_id", orderID)

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
	if err := s.validateCSR(csr, &order.Order); err != nil {
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

	// Generate certificate using our certificate manager
	cert, err := s.certManager.GenerateCertificate(domain)
	if err != nil {
		s.logger.Error("Failed to generate certificate", "error", err, "domain", domain)
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
	certificateURL := fmt.Sprintf("%s/cert/%s", s.baseURL, orderID)
	
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

	// Return updated order
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func (s *Server) handleAuthorization(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, &ProblemDetails{
		Type:   ErrorTypeServerInternal,
		Title:  "Not implemented",
		Status: http.StatusNotImplemented,
		Detail: "Authorization handling is not yet implemented",
	})
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, &ProblemDetails{
		Type:   ErrorTypeServerInternal,
		Title:  "Not implemented",
		Status: http.StatusNotImplemented,
		Detail: "Challenge handling is not yet implemented",
	})
}

func (s *Server) handleCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certID := vars["certId"]

	s.logger.Info("Certificate retrieval request", "cert_id", certID)

	// Get certificate from storage (try persistent storage first, then fallback to memory)
	var certChain []byte
	var exists bool
	
	if s.storage != nil {
		var storageErr error
		certChain, storageErr = s.storage.GetCertificate(certID)
		exists = (storageErr == nil)
		if !exists {
			s.logger.Debug("Certificate not found in persistent storage, checking memory", "cert_id", certID)
		}
	}
	
	// Fallback to memory storage if persistent storage fails or certificate not found
	if !exists {
		s.certificatesMu.RLock()
		certChain, exists = s.certificates[certID]
		s.certificatesMu.RUnlock()
	}

	if !exists {
		s.writeError(w, &ProblemDetails{
			Type:   ErrorTypeOrderNotFound,
			Title:  "Certificate not found",
			Status: http.StatusNotFound,
			Detail: fmt.Sprintf("Certificate %s not found", certID),
		})
		return
	}

	s.logger.Info("Certificate retrieved successfully", "cert_id", certID, "size", len(certChain))

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
func (s *Server) validateCSR(csr *x509.CertificateRequest, order *Order) error {
	// Extract domains from CSR
	csrDomains := make(map[string]bool)
	
	// Add common name if present
	if csr.Subject.CommonName != "" {
		csrDomains[csr.Subject.CommonName] = true
	}
	
	// Add DNS SANs
	for _, dnsName := range csr.DNSNames {
		csrDomains[dnsName] = true
	}
	
	// Check that all order identifiers are present in CSR
	for _, identifier := range order.Identifiers {
		if identifier.Type != "dns" {
			continue // Skip non-DNS identifiers
		}
		
		if !csrDomains[identifier.Value] {
			return fmt.Errorf("CSR missing domain: %s", identifier.Value)
		}
	}
	
	// Check that CSR doesn't contain unauthorized domains
	for domain := range csrDomains {
		found := false
		for _, identifier := range order.Identifiers {
			if identifier.Type == "dns" && identifier.Value == domain {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("CSR contains unauthorized domain: %s", domain)
		}
	}
	
	return nil
}
