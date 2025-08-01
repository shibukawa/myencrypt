package acme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// parseJWSRequest parses a JWS request from HTTP request body
func (s *Server) parseJWSRequest(r *http.Request) (*JWS, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Failed to read request body",
		}
	}
	
	var jws JWS
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Invalid JWS format",
		}
	}
	
	// Decode and validate the payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Invalid base64url encoding in payload",
		}
	}
	
	// Replace the payload with decoded content for easier processing
	jws.Payload = string(payloadBytes)
	
	return &jws, nil
}

// parseJWSHeader parses the protected header from a JWS
func (s *Server) parseJWSHeader(protected string) (*JWSHeader, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Invalid base64url encoding in protected header",
		}
	}
	
	var header JWSHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Invalid JSON in protected header",
		}
	}
	
	// Validate nonce if present
	if header.Nonce != "" {
		if err := s.ValidateNonce(header.Nonce); err != nil {
			return nil, err
		}
	}
	
	// Validate algorithm
	if header.Alg == "" {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Missing algorithm in protected header",
		}
	}
	
	// Check for supported algorithms
	if !s.isSupportedAlgorithm(header.Alg) {
		return nil, &ProblemDetails{
			Type:   ErrorTypeBadSignatureAlgorithm,
			Title:  "Bad signature algorithm",
			Status: http.StatusBadRequest,
			Detail: fmt.Sprintf("Algorithm %s is not supported", header.Alg),
		}
	}
	
	return &header, nil
}

// isSupportedAlgorithm checks if the given algorithm is supported
func (s *Server) isSupportedAlgorithm(alg string) bool {
	supportedAlgorithms := []string{
		"RS256", "RS384", "RS512",
		"ES256", "ES384", "ES512",
		"PS256", "PS384", "PS512",
	}
	
	for _, supported := range supportedAlgorithms {
		if alg == supported {
			return true
		}
	}
	
	return false
}

// validateJWSSignature validates the JWS signature (simplified implementation)
// In a production implementation, this would perform actual cryptographic verification
func (s *Server) validateJWSSignature(jws *JWS, header *JWSHeader) error {
	// For development purposes, we'll skip actual signature verification
	// In production, this would:
	// 1. Reconstruct the signing input (protected + "." + payload)
	// 2. Verify the signature using the public key from JWK or account
	// 3. Return appropriate error if verification fails
	
	s.logger.Debug("JWS signature validation skipped for development")
	return nil
}

// createJWSResponse creates a JWS response (for future use)
func (s *Server) createJWSResponse(payload interface{}, accountKey *JSONWebKey, nonce string, url string) (*JWS, error) {
	// This would be used for responses that need to be signed by the server
	// Currently not needed for basic ACME directory functionality
	return nil, fmt.Errorf("JWS response creation not implemented")
}

// Helper functions for JWK handling

// validateJWK validates a JSON Web Key
func (s *Server) validateJWK(jwk *JSONWebKey) error {
	if jwk == nil {
		return &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Missing JWK",
		}
	}
	
	// Validate key type
	if jwk.Kty == "" {
		return &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Malformed request",
			Status: http.StatusBadRequest,
			Detail: "Missing key type (kty) in JWK",
		}
	}
	
	// Validate based on key type
	switch jwk.Kty {
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return &ProblemDetails{
				Type:   ErrorTypeBadPublicKey,
				Title:  "Bad public key",
				Status: http.StatusBadRequest,
				Detail: "RSA key missing required parameters (n, e)",
			}
		}
	case "EC":
		if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
			return &ProblemDetails{
				Type:   ErrorTypeBadPublicKey,
				Title:  "Bad public key",
				Status: http.StatusBadRequest,
				Detail: "EC key missing required parameters (x, y, crv)",
			}
		}
	default:
		return &ProblemDetails{
			Type:   ErrorTypeBadPublicKey,
			Title:  "Bad public key",
			Status: http.StatusBadRequest,
			Detail: fmt.Sprintf("Unsupported key type: %s", jwk.Kty),
		}
	}
	
	return nil
}

// jwkThumbprint calculates the JWK thumbprint (for account identification)
func (s *Server) jwkThumbprint(jwk *JSONWebKey) (string, error) {
	// Simplified implementation - in production this would calculate
	// the actual RFC 7638 JWK thumbprint
	return fmt.Sprintf("thumbprint_%s_%s", jwk.Kty, jwk.N), nil
}

// normalizeURL normalizes URLs for comparison
func (s *Server) normalizeURL(url string) string {
	// Remove trailing slashes and normalize for comparison
	return strings.TrimSuffix(url, "/")
}

// parseJWSPayload parses a JWS request and returns the payload
func (s *Server) parseJWSPayload(r *http.Request) ([]byte, error) {
	jws, err := s.parseJWSRequest(r)
	if err != nil {
		return nil, err
	}
	
	// Decode the payload
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, &ProblemDetails{
			Type:   ErrorTypeMalformed,
			Title:  "Invalid JWS payload",
			Status: http.StatusBadRequest,
			Detail: "Failed to decode JWS payload",
		}
	}
	
	return payload, nil
}
