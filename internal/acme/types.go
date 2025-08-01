package acme

import (
	"crypto"
	"fmt"
	"time"
)

// RFC 8555 ACME Protocol Data Structures

// Directory represents the ACME directory endpoint response
type Directory struct {
	NewNonce   string            `json:"newNonce"`
	NewAccount string            `json:"newAccount"`
	NewOrder   string            `json:"newOrder"`
	NewAuthz   string            `json:"newAuthz,omitempty"`
	RevokeCert string            `json:"revokeCert"`
	KeyChange  string            `json:"keyChange"`
	Meta       *DirectoryMeta    `json:"meta,omitempty"`
	ExternalAccountRequired bool `json:"externalAccountRequired,omitempty"`
}

// DirectoryMeta contains metadata about the ACME server
type DirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService,omitempty"`
	Website                 string   `json:"website,omitempty"`
	CaaIdentities           []string `json:"caaIdentities,omitempty"`
	ExternalAccountRequired bool     `json:"externalAccountRequired,omitempty"`
}

// Account represents an ACME account
type Account struct {
	ID        string    `json:"id"`
	Key       *JSONWebKey `json:"key"`
	Contact   []string  `json:"contact,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// JSONWebKey represents a JSON Web Key (JWK)
type JSONWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	X   string `json:"x,omitempty"`   // EC x coordinate
	Y   string `json:"y,omitempty"`   // EC y coordinate
	Crv string `json:"crv,omitempty"` // EC curve
}

// Order represents a certificate order
type Order struct {
	ID           string        `json:"id"`
	AccountID    string        `json:"accountId"`
	Status       string        `json:"status"`
	Expires      time.Time     `json:"expires"`
	Identifiers  []Identifier  `json:"identifiers"`
	NotBefore    *time.Time    `json:"notBefore,omitempty"`
	NotAfter     *time.Time    `json:"notAfter,omitempty"`
	Error        *ProblemDetails `json:"error,omitempty"`
	Authorizations []string    `json:"authorizations"`
	Finalize     string        `json:"finalize"`
	Certificate  string        `json:"certificate,omitempty"`
	CreatedAt    time.Time     `json:"createdAt"`
	UpdatedAt    time.Time     `json:"updatedAt"`
}

// Identifier represents a domain identifier
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Authorization represents a domain authorization
type Authorization struct {
	ID         string        `json:"id"`
	Identifier Identifier    `json:"identifier"`
	Status     string        `json:"status"`
	Expires    time.Time     `json:"expires"`
	Challenges []Challenge   `json:"challenges"`
	Wildcard   bool          `json:"wildcard,omitempty"`
	CreatedAt  time.Time     `json:"createdAt"`
	UpdatedAt  time.Time     `json:"updatedAt"`
}

// Challenge represents an ACME challenge
type Challenge struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	URL    string `json:"url"`
	Status string `json:"status"`
	Token  string `json:"token"`
	KeyAuthorization string `json:"keyAuthorization,omitempty"`
	Validated *time.Time `json:"validated,omitempty"`
	Error     *ProblemDetails `json:"error,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ProblemDetails represents an RFC 7807 problem details object
type ProblemDetails struct {
	Type     string      `json:"type"`
	Title    string      `json:"title"`
	Status   int         `json:"status"`
	Detail   string      `json:"detail"`
	Instance string      `json:"instance,omitempty"`
	SubProblems []SubProblem `json:"subproblems,omitempty"`
}

// Error implements the error interface for ProblemDetails
func (p *ProblemDetails) Error() string {
	return fmt.Sprintf("%s: %s", p.Title, p.Detail)
}

// SubProblem represents a sub-problem in problem details
type SubProblem struct {
	Type       string     `json:"type"`
	Detail     string     `json:"detail"`
	Identifier Identifier `json:"identifier"`
}

// ACME Status Constants
const (
	StatusPending     = "pending"
	StatusProcessing  = "processing"
	StatusValid       = "valid"
	StatusInvalid     = "invalid"
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusRevoked     = "revoked"
	StatusReady       = "ready"
)

// Order Status Constants
const (
	OrderStatusPending    = "pending"
	OrderStatusReady      = "ready"
	OrderStatusProcessing = "processing"
	OrderStatusValid      = "valid"
	OrderStatusInvalid    = "invalid"
)

// Challenge Types
const (
	ChallengeTypeHTTP01 = "http-01"
	ChallengeTypeDNS01  = "dns-01"
	ChallengeTypeTLSALPN01 = "tls-alpn-01"
)

// Error Types (RFC 8555 Section 6.7)
const (
	ErrorTypeAccountDoesNotExist     = "urn:ietf:params:acme:error:accountDoesNotExist"
	ErrorTypeAlreadyRevoked          = "urn:ietf:params:acme:error:alreadyRevoked"
	ErrorTypeBadCSR                  = "urn:ietf:params:acme:error:badCSR"
	ErrorTypeBadNonce                = "urn:ietf:params:acme:error:badNonce"
	ErrorTypeBadPublicKey            = "urn:ietf:params:acme:error:badPublicKey"
	ErrorTypeBadRevocationReason     = "urn:ietf:params:acme:error:badRevocationReason"
	ErrorTypeBadSignatureAlgorithm   = "urn:ietf:params:acme:error:badSignatureAlgorithm"
	ErrorTypeCAA                     = "urn:ietf:params:acme:error:caa"
	ErrorTypeCompound                = "urn:ietf:params:acme:error:compound"
	ErrorTypeConnection              = "urn:ietf:params:acme:error:connection"
	ErrorTypeDNS                     = "urn:ietf:params:acme:error:dns"
	ErrorTypeExternalAccountRequired = "urn:ietf:params:acme:error:externalAccountRequired"
	ErrorTypeIncorrectResponse       = "urn:ietf:params:acme:error:incorrectResponse"
	ErrorTypeInvalidContact          = "urn:ietf:params:acme:error:invalidContact"
	ErrorTypeMalformed               = "urn:ietf:params:acme:error:malformed"
	ErrorTypeOrderNotFound           = "urn:ietf:params:acme:error:orderNotFound"
	ErrorTypeOrderNotReady           = "urn:ietf:params:acme:error:orderNotReady"
	ErrorTypeRateLimited             = "urn:ietf:params:acme:error:rateLimited"
	ErrorTypeRejectedIdentifier      = "urn:ietf:params:acme:error:rejectedIdentifier"
	ErrorTypeServerInternal          = "urn:ietf:params:acme:error:serverInternal"
	ErrorTypeTLS                     = "urn:ietf:params:acme:error:tls"
	ErrorTypeUnauthorized            = "urn:ietf:params:acme:error:unauthorized"
	ErrorTypeUnsupportedContact      = "urn:ietf:params:acme:error:unsupportedContact"
	ErrorTypeUnsupportedIdentifier   = "urn:ietf:params:acme:error:unsupportedIdentifier"
	ErrorTypeUserActionRequired      = "urn:ietf:params:acme:error:userActionRequired"
)

// Request/Response Types

// AccountRequest represents a new account request
type AccountRequest struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitempty"`
}

// OrderRequest represents a new order request
type OrderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   *time.Time   `json:"notBefore,omitempty"`
	NotAfter    *time.Time   `json:"notAfter,omitempty"`
}

// FinalizeRequest represents a finalize order request
type FinalizeRequest struct {
	CSR string `json:"csr"` // Base64url-encoded DER CSR
}

// KeyChangeRequest represents a key change request
type KeyChangeRequest struct {
	Account   string `json:"account"`
	OldKey    *JSONWebKey `json:"oldKey"`
}

// RevocationRequest represents a certificate revocation request
type RevocationRequest struct {
	Certificate string `json:"certificate"` // Base64url-encoded DER certificate
	Reason      *int   `json:"reason,omitempty"`
}

// JWS represents a JSON Web Signature
type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// JWSHeader represents a JWS header
type JWSHeader struct {
	Alg   string      `json:"alg"`
	Nonce string      `json:"nonce,omitempty"`
	URL   string      `json:"url,omitempty"`
	JWK   *JSONWebKey `json:"jwk,omitempty"`
	Kid   string      `json:"kid,omitempty"`
}

// NonceResponse represents a nonce response
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// Internal types for server implementation

// ServerAccount represents an account stored on the server
type ServerAccount struct {
	Account
	PrivateKey crypto.PrivateKey `json:"-"` // Not serialized
}

// ServerOrder represents an order stored on the server
type ServerOrder struct {
	Order
	CSR []byte `json:"-"` // DER-encoded CSR
}

// ServerChallenge represents a challenge stored on the server
type ServerChallenge struct {
	Challenge
	AuthzID string `json:"authzId"`
}

// ServerAuthorization represents an authorization stored on the server
type ServerAuthorization struct {
	Authorization
	OrderID string `json:"orderId"`
}
