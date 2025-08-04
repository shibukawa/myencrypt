package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// CACertificate represents a CA certificate and its private key
type CACertificate struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// CAManager handles CA certificate operations
type CAManager struct {
	config *config.Config
	logger *logger.Logger
}

// NewCAManager creates a new CA manager instance
func NewCAManager(cfg *config.Config, log *logger.Logger) *CAManager {
	return &CAManager{
		config: cfg,
		logger: log.WithComponent("ca-manager"),
	}
}

// InitializeCA creates a new CA certificate and private key if they don't exist
func (ca *CAManager) InitializeCA() error {
	return ca.InitializeCAWithForce(false)
}

// InitializeCAWithForce creates a new CA certificate and private key, optionally forcing regeneration
func (ca *CAManager) InitializeCAWithForce(force bool) error {
	// Ensure the certificate store directory exists
	if err := ca.ensureDirectoryExists(); err != nil {
		return fmt.Errorf("failed to create certificate store directory: %w", err)
	}

	// Check if CA already exists and force is not specified
	if ca.caExists() && !force {
		return nil
	}

	// Generate CA certificate and private key
	caCert, err := ca.generateCACertificate()
	if err != nil {
		return fmt.Errorf("failed to generate CA certificate: %w", err)
	}

	// Save CA certificate and private key to files
	if err := ca.saveCACertificate(caCert); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	return nil
}

// GetCACertificate loads and returns the CA certificate
func (ca *CAManager) GetCACertificate() (*CACertificate, error) {
	ca.logger.Debug("Loading CA certificate")

	certPath := ca.getCACertPath()
	keyPath := ca.getCAKeyPath()

	// Check if files exist
	if !ca.caExists() {
		return nil, fmt.Errorf("CA certificate not found, run 'myencrypt init' first")
	}

	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	var privateKey *ecdsa.PrivateKey

	// Try to parse as ECDSA private key first (new format)
	if keyBlock.Type == "EC PRIVATE KEY" {
		var err error
		privateKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
	} else if keyBlock.Type == "RSA PRIVATE KEY" {
		// Legacy support for existing RSA keys
		_, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		// For backward compatibility, we'll need to regenerate as ECDSA
		ca.logger.Warn("Found legacy RSA CA certificate, consider regenerating with ECDSA")
		// For now, we'll return an error to force regeneration
		return nil, fmt.Errorf("legacy RSA CA certificate found, please regenerate with 'myencrypt init --force'")
	} else {
		return nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	return &CACertificate{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// GetCAPrivateKey returns the CA private key
func (ca *CAManager) GetCAPrivateKey() (*ecdsa.PrivateKey, error) {
	caCert, err := ca.GetCACertificate()
	if err != nil {
		return nil, err
	}
	return caCert.PrivateKey, nil
}

// IsCAInstalled checks if the CA certificate is installed in the system trust store
func (ca *CAManager) IsCAInstalled() (bool, error) {
	// For now, we'll just check if the CA files exist
	// In a full implementation, this would check the system trust store
	return ca.caExists(), nil
}

// ensureDirectoryExists creates the certificate store directory if it doesn't exist
func (ca *CAManager) ensureDirectoryExists() error {
	certStorePath := ca.config.GetCertStorePath()
	if err := os.MkdirAll(certStorePath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", certStorePath, err)
	}
	return nil
}

// caExists checks if CA certificate and private key files exist
func (ca *CAManager) caExists() bool {
	certPath := ca.getCACertPath()
	keyPath := ca.getCAKeyPath()

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	return certErr == nil && keyErr == nil
}

// CAExists is a public method to check if CA certificate exists
func (ca *CAManager) CAExists() bool {
	return ca.caExists()
}

// getCACertPath returns the path to the CA certificate file
func (ca *CAManager) getCACertPath() string {
	return filepath.Join(ca.config.GetCertStorePath(), "rootCA.pem")
}

// getCAKeyPath returns the path to the CA private key file
func (ca *CAManager) getCAKeyPath() string {
	return filepath.Join(ca.config.GetCertStorePath(), "rootCA-key.pem")
}

// generateCACertificate creates a new CA certificate and private key
func (ca *CAManager) generateCACertificate() (*CACertificate, error) {

	// Generate ECDSA private key using P-256 curve
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	// Get project name for Docker mode
	projectName := os.Getenv("MYENCRYPT_PROJECT_NAME")
	var caName string
	if projectName != "" {
		// Docker mode: include project name
		caName = fmt.Sprintf("MyEncrypt Development CA (%s)", projectName)
	} else {
		// Service mode: use default name
		caName = "MyEncrypt Development CA"
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{caName},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    caName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(ca.config.CACertTTL),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM (ECDSA)
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return &CACertificate{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// saveCACertificate saves the CA certificate and private key to files
func (ca *CAManager) saveCACertificate(caCert *CACertificate) error {
	certPath := ca.getCACertPath()
	keyPath := ca.getCAKeyPath()

	// Save certificate file
	if err := os.WriteFile(certPath, caCert.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s: %w", certPath, err)
	}

	// Save private key file with restricted permissions
	if err := os.WriteFile(keyPath, caCert.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA private key to %s: %w", keyPath, err)
	}

	return nil
}

// GetCertificateStorePath returns the certificate storage path
func (ca *CAManager) GetCertificateStorePath() string {
	return ca.config.GetCertStorePath()
}

// ValidateCA checks if the CA certificate is valid and not expired
func (ca *CAManager) ValidateCA() error {
	caCert, err := ca.GetCACertificate()
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	now := time.Now()
	if now.Before(caCert.Certificate.NotBefore) {
		return fmt.Errorf("CA certificate is not yet valid (valid from %s)",
			caCert.Certificate.NotBefore.Format(time.RFC3339))
	}

	if now.After(caCert.Certificate.NotAfter) {
		return fmt.Errorf("CA certificate has expired (expired on %s)",
			caCert.Certificate.NotAfter.Format(time.RFC3339))
	}

	ca.logger.Debug("CA certificate is valid",
		"valid_until", caCert.Certificate.NotAfter.Format(time.RFC3339))

	return nil
}
