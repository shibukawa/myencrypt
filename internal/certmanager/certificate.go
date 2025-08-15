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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shibukawa/myencrypt/internal/config"
	"github.com/shibukawa/myencrypt/internal/logger"
)

// Certificate represents an individual certificate
type Certificate struct {
	Domain      string
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
	ValidFrom   time.Time
	ValidUntil  time.Time
	CreatedAt   time.Time
}

// CertificateManager handles individual certificate operations
type CertificateManager struct {
	config       *config.Config
	logger       *logger.Logger
	caManager    *CAManager
	certDir      string
	certificates map[string]*Certificate
	mu           sync.RWMutex
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(cfg *config.Config, log *logger.Logger, caManager *CAManager) *CertificateManager {
	certDir := filepath.Join(cfg.GetCertStorePath(), "certificates")
	os.MkdirAll(certDir, 0755)

	return &CertificateManager{
		config:       cfg,
		logger:       log.WithComponent("cert-manager"),
		caManager:    caManager,
		certDir:      certDir,
		certificates: make(map[string]*Certificate),
	}
}

// GenerateCertificate generates a new certificate for the specified domain
func (cm *CertificateManager) GenerateCertificate(domain string) (*Certificate, error) {
	cm.caManager.logger.Info("Generating certificate", "domain", domain)

	// Get CA certificate and private key
	caCert, err := cm.caManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Generate ECDSA private key for the certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Extract CA creation time and project info
	caCreatedAt := caCert.Certificate.NotBefore
	projectName := config.GetProjectName()

	// Create certificate template
	// Construct base URLs for CRL and OCSP
	baseURL := fmt.Sprintf("http://localhost:%d", cm.config.HTTPPort)

	// Build organization unit with CA information
	var orgUnit []string
	if projectName != "" {
		orgUnit = []string{
			"MyEncrypt Client Certificate",
			fmt.Sprintf("Project: %s", projectName),
			fmt.Sprintf("CA Created: %s", caCreatedAt.Format("2006-01-02 15:04:05 MST")),
			fmt.Sprintf("Cert Issued: %s", time.Now().Format("2006-01-02 15:04:05 MST")),
		}
	} else {
		orgUnit = []string{
			"MyEncrypt Client Certificate",
			fmt.Sprintf("CA Created: %s", caCreatedAt.Format("2006-01-02 15:04:05 MST")),
			fmt.Sprintf("Cert Issued: %s", time.Now().Format("2006-01-02 15:04:05 MST")),
		}
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"MyEncrypt Development"},
			OrganizationalUnit: orgUnit,
			Country:            []string{"US"},
			Province:           []string{"Development"},
			Locality:           []string{"Local"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
			CommonName:         domain,
		},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(cm.caManager.config.IndividualCertTTL),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA256,

		// Add CRL Distribution Points for certificate revocation checking
		CRLDistributionPoints: []string{
			baseURL + "/crl/myencrypt.crl",
		},

		// Add OCSP Server for online certificate status checking
		OCSPServer: []string{
			baseURL + "/ocsp",
		},

		// Add CA Issuers URI for certificate chain building
		IssuingCertificateURL: []string{
			baseURL + "/ca.crt",
		},
	}

	// Add domain to certificate
	if err := cm.addDomainToTemplate(&template, domain); err != nil {
		return nil, fmt.Errorf("failed to add domain to certificate: %w", err)
	}

	// Create the certificate signed by CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert.Certificate, &privateKey.PublicKey, caCert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the generated certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	certificate := &Certificate{
		Domain:      domain,
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		ValidFrom:   cert.NotBefore,
		ValidUntil:  cert.NotAfter,
		CreatedAt:   time.Now(),
	}

	// Save certificate to file system for management API access
	if err := cm.saveCertificateToFile(certificate); err != nil {
		cm.caManager.logger.Error("Failed to save certificate to file", "domain", domain, "error", err)
		// Don't fail the generation, just log the error
	}

	cm.caManager.logger.Info("Certificate generated successfully",
		"domain", domain,
		"serial", cert.SerialNumber.String(),
		"valid_until", cert.NotAfter.Format(time.RFC3339))

	return certificate, nil
}

// addDomainToTemplate adds the domain to the certificate template as SAN
func (cm *CertificateManager) addDomainToTemplate(template *x509.Certificate, domain string) error {
	// Handle wildcard domains
	if strings.HasPrefix(domain, "*.") {
		// For wildcard certificates, add both the wildcard and the base domain
		baseDomain := strings.TrimPrefix(domain, "*.")
		template.DNSNames = []string{domain, baseDomain}
		cm.caManager.logger.Debug("Added wildcard domain to certificate", "wildcard", domain, "base", baseDomain)
	} else {
		// Check if it's an IP address
		if ip := net.ParseIP(domain); ip != nil {
			template.IPAddresses = []net.IP{ip}
			cm.caManager.logger.Debug("Added IP address to certificate", "ip", domain)
		} else {
			// Regular domain name
			template.DNSNames = []string{domain}
			cm.caManager.logger.Debug("Added DNS name to certificate", "domain", domain)
		}
	}

	return nil
}

// ValidateCertificate checks if a certificate is valid and not expired
func (cm *CertificateManager) ValidateCertificate(cert *Certificate) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	now := time.Now()
	if now.Before(cert.ValidFrom) {
		return fmt.Errorf("certificate is not yet valid (valid from: %s)", cert.ValidFrom.Format(time.RFC3339))
	}

	if now.After(cert.ValidUntil) {
		return fmt.Errorf("certificate has expired (expired: %s)", cert.ValidUntil.Format(time.RFC3339))
	}

	return nil
}

// GetCertificateChain returns the certificate chain (cert + CA cert) in PEM format
func (cm *CertificateManager) GetCertificateChain(cert *Certificate) ([]byte, error) {
	// Get CA certificate
	caCert, err := cm.caManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Combine certificate and CA certificate
	chain := append(cert.CertPEM, caCert.CertPEM...)
	return chain, nil
}

// GetCertificateInfo returns human-readable certificate information
func (cm *CertificateManager) GetCertificateInfo(cert *Certificate) map[string]interface{} {
	info := map[string]interface{}{
		"domain":       cert.Domain,
		"serial":       cert.Certificate.SerialNumber.String(),
		"subject":      cert.Certificate.Subject.String(),
		"issuer":       cert.Certificate.Issuer.String(),
		"valid_from":   cert.ValidFrom.Format(time.RFC3339),
		"valid_until":  cert.ValidUntil.Format(time.RFC3339),
		"created_at":   cert.CreatedAt.Format(time.RFC3339),
		"dns_names":    cert.Certificate.DNSNames,
		"ip_addresses": cert.Certificate.IPAddresses,
		"algorithm":    "ECDSA P-256",
		"signature":    cert.Certificate.SignatureAlgorithm.String(),
	}

	// Calculate remaining validity
	remaining := time.Until(cert.ValidUntil)
	if remaining > 0 {
		info["remaining_hours"] = int(remaining.Hours())
		info["remaining_days"] = int(remaining.Hours() / 24)
	} else {
		info["remaining_hours"] = 0
		info["remaining_days"] = 0
		info["expired"] = true
	}

	return info
}

// saveCertificateToFile saves the certificate and private key to the file system
func (cm *CertificateManager) saveCertificateToFile(cert *Certificate) error {
	// Create certificate directory
	certDir := filepath.Join(cm.caManager.config.GetCertStorePath(), "certs", cert.Domain)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Save certificate PEM
	certPath := filepath.Join(certDir, "cert.pem")
	if err := os.WriteFile(certPath, cert.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	// Save private key PEM
	keyPath := filepath.Join(certDir, "key.pem")
	if err := os.WriteFile(keyPath, cert.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	cm.caManager.logger.Debug("Certificate saved to file system", "domain", cert.Domain, "path", certDir)
	return nil
}

// CA Management API methods implementation

// GetCACertificatePEM returns the PEM-encoded CA certificate
func (cm *CombinedManager) GetCACertificatePEM() ([]byte, error) {
	cm.caManager.logger.Debug("Getting CA certificate")

	caPath := filepath.Join(cm.caManager.config.GetCertStorePath(), "rootCA.pem")
	caData, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	return caData, nil
}

// GetCAInfo returns information about the CA certificate
func (cm *CombinedManager) GetCAInfo() (map[string]interface{}, error) {
	cm.caManager.logger.Debug("Getting CA certificate info")

	caCert, err := cm.GetCACertificate()
	if err != nil {
		return nil, err
	}

	// Parse the CA certificate - caCert.Certificate is already *x509.Certificate
	cert := caCert.Certificate

	info := map[string]interface{}{
		"subject":             cert.Subject.String(),
		"issuer":              cert.Issuer.String(),
		"serial_number":       cert.SerialNumber.String(),
		"not_before":          cert.NotBefore,
		"not_after":           cert.NotAfter,
		"is_ca":               cert.IsCA,
		"key_usage":           cert.KeyUsage,
		"signature_algorithm": cert.SignatureAlgorithm.String(),
	}

	// Calculate expiry information
	now := time.Now()
	if cert.NotAfter.After(now) {
		remaining := cert.NotAfter.Sub(now)
		info["expired"] = false
		info["remaining_hours"] = int(remaining.Hours())
		info["remaining_days"] = int(remaining.Hours() / 24)
	} else {
		info["expired"] = true
		info["remaining_hours"] = 0
		info["remaining_days"] = 0
	}

	return info, nil
}

// RegenerateCA regenerates the CA certificate and private key
func (cm *CombinedManager) RegenerateCA() error {
	cm.caManager.logger.Info("Regenerating CA certificate")

	// Remove existing CA files
	caFiles := []string{"rootCA.pem", "rootCA-key.pem"}
	for _, file := range caFiles {
		path := filepath.Join(cm.caManager.config.GetCertStorePath(), file)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cm.caManager.logger.Warn("Failed to remove existing CA file", "file", file, "error", err)
		}
	}

	// Reinitialize CA
	if err := cm.InitializeCA(); err != nil {
		return fmt.Errorf("failed to regenerate CA: %w", err)
	}

	cm.caManager.logger.Info("CA certificate regenerated successfully")
	return nil
}

// ListCertificates returns all stored certificates
func (cm *CertificateManager) ListCertificates() (map[string]*Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	certificates := make(map[string]*Certificate)

	// Copy certificates from memory cache
	for domain, cert := range cm.certificates {
		certificates[domain] = cert
	}

	cm.logger.Debug("Listed certificates", "count", len(certificates))
	return certificates, nil
}

// GetCertificate retrieves a specific certificate by domain
func (cm *CertificateManager) GetCertificate(domain string) (*Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cert, exists := cm.certificates[domain]
	if !exists {
		return nil, fmt.Errorf("certificate not found for domain: %s", domain)
	}

	cm.logger.Debug("Retrieved certificate", "domain", domain)
	return cert, nil
}

// DeleteCertificate removes a certificate from storage
func (cm *CertificateManager) DeleteCertificate(domain string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if certificate exists
	if _, exists := cm.certificates[domain]; !exists {
		return fmt.Errorf("certificate not found for domain: %s", domain)
	}

	// Remove from memory cache
	delete(cm.certificates, domain)

	// Remove certificate file if it exists
	certPath := filepath.Join(cm.certDir, fmt.Sprintf("%s.pem", domain))
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		cm.logger.Error("Failed to remove certificate file", "error", err, "path", certPath)
		// Don't return error as memory cleanup was successful
	}

	// Remove private key file if it exists
	keyPath := filepath.Join(cm.certDir, fmt.Sprintf("%s.key", domain))
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		cm.logger.Error("Failed to remove private key file", "error", err, "path", keyPath)
		// Don't return error as memory cleanup was successful
	}

	cm.logger.Info("Certificate deleted", "domain", domain)
	return nil
}

// GenerateCertificateFromCSR generates a new certificate from a Certificate Signing Request
func (cm *CertificateManager) GenerateCertificateFromCSR(csr *x509.CertificateRequest) (*Certificate, error) {
	if len(csr.DNSNames) == 0 && csr.Subject.CommonName == "" {
		return nil, fmt.Errorf("CSR must contain at least one DNS name or common name")
	}

	// Use the first DNS name or common name as the domain
	domain := csr.Subject.CommonName
	if len(csr.DNSNames) > 0 {
		domain = csr.DNSNames[0]
	}

	cm.caManager.logger.Info("Generating certificate from CSR", "domain", domain)

	// Get CA certificate and private key
	caCert, err := cm.caManager.GetCACertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Generate a random serial number
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000000))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Construct base URLs for CRL and OCSP
	baseURL := fmt.Sprintf("http://localhost:%d", cm.config.HTTPPort)

	// Extract CA creation time and project info
	caCreatedAt := caCert.Certificate.NotBefore
	projectName := config.GetProjectName()

	// Build organization unit with CA information
	var orgUnit []string
	if projectName != "" {
		orgUnit = []string{
			"MyEncrypt Client Certificate",
			fmt.Sprintf("Project: %s", projectName),
			fmt.Sprintf("CA Created: %s", caCreatedAt.Format("2006-01-02 15:04:05 MST")),
			fmt.Sprintf("Cert Issued: %s", time.Now().Format("2006-01-02 15:04:05 MST")),
		}
	} else {
		orgUnit = []string{
			"MyEncrypt Client Certificate",
			fmt.Sprintf("CA Created: %s", caCreatedAt.Format("2006-01-02 15:04:05 MST")),
			fmt.Sprintf("Cert Issued: %s", time.Now().Format("2006-01-02 15:04:05 MST")),
		}
	}

	// Enhance the CSR subject with MyEncrypt information
	enhancedSubject := csr.Subject
	if len(enhancedSubject.Organization) == 0 {
		enhancedSubject.Organization = []string{"MyEncrypt Development"}
	}
	enhancedSubject.OrganizationalUnit = orgUnit
	if enhancedSubject.Province == nil || len(enhancedSubject.Province) == 0 {
		enhancedSubject.Province = []string{"Development"}
	}
	if enhancedSubject.Locality == nil || len(enhancedSubject.Locality) == 0 {
		enhancedSubject.Locality = []string{"Local"}
	}

	// Create certificate template based on CSR
	template := x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            enhancedSubject,
		DNSNames:           csr.DNSNames,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(cm.caManager.config.IndividualCertTTL),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: x509.ECDSAWithSHA256,

		// Add CRL Distribution Points for certificate revocation checking
		CRLDistributionPoints: []string{
			baseURL + "/crl/myencrypt.crl",
		},

		// Add OCSP Server for online certificate status checking
		OCSPServer: []string{
			baseURL + "/ocsp",
		},

		// Add CA Issuers URI for certificate chain building
		IssuingCertificateURL: []string{
			baseURL + "/ca.crt",
		},
	}

	// Add domain to certificate template
	if err := cm.addDomainToTemplate(&template, domain); err != nil {
		return nil, fmt.Errorf("failed to add domain to certificate: %w", err)
	}

	// Create certificate using the CSR's public key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert.Certificate, csr.PublicKey, caCert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	cm.caManager.logger.Info("Certificate generated successfully from CSR",
		"domain", domain,
		"serial", cert.SerialNumber,
		"valid_until", cert.NotAfter)

	// Note: We don't have the private key since it was generated by the client
	// The client will use their own private key with this certificate
	return &Certificate{
		Certificate: cert,
		PrivateKey:  nil, // Client keeps their private key
		Domain:      domain,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		KeyPEM:      nil, // No private key PEM since client keeps it
		ValidFrom:   cert.NotBefore,
		ValidUntil:  cert.NotAfter,
		CreatedAt:   time.Now(),
	}, nil
}
