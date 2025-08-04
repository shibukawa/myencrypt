package certmanager

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/shibukawayoshiki/myencrypt2/internal/config"
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// Manager represents a unified certificate manager interface
type Manager interface {
	// CA management
	InitializeCA() error
	GetCACertificate() (*CACertificate, error)
	GetCAPrivateKey() (*ecdsa.PrivateKey, error)
	IsCAInstalled() (bool, error)
	ValidateCA() error
	GetCertificateStorePath() string
	
	// Individual certificate generation
	GenerateCertificate(domain string) (*Certificate, error)
	GenerateCertificateFromCSR(csr *x509.CertificateRequest) (*Certificate, error)
	ValidateCertificate(cert *Certificate) error
	GetCertificateChain(cert *Certificate) ([]byte, error)
	
	// Certificate listing and management
	ListCertificates() (map[string]*Certificate, error)
	GetCertificate(domain string) (*Certificate, error)
	DeleteCertificate(domain string) error
	GetCertificateInfo(cert *Certificate) map[string]interface{}
	
	// Domain management
	LoadAllowedDomains() error
	ReloadAllowedDomains() error
	ListAllowedDomains() ([]string, error)
	IsAllowedDomain(domain string) bool
	AddDomainToFile(domain string) error
	RemoveDomainFromFile(domain string) error
	GetAllowedDomainsFilePath() string
	
	// Management API methods (CA only)
	GetCACertificatePEM() ([]byte, error)
	GetCAInfo() (map[string]interface{}, error)
	RegenerateCA() error
}

// CombinedManager combines CA and domain management functionality
type CombinedManager struct {
	caManager   *CAManager
	domainManager *DomainManager
	certManager   *CertificateManager
}

// New creates a new combined certificate manager
func New(cfg *config.Config, log *logger.Logger) Manager {
	caManager := NewCAManager(cfg, log)
	domainManager := NewDomainManager(cfg, log)
	certManager := NewCertificateManager(cfg, log, caManager)
	
	return &CombinedManager{
		caManager:     caManager,
		domainManager: domainManager,
		certManager:   certManager,
	}
}

// CA management methods - delegate to CAManager

func (m *CombinedManager) InitializeCA() error {
	return m.caManager.InitializeCA()
}

func (m *CombinedManager) GetCACertificate() (*CACertificate, error) {
	return m.caManager.GetCACertificate()
}

func (m *CombinedManager) GetCAPrivateKey() (*ecdsa.PrivateKey, error) {
	return m.caManager.GetCAPrivateKey()
}

func (m *CombinedManager) IsCAInstalled() (bool, error) {
	return m.caManager.IsCAInstalled()
}

func (m *CombinedManager) ValidateCA() error {
	return m.caManager.ValidateCA()
}

func (m *CombinedManager) GetCertificateStorePath() string {
	return m.caManager.GetCertificateStorePath()
}

// Domain management methods - delegate to DomainManager

func (m *CombinedManager) LoadAllowedDomains() error {
	return m.domainManager.LoadAllowedDomains()
}

func (m *CombinedManager) ReloadAllowedDomains() error {
	return m.domainManager.ReloadAllowedDomains()
}

func (m *CombinedManager) ListAllowedDomains() ([]string, error) {
	return m.domainManager.ListAllowedDomains()
}

func (m *CombinedManager) IsAllowedDomain(domain string) bool {
	return m.domainManager.IsAllowedDomain(domain)
}

func (m *CombinedManager) AddDomainToFile(domain string) error {
	return m.domainManager.AddDomainToFile(domain)
}

func (m *CombinedManager) RemoveDomainFromFile(domain string) error {
	return m.domainManager.RemoveDomainFromFile(domain)
}

func (m *CombinedManager) GetAllowedDomainsFilePath() string {
	return m.domainManager.GetAllowedDomainsFilePath()
}

// Certificate generation methods - delegate to CertificateManager

func (m *CombinedManager) GenerateCertificate(domain string) (*Certificate, error) {
	return m.certManager.GenerateCertificate(domain)
}

func (m *CombinedManager) GenerateCertificateFromCSR(csr *x509.CertificateRequest) (*Certificate, error) {
	return m.certManager.GenerateCertificateFromCSR(csr)
}

func (m *CombinedManager) ValidateCertificate(cert *Certificate) error {
	return m.certManager.ValidateCertificate(cert)
}

func (m *CombinedManager) GetCertificateChain(cert *Certificate) ([]byte, error) {
	return m.certManager.GetCertificateChain(cert)
}

// Certificate listing and management methods

func (m *CombinedManager) ListCertificates() (map[string]*Certificate, error) {
	return m.certManager.ListCertificates()
}

func (m *CombinedManager) GetCertificate(domain string) (*Certificate, error) {
	return m.certManager.GetCertificate(domain)
}

func (m *CombinedManager) DeleteCertificate(domain string) error {
	return m.certManager.DeleteCertificate(domain)
}

func (m *CombinedManager) GetCertificateInfo(cert *Certificate) map[string]interface{} {
	return m.certManager.GetCertificateInfo(cert)
}
