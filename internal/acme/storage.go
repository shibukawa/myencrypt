package acme

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shibukawa/myencrypt/internal/config"
	"github.com/shibukawa/myencrypt/internal/logger"
)

// Storage interface for ACME state persistence
type Storage interface {
	// Account operations
	StoreAccount(accountID string, account *ServerAccount) error
	GetAccount(accountID string) (*ServerAccount, error)
	DeleteAccount(accountID string) error

	// Order operations
	StoreOrder(orderID string, order *ServerOrder) error
	GetOrder(orderID string) (*ServerOrder, error)
	UpdateOrderStatus(orderID string, status string, certificateURL string) error
	DeleteOrder(orderID string) error

	// Certificate operations
	StoreCertificate(certID string, certChain []byte) error
	GetCertificate(certID string) ([]byte, error)
	DeleteCertificate(certID string) error

	// Authorization operations
	StoreAuthorization(authzID string, authz *ServerAuthorization) error
	GetAuthorization(authzID string) (*ServerAuthorization, error)
	DeleteAuthorization(authzID string) error

	// Challenge operations
	StoreChallenge(challengeID string, challenge *ServerChallenge) error
	GetChallenge(challengeID string) (*ServerChallenge, error)
	UpdateChallengeStatus(challengeID string, status string) error
	DeleteChallenge(challengeID string) error

	// Nonce operations
	StoreNonce(nonce string, expiry time.Time) error
	ValidateAndDeleteNonce(nonce string) error
	CleanupExpiredNonces() error

	// Cleanup operations
	Close() error
}

// FileStorage implements Storage interface using file system
type FileStorage struct {
	basePath string
	logger   *logger.Logger
	mu       sync.RWMutex
}

// NewFileStorage creates a new file-based storage
func NewFileStorage(cfg *config.Config, log *logger.Logger) (*FileStorage, error) {
	basePath := filepath.Join(cfg.GetCertStorePath(), "acme-state")

	// Create directory structure
	dirs := []string{
		"accounts",
		"orders",
		"certificates",
		"authorizations",
		"challenges",
		"nonces",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(basePath, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dirPath, err)
		}
	}

	return &FileStorage{
		basePath: basePath,
		logger:   log.WithComponent("acme-storage"),
	}, nil
}

// Account operations
func (fs *FileStorage) StoreAccount(accountID string, account *ServerAccount) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.writeJSON(filepath.Join("accounts", accountID+".json"), account)
}

func (fs *FileStorage) GetAccount(accountID string) (*ServerAccount, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var account ServerAccount
	err := fs.readJSON(filepath.Join("accounts", accountID+".json"), &account)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (fs *FileStorage) DeleteAccount(accountID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.deleteFile(filepath.Join("accounts", accountID+".json"))
}

// Order operations
func (fs *FileStorage) StoreOrder(orderID string, order *ServerOrder) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.writeJSON(filepath.Join("orders", orderID+".json"), order)
}

func (fs *FileStorage) GetOrder(orderID string) (*ServerOrder, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var order ServerOrder
	err := fs.readJSON(filepath.Join("orders", orderID+".json"), &order)
	if err != nil {
		return nil, err
	}
	return &order, nil
}

func (fs *FileStorage) UpdateOrderStatus(orderID string, status string, certificateURL string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Read existing order
	var order ServerOrder
	if err := fs.readJSON(filepath.Join("orders", orderID+".json"), &order); err != nil {
		return err
	}

	// Update status
	order.Status = status
	if certificateURL != "" {
		order.Certificate = certificateURL
	}

	// Write back
	return fs.writeJSON(filepath.Join("orders", orderID+".json"), &order)
}

func (fs *FileStorage) DeleteOrder(orderID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.deleteFile(filepath.Join("orders", orderID+".json"))
}

// Certificate operations
func (fs *FileStorage) StoreCertificate(certID string, certChain []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	certPath := filepath.Join(fs.basePath, "certificates", certID+".pem")
	return os.WriteFile(certPath, certChain, 0644)
}

func (fs *FileStorage) GetCertificate(certID string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	certPath := filepath.Join(fs.basePath, "certificates", certID+".pem")
	return os.ReadFile(certPath)
}

func (fs *FileStorage) DeleteCertificate(certID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.deleteFile(filepath.Join("certificates", certID+".pem"))
}

// Authorization operations
func (fs *FileStorage) StoreAuthorization(authzID string, authz *ServerAuthorization) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.writeJSON(filepath.Join("authorizations", authzID+".json"), authz)
}

func (fs *FileStorage) GetAuthorization(authzID string) (*ServerAuthorization, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var authz ServerAuthorization
	err := fs.readJSON(filepath.Join("authorizations", authzID+".json"), &authz)
	if err != nil {
		return nil, err
	}
	return &authz, nil
}

func (fs *FileStorage) DeleteAuthorization(authzID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.deleteFile(filepath.Join("authorizations", authzID+".json"))
}

// Challenge operations
func (fs *FileStorage) StoreChallenge(challengeID string, challenge *ServerChallenge) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.writeJSON(filepath.Join("challenges", challengeID+".json"), challenge)
}

func (fs *FileStorage) GetChallenge(challengeID string) (*ServerChallenge, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	var challenge ServerChallenge
	err := fs.readJSON(filepath.Join("challenges", challengeID+".json"), &challenge)
	if err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (fs *FileStorage) UpdateChallengeStatus(challengeID string, status string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Read existing challenge
	var challenge ServerChallenge
	if err := fs.readJSON(filepath.Join("challenges", challengeID+".json"), &challenge); err != nil {
		return err
	}

	// Update status
	challenge.Status = status

	// Write back
	return fs.writeJSON(filepath.Join("challenges", challengeID+".json"), &challenge)
}

func (fs *FileStorage) DeleteChallenge(challengeID string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	return fs.deleteFile(filepath.Join("challenges", challengeID+".json"))
}

// Nonce operations
type NonceEntry struct {
	Nonce  string    `json:"nonce"`
	Expiry time.Time `json:"expiry"`
}

func (fs *FileStorage) StoreNonce(nonce string, expiry time.Time) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	entry := NonceEntry{
		Nonce:  nonce,
		Expiry: expiry,
	}

	return fs.writeJSON(filepath.Join("nonces", nonce+".json"), &entry)
}

func (fs *FileStorage) ValidateAndDeleteNonce(nonce string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if nonce exists and is not expired
	var entry NonceEntry
	if err := fs.readJSON(filepath.Join("nonces", nonce+".json"), &entry); err != nil {
		return fmt.Errorf("nonce not found or invalid")
	}

	if time.Now().After(entry.Expiry) {
		fs.deleteFile(filepath.Join("nonces", nonce+".json"))
		return fmt.Errorf("nonce expired")
	}

	// Delete nonce (one-time use)
	return fs.deleteFile(filepath.Join("nonces", nonce+".json"))
}

func (fs *FileStorage) CleanupExpiredNonces() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	noncesDir := filepath.Join(fs.basePath, "nonces")
	entries, err := os.ReadDir(noncesDir)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			var nonceEntry NonceEntry
			if err := fs.readJSON(filepath.Join("nonces", entry.Name()), &nonceEntry); err != nil {
				continue
			}

			if now.After(nonceEntry.Expiry) {
				fs.deleteFile(filepath.Join("nonces", entry.Name()))
			}
		}
	}

	return nil
}

func (fs *FileStorage) Close() error {
	// Cleanup expired nonces on close
	return fs.CleanupExpiredNonces()
}

// Helper methods
func (fs *FileStorage) writeJSON(relativePath string, data interface{}) error {
	fullPath := filepath.Join(fs.basePath, relativePath)

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(fullPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", fullPath, err)
	}

	fs.logger.Debug("Stored data", "path", relativePath)
	return nil
}

func (fs *FileStorage) readJSON(relativePath string, data interface{}) error {
	fullPath := filepath.Join(fs.basePath, relativePath)

	jsonData, err := os.ReadFile(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not found")
		}
		return fmt.Errorf("failed to read file %s: %w", fullPath, err)
	}

	if err := json.Unmarshal(jsonData, data); err != nil {
		return fmt.Errorf("failed to unmarshal JSON from %s: %w", fullPath, err)
	}

	return nil
}

func (fs *FileStorage) deleteFile(relativePath string) error {
	fullPath := filepath.Join(fs.basePath, relativePath)

	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file %s: %w", fullPath, err)
	}

	fs.logger.Debug("Deleted data", "path", relativePath)
	return nil
}
