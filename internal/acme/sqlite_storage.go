package acme

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/shibukawa/myencrypt/internal/config"
	"github.com/shibukawa/myencrypt/internal/logger"
)

// SQLiteStorage implements Storage interface using SQLite
type SQLiteStorage struct {
	db      *sql.DB
	logger  *logger.Logger
	baseURL string
}

// NewSQLiteStorage creates a new SQLite-based storage
func NewSQLiteStorage(cfg *config.Config, log *logger.Logger, baseURL string) (*SQLiteStorage, error) {
	dbPath := cfg.GetDatabasePath()

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &SQLiteStorage{
		db:      db,
		logger:  log.WithComponent("sqlite-storage"),
		baseURL: baseURL,
	}

	if err := storage.initDatabase(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	storage.logger.Info("SQLite storage initialized", "path", dbPath)
	return storage, nil
}

// initDatabase creates tables if they don't exist
func (s *SQLiteStorage) initDatabase() error {
	schema := `
	-- アカウント管理
	CREATE TABLE IF NOT EXISTS accounts (
		id TEXT PRIMARY KEY,
		public_key_jwk TEXT NOT NULL,
		contact TEXT,
		status TEXT DEFAULT 'valid',
		terms_agreed BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- 証明書注文
	CREATE TABLE IF NOT EXISTS orders (
		id TEXT PRIMARY KEY,
		account_id TEXT NOT NULL,
		status TEXT DEFAULT 'pending',
		domains TEXT NOT NULL,
		not_before DATETIME,
		not_after DATETIME,
		expires_at DATETIME NOT NULL,
		certificate_url TEXT,
		finalize_url TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);

	-- 発行済み証明書
	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		order_id TEXT NOT NULL,
		account_id TEXT NOT NULL,
		serial_number TEXT UNIQUE NOT NULL,
		domains TEXT NOT NULL,
		certificate_pem TEXT NOT NULL,
		certificate_chain_pem TEXT,
		issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		status TEXT DEFAULT 'valid',
		revoked_at DATETIME,
		revocation_reason INTEGER,
		FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
		FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
	);

	-- ドメイン認証
	CREATE TABLE IF NOT EXISTS authorizations (
		id TEXT PRIMARY KEY,
		order_id TEXT NOT NULL,
		domain TEXT NOT NULL,
		status TEXT DEFAULT 'pending',
		expires_at DATETIME NOT NULL,
		wildcard BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
	);

	-- チャレンジ
	CREATE TABLE IF NOT EXISTS challenges (
		id TEXT PRIMARY KEY,
		authorization_id TEXT NOT NULL,
		type TEXT NOT NULL,
		status TEXT DEFAULT 'pending',
		token TEXT NOT NULL,
		key_authorization TEXT,
		validated_at DATETIME,
		error_detail TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (authorization_id) REFERENCES authorizations(id) ON DELETE CASCADE
	);

	-- Nonce管理
	CREATE TABLE IF NOT EXISTS nonces (
		nonce TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- インデックス作成
	CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
	CREATE INDEX IF NOT EXISTS idx_orders_account_id ON orders(account_id);
	CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
	CREATE INDEX IF NOT EXISTS idx_certificates_account_id ON certificates(account_id);
	CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
	CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON certificates(expires_at);
	CREATE INDEX IF NOT EXISTS idx_nonces_expires_at ON nonces(expires_at);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Run migrations
	return s.runMigrations()
}

// runMigrations handles database schema migrations
func (s *SQLiteStorage) runMigrations() error {
	// Check if finalize_url column exists in orders table
	var columnExists bool
	err := s.db.QueryRow(`
		SELECT COUNT(*) > 0 
		FROM pragma_table_info('orders') 
		WHERE name = 'finalize_url'
	`).Scan(&columnExists)

	if err != nil {
		return fmt.Errorf("failed to check finalize_url column: %w", err)
	}

	// Add finalize_url column if it doesn't exist
	if !columnExists {
		s.logger.Info("Adding finalize_url column to orders table")
		_, err = s.db.Exec(`ALTER TABLE orders ADD COLUMN finalize_url TEXT`)
		if err != nil {
			return fmt.Errorf("failed to add finalize_url column: %w", err)
		}
	}

	// Check if updated_at column exists in certificates table
	var certUpdatedAtExists bool
	err = s.db.QueryRow(`
		SELECT COUNT(*) > 0 
		FROM pragma_table_info('certificates') 
		WHERE name = 'updated_at'
	`).Scan(&certUpdatedAtExists)

	if err != nil {
		return fmt.Errorf("failed to check updated_at column in certificates: %w", err)
	}

	// Add updated_at column to certificates table if it doesn't exist
	if !certUpdatedAtExists {
		s.logger.Info("Adding updated_at column to certificates table")
		// SQLite doesn't allow adding columns with non-constant defaults, so we add without default first
		_, err = s.db.Exec(`ALTER TABLE certificates ADD COLUMN updated_at DATETIME`)
		if err != nil {
			return fmt.Errorf("failed to add updated_at column to certificates: %w", err)
		}

		// Update existing records to have updated_at = issued_at
		_, err = s.db.Exec(`UPDATE certificates SET updated_at = issued_at WHERE updated_at IS NULL`)
		if err != nil {
			return fmt.Errorf("failed to update existing certificates with updated_at: %w", err)
		}
	}

	return nil
}

// Account operations
func (s *SQLiteStorage) StoreAccount(accountID string, account *ServerAccount) error {
	contactJSON, _ := json.Marshal(account.Contact)
	publicKeyJSON, _ := json.Marshal(account.Key)

	query := `
		INSERT OR REPLACE INTO accounts (id, public_key_jwk, contact, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`

	_, err := s.db.Exec(query, accountID, string(publicKeyJSON), string(contactJSON), account.Status, account.CreatedAt)
	if err != nil {
		s.logger.Error("Failed to store account", "account_id", accountID, "error", err)
		return err
	}

	s.logger.Debug("Account stored", "account_id", accountID)
	return nil
}

func (s *SQLiteStorage) GetAccount(accountID string) (*ServerAccount, error) {
	query := `SELECT id, public_key_jwk, contact, status, created_at, updated_at FROM accounts WHERE id = ?`

	var account ServerAccount
	var publicKeyJSON, contactJSON string

	err := s.db.QueryRow(query, accountID).Scan(
		&account.ID,
		&publicKeyJSON,
		&contactJSON,
		&account.Status,
		&account.CreatedAt,
		&account.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}

	// Parse JSON fields
	if err := json.Unmarshal([]byte(publicKeyJSON), &account.Key); err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	if contactJSON != "" {
		if err := json.Unmarshal([]byte(contactJSON), &account.Contact); err != nil {
			return nil, fmt.Errorf("failed to parse contact: %w", err)
		}
	}

	return &account, nil
}

func (s *SQLiteStorage) DeleteAccount(accountID string) error {
	query := `DELETE FROM accounts WHERE id = ?`
	_, err := s.db.Exec(query, accountID)
	return err
}

// Order operations
func (s *SQLiteStorage) StoreOrder(orderID string, order *ServerOrder) error {
	domainsJSON, _ := json.Marshal(order.Identifiers)

	query := `
		INSERT OR REPLACE INTO orders (id, account_id, status, domains, not_before, not_after, expires_at, certificate_url, finalize_url, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	_, err := s.db.Exec(query, orderID, order.AccountID, order.Status, string(domainsJSON),
		order.NotBefore, order.NotAfter, order.Expires, order.Certificate, order.Finalize)

	if err != nil {
		s.logger.Error("Failed to store order", "order_id", orderID, "error", err)
		return err
	}

	s.logger.Debug("Order stored", "order_id", orderID)
	return nil
}

func (s *SQLiteStorage) GetOrder(orderID string) (*ServerOrder, error) {
	query := `SELECT id, account_id, status, domains, not_before, not_after, expires_at, certificate_url, finalize_url FROM orders WHERE id = ?`

	var order ServerOrder
	var domainsJSON string

	err := s.db.QueryRow(query, orderID).Scan(
		&order.ID,
		&order.AccountID,
		&order.Status,
		&domainsJSON,
		&order.NotBefore,
		&order.NotAfter,
		&order.Expires,
		&order.Certificate,
		&order.Finalize,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("order not found")
		}
		return nil, err
	}

	// Parse domains JSON
	if err := json.Unmarshal([]byte(domainsJSON), &order.Identifiers); err != nil {
		return nil, fmt.Errorf("failed to parse domains: %w", err)
	}

	return &order, nil
}

func (s *SQLiteStorage) UpdateOrderStatus(orderID string, status string, certificateURL string) error {
	query := `UPDATE orders SET status = ?, certificate_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := s.db.Exec(query, status, certificateURL, orderID)
	return err
}

func (s *SQLiteStorage) DeleteOrder(orderID string) error {
	query := `DELETE FROM orders WHERE id = ?`
	_, err := s.db.Exec(query, orderID)
	return err
}

// Certificate operations
func (s *SQLiteStorage) StoreCertificate(certID string, certChain []byte) error {
	// Get order information to extract domains and account ID
	var orderID, accountID string
	var domainsJSON string

	// First, try to get order information using certID as orderID
	orderQuery := `SELECT id, account_id, domains FROM orders WHERE id = ?`
	err := s.db.QueryRow(orderQuery, certID).Scan(&orderID, &accountID, &domainsJSON)

	var finalDomainsJSON string = "[]"

	if err == nil {
		// Parse the domains from order format to simple string array
		var orderDomains []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		}

		if err := json.Unmarshal([]byte(domainsJSON), &orderDomains); err == nil {
			var domains []string
			for _, domain := range orderDomains {
				if domain.Type == "dns" {
					domains = append(domains, domain.Value)
				}
			}
			if len(domains) > 0 {
				if domainsBytes, err := json.Marshal(domains); err == nil {
					finalDomainsJSON = string(domainsBytes)
				}
			}
		}
	} else {
		// If not found, use default values
		orderID = certID
		accountID = "unknown"
	}

	// Parse certificate to extract serial number and expiration
	serialNumber := certID                   // Default to certID if parsing fails
	expiresAt := "datetime('now', '+1 day')" // Default expiration

	// Try to parse the certificate for more accurate information
	if block, _ := pem.Decode(certChain); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			serialNumber = cert.SerialNumber.String()
			expiresAt = "'" + cert.NotAfter.Format("2006-01-02 15:04:05") + "'"

			// If we couldn't get domains from order, try to get from certificate
			if finalDomainsJSON == "[]" && len(cert.DNSNames) > 0 {
				if domainsBytes, err := json.Marshal(cert.DNSNames); err == nil {
					finalDomainsJSON = string(domainsBytes)
				}
			}
		}
	}

	query := `
		INSERT OR REPLACE INTO certificates (id, order_id, account_id, serial_number, domains, certificate_pem, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ` + expiresAt + `, CURRENT_TIMESTAMP)
	`

	_, err = s.db.Exec(query, certID, orderID, accountID, serialNumber, finalDomainsJSON, string(certChain))
	return err
}

func (s *SQLiteStorage) GetCertificate(certID string) ([]byte, error) {
	query := `SELECT certificate_pem FROM certificates WHERE id = ?`

	var certPEM string
	err := s.db.QueryRow(query, certID).Scan(&certPEM)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, err
	}

	return []byte(certPEM), nil
}

func (s *SQLiteStorage) DeleteCertificate(certID string) error {
	query := `DELETE FROM certificates WHERE id = ?`
	_, err := s.db.Exec(query, certID)
	return err
}

// Authorization operations
func (s *SQLiteStorage) StoreAuthorization(authzID string, authz *ServerAuthorization) error {
	query := `
		INSERT OR REPLACE INTO authorizations (id, order_id, domain, status, expires_at, wildcard, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	_, err := s.db.Exec(query, authzID, authz.OrderID, authz.Identifier.Value, authz.Status, authz.Expires, false)
	return err
}

func (s *SQLiteStorage) GetAuthorization(authzID string) (*ServerAuthorization, error) {
	query := `SELECT id, order_id, domain, status, expires_at, wildcard FROM authorizations WHERE id = ?`

	var authz ServerAuthorization
	var domain string
	var wildcard bool

	err := s.db.QueryRow(query, authzID).Scan(
		&authz.ID,
		&authz.OrderID,
		&domain,
		&authz.Status,
		&authz.Expires,
		&wildcard,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("authorization not found")
		}
		return nil, err
	}

	authz.Identifier = Identifier{Type: "dns", Value: domain}
	authz.Wildcard = wildcard

	// Get challenges for this authorization
	challengeQuery := `SELECT id, type, status, token, key_authorization, validated_at, error_detail, created_at, updated_at FROM challenges WHERE authorization_id = ?`
	rows, err := s.db.Query(challengeQuery, authzID)
	if err != nil {
		return nil, fmt.Errorf("failed to get challenges: %w", err)
	}
	defer rows.Close()

	var challenges []Challenge
	for rows.Next() {
		var serverChallenge ServerChallenge
		var keyAuth sql.NullString
		var validatedAt sql.NullTime
		var errorDetail sql.NullString

		err := rows.Scan(
			&serverChallenge.ID,
			&serverChallenge.Type,
			&serverChallenge.Status,
			&serverChallenge.Token,
			&keyAuth,
			&validatedAt,
			&errorDetail,
			&serverChallenge.CreatedAt,
			&serverChallenge.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan challenge: %w", err)
		}

		if keyAuth.Valid {
			serverChallenge.KeyAuthorization = keyAuth.String
		}

		if validatedAt.Valid {
			serverChallenge.Validated = &validatedAt.Time
		}

		if errorDetail.Valid && errorDetail.String != "" {
			var problemDetails ProblemDetails
			if err := json.Unmarshal([]byte(errorDetail.String), &problemDetails); err == nil {
				serverChallenge.Error = &problemDetails
			}
		}

		// Convert ServerChallenge to Challenge for client response
		challenge := serverChallenge.Challenge
		// Set the URL using the server challenge ID
		challenge.URL = fmt.Sprintf("%s/acme/chall/%s", s.baseURL, serverChallenge.ID)
		challenges = append(challenges, challenge)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating challenges: %w", err)
	}

	authz.Challenges = challenges

	return &authz, nil
}

func (s *SQLiteStorage) DeleteAuthorization(authzID string) error {
	query := `DELETE FROM authorizations WHERE id = ?`
	_, err := s.db.Exec(query, authzID)
	return err
}

// Challenge operations
func (s *SQLiteStorage) StoreChallenge(challengeID string, challenge *ServerChallenge) error {
	query := `
		INSERT OR REPLACE INTO challenges (id, authorization_id, type, status, token, key_authorization, validated_at, error_detail, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`

	errorJSON, _ := json.Marshal(challenge.Error)

	_, err := s.db.Exec(query, challengeID, challenge.AuthzID, challenge.Type, challenge.Status,
		challenge.Token, challenge.KeyAuthorization, challenge.Validated, string(errorJSON))
	return err
}

func (s *SQLiteStorage) GetChallenge(challengeID string) (*ServerChallenge, error) {
	query := `SELECT id, authorization_id, type, status, token, key_authorization, validated_at, error_detail FROM challenges WHERE id = ?`

	var challenge ServerChallenge
	var errorJSON string

	err := s.db.QueryRow(query, challengeID).Scan(
		&challenge.ID,
		&challenge.AuthzID,
		&challenge.Type,
		&challenge.Status,
		&challenge.Token,
		&challenge.KeyAuthorization,
		&challenge.Validated,
		&errorJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("challenge not found")
		}
		return nil, err
	}

	// Parse error JSON if present
	if errorJSON != "" {
		if err := json.Unmarshal([]byte(errorJSON), &challenge.Error); err != nil {
			s.logger.Warn("Failed to parse challenge error", "error", err)
		}
	}

	// Set the URL for the challenge
	challenge.URL = fmt.Sprintf("%s/acme/chall/%s", s.baseURL, challenge.ID)

	return &challenge, nil
}

func (s *SQLiteStorage) UpdateChallengeStatus(challengeID string, status string) error {
	query := `UPDATE challenges SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := s.db.Exec(query, status, challengeID)
	return err
}

func (s *SQLiteStorage) DeleteChallenge(challengeID string) error {
	query := `DELETE FROM challenges WHERE id = ?`
	_, err := s.db.Exec(query, challengeID)
	return err
}

// Nonce operations
func (s *SQLiteStorage) StoreNonce(nonce string, expiry time.Time) error {
	query := `INSERT INTO nonces (nonce, expires_at) VALUES (?, ?)`
	_, err := s.db.Exec(query, nonce, expiry)
	return err
}

func (s *SQLiteStorage) ValidateAndDeleteNonce(nonce string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check if nonce exists and is not expired
	var expiresAt time.Time
	err = tx.QueryRow("SELECT expires_at FROM nonces WHERE nonce = ?", nonce).Scan(&expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("nonce not found")
		}
		return err
	}

	if time.Now().After(expiresAt) {
		return fmt.Errorf("nonce expired")
	}

	// Delete nonce (one-time use)
	_, err = tx.Exec("DELETE FROM nonces WHERE nonce = ?", nonce)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLiteStorage) CleanupExpiredNonces() error {
	query := `DELETE FROM nonces WHERE expires_at < CURRENT_TIMESTAMP`
	result, err := s.db.Exec(query)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		s.logger.Debug("Cleaned up expired nonces", "count", rowsAffected)
	}

	return nil
}

// Management API methods
func (s *SQLiteStorage) GetAllAccounts() ([]*ServerAccount, error) {
	query := `SELECT id, public_key_jwk, contact, status, created_at, updated_at FROM accounts ORDER BY created_at DESC`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []*ServerAccount
	for rows.Next() {
		var account ServerAccount
		var publicKeyJSON, contactJSON string

		err := rows.Scan(
			&account.ID,
			&publicKeyJSON,
			&contactJSON,
			&account.Status,
			&account.CreatedAt,
			&account.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Parse JSON fields
		if err := json.Unmarshal([]byte(publicKeyJSON), &account.Key); err != nil {
			continue
		}

		if contactJSON != "" {
			json.Unmarshal([]byte(contactJSON), &account.Contact)
		}

		accounts = append(accounts, &account)
	}

	return accounts, nil
}

func (s *SQLiteStorage) GetAllCertificates() ([]*CertificateInfo, error) {
	query := `
		SELECT c.id, c.account_id, c.serial_number, c.domains, c.issued_at, c.expires_at, c.status, c.revoked_at,
		       a.contact
		FROM certificates c
		LEFT JOIN accounts a ON c.account_id = a.id
		ORDER BY c.issued_at DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certificates []*CertificateInfo
	for rows.Next() {
		var cert CertificateInfo
		var domainsJSON, contactJSON sql.NullString

		err := rows.Scan(
			&cert.ID,
			&cert.AccountID,
			&cert.SerialNumber,
			&domainsJSON,
			&cert.IssuedAt,
			&cert.ExpiresAt,
			&cert.Status,
			&cert.RevokedAt,
			&contactJSON,
		)
		if err != nil {
			continue
		}

		// Parse domains JSON
		if domainsJSON.Valid {
			json.Unmarshal([]byte(domainsJSON.String), &cert.Domains)
		}

		// Parse contact JSON
		if contactJSON.Valid {
			json.Unmarshal([]byte(contactJSON.String), &cert.AccountContact)
		}

		certificates = append(certificates, &cert)
	}

	return certificates, nil
}

func (s *SQLiteStorage) RevokeAccount(accountID string) error {
	query := `UPDATE accounts SET status = 'deactivated', updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := s.db.Exec(query, accountID)
	return err
}

func (s *SQLiteStorage) RevokeCertificate(certID string, reason int) error {
	query := `UPDATE certificates SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP, revocation_reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	_, err := s.db.Exec(query, reason, certID)
	return err
}

func (s *SQLiteStorage) GetStatistics() (*Statistics, error) {
	stats := &Statistics{}

	// Count active accounts
	err := s.db.QueryRow("SELECT COUNT(*) FROM accounts WHERE status = 'valid'").Scan(&stats.ActiveAccounts)
	if err != nil {
		return nil, err
	}

	// Count valid certificates
	err = s.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'valid'").Scan(&stats.ValidCertificates)
	if err != nil {
		return nil, err
	}

	// Count expired certificates
	err = s.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE expires_at < CURRENT_TIMESTAMP AND status = 'valid'").Scan(&stats.ExpiredCertificates)
	if err != nil {
		return nil, err
	}

	// Count revoked certificates
	err = s.db.QueryRow("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'").Scan(&stats.RevokedCertificates)
	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *SQLiteStorage) Close() error {
	if err := s.CleanupExpiredNonces(); err != nil {
		s.logger.Warn("Failed to cleanup nonces on close", "error", err)
	}
	return s.db.Close()
}

// Helper types for management interface
type CertificateInfo struct {
	ID             string     `json:"id"`
	AccountID      string     `json:"account_id"`
	SerialNumber   string     `json:"serial_number"`
	Domains        []string   `json:"domains"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	Status         string     `json:"status"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	AccountContact []string   `json:"account_contact,omitempty"`
}

type Statistics struct {
	ActiveAccounts      int `json:"active_accounts"`
	ValidCertificates   int `json:"valid_certificates"`
	ExpiredCertificates int `json:"expired_certificates"`
	RevokedCertificates int `json:"revoked_certificates"`
}
