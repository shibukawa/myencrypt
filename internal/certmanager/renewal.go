package certmanager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// RenewalManager manages automatic certificate renewal
type RenewalManager struct {
	certManager Manager
	logger      logger.Logger
	
	// Renewal configuration
	checkInterval    time.Duration
	renewalThreshold time.Duration
	maxRetries       int
	retryDelay       time.Duration
	
	// Runtime state
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	mu         sync.RWMutex
	
	// Tracking
	renewalQueue    map[string]*RenewalTask
	lastCheck       time.Time
	renewalStats    RenewalStats
}

// RenewalTask represents a certificate renewal task
type RenewalTask struct {
	Domain       string
	Certificate  *Certificate
	NextAttempt  time.Time
	Attempts     int
	LastError    error
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RenewalStats tracks renewal statistics
type RenewalStats struct {
	TotalRenewals    int64
	SuccessfulRenewals int64
	FailedRenewals   int64
	LastRenewalTime  time.Time
	LastFailureTime  time.Time
	LastFailureError string
}

// RenewalConfig holds renewal configuration
type RenewalConfig struct {
	CheckInterval    time.Duration // How often to check for renewals
	RenewalThreshold time.Duration // Renew when certificate expires within this time
	MaxRetries       int           // Maximum retry attempts
	RetryDelay       time.Duration // Delay between retries
}

// DefaultRenewalConfig returns default renewal configuration
func DefaultRenewalConfig() RenewalConfig {
	return RenewalConfig{
		CheckInterval:    30 * time.Minute, // Check every 30 minutes
		RenewalThreshold: 6 * time.Hour,    // Renew when 6 hours left (certificates are valid for 24h)
		MaxRetries:       3,                // Retry up to 3 times
		RetryDelay:       5 * time.Minute,  // Wait 5 minutes between retries
	}
}

// NewRenewalManager creates a new renewal manager
func NewRenewalManager(certManager Manager, logger logger.Logger, config RenewalConfig) *RenewalManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &RenewalManager{
		certManager:      certManager,
		logger:           logger,
		checkInterval:    config.CheckInterval,
		renewalThreshold: config.RenewalThreshold,
		maxRetries:       config.MaxRetries,
		retryDelay:       config.RetryDelay,
		ctx:              ctx,
		cancel:           cancel,
		renewalQueue:     make(map[string]*RenewalTask),
	}
}

// Start begins the automatic renewal process
func (rm *RenewalManager) Start(ctx context.Context) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.logger.Info("Starting certificate renewal manager", 
		"check_interval", rm.checkInterval,
		"renewal_threshold", rm.renewalThreshold,
		"max_retries", rm.maxRetries)
	
	// Create a new context that can be cancelled
	renewalCtx, cancel := context.WithCancel(ctx)
	rm.ctx = renewalCtx
	rm.cancel = cancel
	
	rm.wg.Add(1)
	go rm.renewalLoop()
	
	return nil
}

// Stop stops the automatic renewal process
func (rm *RenewalManager) Stop() error {
	rm.logger.Info("Stopping certificate renewal manager")
	
	rm.cancel()
	rm.wg.Wait()
	
	rm.logger.Info("Certificate renewal manager stopped")
	return nil
}

// renewalLoop is the main renewal loop
func (rm *RenewalManager) renewalLoop() {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(rm.checkInterval)
	defer ticker.Stop()
	
	// Initial check
	rm.checkForRenewals()
	
	for {
		select {
		case <-rm.ctx.Done():
			rm.logger.Info("Renewal loop stopping")
			return
		case <-ticker.C:
			rm.checkForRenewals()
		}
	}
}

// checkForRenewals checks all certificates and queues renewals as needed
func (rm *RenewalManager) checkForRenewals() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.lastCheck = time.Now()
	rm.logger.Debug("Checking certificates for renewal")
	
	// Get all certificates from the certificate manager
	certificates, err := rm.getAllCertificates()
	if err != nil {
		rm.logger.Error("Failed to get certificates for renewal check", "error", err)
		return
	}
	
	renewalCount := 0
	for domain, cert := range certificates {
		if rm.needsRenewal(cert) {
			if rm.queueRenewal(domain, cert) {
				renewalCount++
			}
		}
	}
	
	if renewalCount > 0 {
		rm.logger.Info("Queued certificates for renewal", "count", renewalCount)
	}
	
	// Process renewal queue
	rm.processRenewalQueue()
}

// getAllCertificates gets all certificates from the certificate manager
func (rm *RenewalManager) getAllCertificates() (map[string]*Certificate, error) {
	return rm.certManager.ListCertificates()
}

// needsRenewal checks if a certificate needs renewal
func (rm *RenewalManager) needsRenewal(cert *Certificate) bool {
	if cert == nil || cert.Certificate == nil {
		return false
	}
	
	// Check if certificate expires within the renewal threshold
	timeUntilExpiry := time.Until(cert.Certificate.NotAfter)
	needsRenewal := timeUntilExpiry <= rm.renewalThreshold
	
	if needsRenewal {
		rm.logger.Debug("Certificate needs renewal",
			"expires_at", cert.Certificate.NotAfter,
			"time_until_expiry", timeUntilExpiry,
			"renewal_threshold", rm.renewalThreshold)
	}
	
	return needsRenewal
}

// queueRenewal adds a certificate to the renewal queue
func (rm *RenewalManager) queueRenewal(domain string, cert *Certificate) bool {
	// Check if already queued
	if task, exists := rm.renewalQueue[domain]; exists {
		// Update existing task
		task.Certificate = cert
		task.UpdatedAt = time.Now()
		rm.logger.Debug("Updated renewal task", "domain", domain)
		return false
	}
	
	// Create new renewal task
	task := &RenewalTask{
		Domain:      domain,
		Certificate: cert,
		NextAttempt: time.Now(),
		Attempts:    0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	rm.renewalQueue[domain] = task
	rm.logger.Info("Queued certificate for renewal", "domain", domain)
	return true
}

// processRenewalQueue processes all pending renewal tasks
func (rm *RenewalManager) processRenewalQueue() {
	rm.logger.Debug("processRenewalQueue - START")
	now := time.Now()
	
	rm.logger.Debug("Processing renewal queue", "queue_size", len(rm.renewalQueue))
	for domain, task := range rm.renewalQueue {
		rm.logger.Debug("Processing renewal task", "domain", domain, "attempts", task.Attempts)
		
		// Check if it's time to attempt renewal
		if now.Before(task.NextAttempt) {
			rm.logger.Debug("Not time for renewal yet", "domain", domain, "next_attempt", task.NextAttempt)
			continue
		}
		
		// Check if we've exceeded max retries
		if task.Attempts >= rm.maxRetries {
			rm.logger.Error("Certificate renewal failed after max retries",
				"domain", domain,
				"attempts", task.Attempts,
				"last_error", task.LastError)
			
			rm.renewalStats.FailedRenewals++
			rm.renewalStats.LastFailureTime = now
			if task.LastError != nil {
				rm.renewalStats.LastFailureError = task.LastError.Error()
			}
			
			// Remove from queue
			delete(rm.renewalQueue, domain)
			continue
		}
		
		// Attempt renewal
		rm.logger.Info("Attempting certificate renewal",
			"domain", domain,
			"attempt", task.Attempts+1,
			"max_attempts", rm.maxRetries)
		
		rm.logger.Debug("Calling renewCertificate", "domain", domain)
		err := rm.renewCertificate(domain, task)
		rm.logger.Debug("renewCertificate returned", "domain", domain, "error", err)
		
		task.Attempts++
		task.UpdatedAt = now
		
		if err != nil {
			task.LastError = err
			task.NextAttempt = now.Add(rm.retryDelay)
			
			rm.logger.Error("Certificate renewal attempt failed",
				"domain", domain,
				"attempt", task.Attempts,
				"error", err,
				"next_attempt", task.NextAttempt)
		} else {
			// Renewal successful
			rm.logger.Info("Certificate renewal successful", "domain", domain)
			
			rm.renewalStats.SuccessfulRenewals++
			rm.renewalStats.LastRenewalTime = now
			
			// Remove from queue
			delete(rm.renewalQueue, domain)
		}
		
		rm.renewalStats.TotalRenewals++
	}
}

// renewCertificate performs the actual certificate renewal
func (rm *RenewalManager) renewCertificate(domain string, task *RenewalTask) error {
	rm.logger.Debug("renewCertificate - START", "domain", domain)
	
	// Generate new certificate
	rm.logger.Debug("Generating new certificate", "domain", domain)
	newCert, err := rm.certManager.GenerateCertificate(domain)
	if err != nil {
		rm.logger.Debug("Failed to generate certificate", "domain", domain, "error", err)
		return fmt.Errorf("failed to generate new certificate: %w", err)
	}
	rm.logger.Debug("Certificate generated successfully", "domain", domain)
	
	// Validate the new certificate
	rm.logger.Debug("Validating new certificate", "domain", domain)
	if err := rm.certManager.ValidateCertificate(newCert); err != nil {
		rm.logger.Debug("Certificate validation failed", "domain", domain, "error", err)
		return fmt.Errorf("new certificate validation failed: %w", err)
	}
	rm.logger.Debug("Certificate validated successfully", "domain", domain)
	
	rm.logger.Info("Certificate renewed successfully",
		"domain", domain,
		"expires_at", newCert.Certificate.NotAfter,
		"valid_for", time.Until(newCert.Certificate.NotAfter))
	
	rm.logger.Debug("renewCertificate - END", "domain", domain)
	return nil
}

// GetRenewalStats returns current renewal statistics
func (rm *RenewalManager) GetRenewalStats() RenewalStats {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	return rm.renewalStats
}

// GetRenewalQueue returns current renewal queue status
func (rm *RenewalManager) GetRenewalQueue() map[string]RenewalTask {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	queue := make(map[string]RenewalTask)
	for domain, task := range rm.renewalQueue {
		queue[domain] = *task // Copy task
	}
	
	return queue
}

// ForceRenewal forces immediate renewal of a specific domain
func (rm *RenewalManager) ForceRenewal(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.logger.Info("Forcing certificate renewal", "domain", domain)
	
	// Create a dummy task for forced renewal
	task := &RenewalTask{
		Domain:      domain,
		NextAttempt: time.Now(),
		Attempts:    0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	
	return rm.renewCertificate(domain, task)
}

// GetLastCheckTime returns the time of the last renewal check
func (rm *RenewalManager) GetLastCheckTime() time.Time {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	return rm.lastCheck
}
