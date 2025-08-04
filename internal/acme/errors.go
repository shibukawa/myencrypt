package acme

import (
	"fmt"
	"time"
	
	"github.com/shibukawayoshiki/myencrypt2/internal/logger"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity int

const (
	ErrorSeverityLow ErrorSeverity = iota
	ErrorSeverityMedium
	ErrorSeverityHigh
	ErrorSeverityCritical
)

func (s ErrorSeverity) String() string {
	switch s {
	case ErrorSeverityLow:
		return "low"
	case ErrorSeverityMedium:
		return "medium"
	case ErrorSeverityHigh:
		return "high"
	case ErrorSeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ErrorCategory represents the category of an error
type ErrorCategory int

const (
	ErrorCategoryACME ErrorCategory = iota
	ErrorCategoryCertificate
	ErrorCategoryStorage
	ErrorCategoryNetwork
	ErrorCategoryConfiguration
	ErrorCategoryRenewal
)

func (c ErrorCategory) String() string {
	switch c {
	case ErrorCategoryACME:
		return "acme"
	case ErrorCategoryCertificate:
		return "certificate"
	case ErrorCategoryStorage:
		return "storage"
	case ErrorCategoryNetwork:
		return "network"
	case ErrorCategoryConfiguration:
		return "configuration"
	case ErrorCategoryRenewal:
		return "renewal"
	default:
		return "unknown"
	}
}

// ACMEError represents a structured error with additional context
type ACMEError struct {
	Code        string
	Message     string
	Details     string
	Severity    ErrorSeverity
	Category    ErrorCategory
	Timestamp   time.Time
	Context     map[string]interface{}
	Underlying  error
}

// Error implements the error interface
func (e *ACMEError) Error() string {
	if e.Underlying != nil {
		return fmt.Sprintf("%s: %s (underlying: %v)", e.Code, e.Message, e.Underlying)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *ACMEError) Unwrap() error {
	return e.Underlying
}

// NewACMEError creates a new ACME error
func NewACMEError(code, message string, severity ErrorSeverity, category ErrorCategory) *ACMEError {
	return &ACMEError{
		Code:      code,
		Message:   message,
		Severity:  severity,
		Category:  category,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
	}
}

// WithDetails adds details to the error
func (e *ACMEError) WithDetails(details string) *ACMEError {
	e.Details = details
	return e
}

// WithContext adds context to the error
func (e *ACMEError) WithContext(key string, value interface{}) *ACMEError {
	e.Context[key] = value
	return e
}

// WithUnderlying adds an underlying error
func (e *ACMEError) WithUnderlying(err error) *ACMEError {
	e.Underlying = err
	return e
}

// Common ACME errors
var (
	ErrAccountNotFound = NewACMEError(
		"ACCOUNT_NOT_FOUND",
		"Account not found",
		ErrorSeverityMedium,
		ErrorCategoryACME,
	)
	
	ErrOrderNotFound = NewACMEError(
		"ORDER_NOT_FOUND",
		"Order not found",
		ErrorSeverityMedium,
		ErrorCategoryACME,
	)
	
	ErrChallengeNotFound = NewACMEError(
		"CHALLENGE_NOT_FOUND",
		"Challenge not found",
		ErrorSeverityMedium,
		ErrorCategoryACME,
	)
	
	ErrInvalidCSR = NewACMEError(
		"INVALID_CSR",
		"Invalid Certificate Signing Request",
		ErrorSeverityHigh,
		ErrorCategoryCertificate,
	)
	
	ErrCertificateGeneration = NewACMEError(
		"CERTIFICATE_GENERATION_FAILED",
		"Failed to generate certificate",
		ErrorSeverityCritical,
		ErrorCategoryCertificate,
	)
	
	ErrStorageFailure = NewACMEError(
		"STORAGE_FAILURE",
		"Storage operation failed",
		ErrorSeverityHigh,
		ErrorCategoryStorage,
	)
	
	ErrRenewalFailure = NewACMEError(
		"RENEWAL_FAILURE",
		"Certificate renewal failed",
		ErrorSeverityHigh,
		ErrorCategoryRenewal,
	)
	
	ErrConfigurationInvalid = NewACMEError(
		"CONFIGURATION_INVALID",
		"Invalid configuration",
		ErrorSeverityCritical,
		ErrorCategoryConfiguration,
	)
)

// ErrorHandler handles and processes errors
type ErrorHandler struct {
	logger    logger.Logger
	alerter   Alerter
	metrics   *ErrorMetrics
}

// ErrorMetrics tracks error statistics
type ErrorMetrics struct {
	TotalErrors      int64
	ErrorsByCategory map[ErrorCategory]int64
	ErrorsBySeverity map[ErrorSeverity]int64
	LastError        *ACMEError
	LastErrorTime    time.Time
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger logger.Logger, alerter Alerter) *ErrorHandler {
	return &ErrorHandler{
		logger:  logger,
		alerter: alerter,
		metrics: &ErrorMetrics{
			ErrorsByCategory: make(map[ErrorCategory]int64),
			ErrorsBySeverity: make(map[ErrorSeverity]int64),
		},
	}
}

// HandleError processes an error with appropriate logging and alerting
func (eh *ErrorHandler) HandleError(err error) {
	if err == nil {
		return
	}
	
	var acmeErr *ACMEError
	if e, ok := err.(*ACMEError); ok {
		acmeErr = e
	} else {
		// Wrap regular errors
		acmeErr = NewACMEError(
			"UNKNOWN_ERROR",
			err.Error(),
			ErrorSeverityMedium,
			ErrorCategoryACME,
		).WithUnderlying(err)
	}
	
	// Update metrics
	eh.updateMetrics(acmeErr)
	
	// Log the error
	eh.logError(acmeErr)
	
	// Send alerts for high severity errors
	if acmeErr.Severity >= ErrorSeverityHigh {
		eh.sendAlert(acmeErr)
	}
}

// updateMetrics updates error metrics
func (eh *ErrorHandler) updateMetrics(err *ACMEError) {
	eh.metrics.TotalErrors++
	eh.metrics.ErrorsByCategory[err.Category]++
	eh.metrics.ErrorsBySeverity[err.Severity]++
	eh.metrics.LastError = err
	eh.metrics.LastErrorTime = err.Timestamp
}

// logError logs an error with appropriate level
func (eh *ErrorHandler) logError(err *ACMEError) {
	fields := []interface{}{
		"error_code", err.Code,
		"severity", err.Severity.String(),
		"category", err.Category.String(),
		"timestamp", err.Timestamp,
	}
	
	// Add context fields
	for key, value := range err.Context {
		fields = append(fields, key, value)
	}
	
	if err.Details != "" {
		fields = append(fields, "details", err.Details)
	}
	
	if err.Underlying != nil {
		fields = append(fields, "underlying_error", err.Underlying.Error())
	}
	
	switch err.Severity {
	case ErrorSeverityLow:
		eh.logger.Debug(err.Message, fields...)
	case ErrorSeverityMedium:
		eh.logger.Info(err.Message, fields...)
	case ErrorSeverityHigh:
		eh.logger.Warn(err.Message, fields...)
	case ErrorSeverityCritical:
		eh.logger.Error(err.Message, fields...)
	}
}

// sendAlert sends an alert for high severity errors
func (eh *ErrorHandler) sendAlert(err *ACMEError) {
	if eh.alerter != nil {
		eh.alerter.SendAlert(err)
	}
}

// GetMetrics returns current error metrics
func (eh *ErrorHandler) GetMetrics() ErrorMetrics {
	return *eh.metrics
}

// Alerter interface for sending alerts
type Alerter interface {
	SendAlert(err *ACMEError) error
}

// LogAlerter implements Alerter by logging alerts
type LogAlerter struct {
	logger logger.Logger
}

// NewLogAlerter creates a new log-based alerter
func NewLogAlerter(logger logger.Logger) *LogAlerter {
	return &LogAlerter{logger: logger}
}

// SendAlert sends an alert by logging it
func (la *LogAlerter) SendAlert(err *ACMEError) error {
	la.logger.Error("ALERT: High severity error occurred",
		"error_code", err.Code,
		"message", err.Message,
		"severity", err.Severity.String(),
		"category", err.Category.String(),
		"timestamp", err.Timestamp,
		"details", err.Details,
	)
	return nil
}

// RecoveryHandler handles panic recovery
func RecoveryHandler(logger logger.Logger) func() {
	return func() {
		if r := recover(); r != nil {
			err := NewACMEError(
				"PANIC_RECOVERED",
				fmt.Sprintf("Panic recovered: %v", r),
				ErrorSeverityCritical,
				ErrorCategoryACME,
			)
			
			logger.Error("Panic recovered", 
				"panic", r,
				"error_code", err.Code,
				"severity", err.Severity.String(),
			)
		}
	}
}
