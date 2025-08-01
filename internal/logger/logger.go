package logger

import (
	"log/slog"
	"os"
)

// Log level constants
const (
	DebugLevel = slog.LevelDebug
	InfoLevel  = slog.LevelInfo
	ErrorLevel = slog.LevelError
)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
	handler slog.Handler
	level   slog.Level
}

// New creates a new logger instance
func New() *Logger {
	return NewWithLevel(slog.LevelInfo)
}

// NewWithLevel creates a new logger with specified level
func NewWithLevel(level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &Logger{
		Logger:  logger,
		handler: handler,
		level:   level,
	}
}

// Fatal logs a fatal error and exits the program
func (l *Logger) Fatal(msg string, args ...any) {
	l.Error(msg, args...)
	os.Exit(1)
}

// WithComponent returns a logger with a component field
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger:  l.With("component", component),
		handler: l.handler,
		level:   l.level,
	}
}

// WithError returns a logger with an error field
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger:  l.With("error", err),
		handler: l.handler,
		level:   l.level,
	}
}

// SetLevel sets the log level for the logger
func (l *Logger) SetLevel(level slog.Level) {
	opts := &slog.HandlerOptions{
		Level: level,
	}

	l.handler = slog.NewTextHandler(os.Stdout, opts)
	l.Logger = slog.New(l.handler)
	l.level = level
}
