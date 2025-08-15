package test

import (
	"context"
	"testing"
	"time"
)

// TestConfig provides standardized configuration for all protocol tests
type TestConfig struct {
	// Timeouts
	MessageTimeout  time.Duration
	RoundTimeout    time.Duration
	ProtocolTimeout time.Duration
	TestTimeout     time.Duration

	// Concurrency
	Workers         int
	PriorityWorkers int
	BufferSize      int
	PriorityBuffer  int

	// Network
	UseZMQ   bool
	BasePort int

	// Debug
	EnableLogging bool
	LogLevel      string
}

// DefaultTestConfig returns sensible defaults for unit tests
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		// Reasonable timeouts for unit tests
		MessageTimeout:  5 * time.Second,
		RoundTimeout:    10 * time.Second,
		ProtocolTimeout: 30 * time.Second,
		TestTimeout:     60 * time.Second,

		// Sufficient concurrency
		Workers:         4,
		PriorityWorkers: 4,
		BufferSize:      10000,
		PriorityBuffer:  1000,

		// Local network
		UseZMQ:   false,
		BasePort: 50000,

		// Debug off by default
		EnableLogging: false,
		LogLevel:      "info",
	}
}

// IntegrationTestConfig returns config for integration tests
func IntegrationTestConfig() *TestConfig {
	cfg := DefaultTestConfig()
	// Longer timeouts for integration tests
	cfg.MessageTimeout = 10 * time.Second
	cfg.RoundTimeout = 30 * time.Second
	cfg.ProtocolTimeout = 90 * time.Second
	cfg.TestTimeout = 120 * time.Second
	return cfg
}

// BenchmarkConfig returns config optimized for benchmarks
func BenchmarkConfig() *TestConfig {
	cfg := DefaultTestConfig()
	// Shorter timeouts for benchmarks
	cfg.MessageTimeout = 2 * time.Second
	cfg.RoundTimeout = 5 * time.Second
	cfg.ProtocolTimeout = 20 * time.Second
	cfg.TestTimeout = 60 * time.Second
	// More workers for performance
	cfg.Workers = 8
	cfg.PriorityWorkers = 8
	return cfg
}

// WithContext creates a context with the test timeout
func (c *TestConfig) WithContext(t testing.TB) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), c.TestTimeout)
	if t != nil {
		t.Cleanup(cancel)
	}
	return ctx, cancel
}

// Apply applies config to environment variables if needed
func (c *TestConfig) Apply() {
	// Can set environment variables here if needed
	// For example, for ZMQ configuration
}
