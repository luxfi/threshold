// Package common provides shared types for threshold signature protocols
package common

import (
	"time"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Runtime contains immutable runtime metadata for protocol execution
type Runtime struct {
	// Session identification
	SessionID []byte
	
	// Party information
	SelfID    party.ID
	PartyIDs  []party.ID
	Threshold int
	
	// Cryptographic parameters
	Group curve.Curve
	
	// Protocol-specific data
	ProtocolID string
	Generation uint64
}

// Config contains protocol configuration parameters
type Config struct {
	// Timing parameters
	MaxRounds      int
	RoundTimeout   time.Duration
	MessageTimeout time.Duration
	
	// Network parameters
	MaxRetries     int
	RetryDelay     time.Duration
	
	// Security parameters
	EnableAbortIdentification bool
	EnableStateRollback       bool
	
	// Performance parameters
	ParallelOperations int
}

// Deps contains external dependencies for protocol execution
type Deps struct {
	// Core dependencies
	Pool    *pool.Pool
	Network protocol.Network
	
	// Optional dependencies
	Storage Storage        // For persistence
	Logger  Logger         // For logging
	Metrics MetricsCollector // For monitoring
}

// Storage interface for state persistence
type Storage interface {
	Save(key string, value []byte) error
	Load(key string) ([]byte, error)
	Delete(key string) error
	List(prefix string) ([]string, error)
}

// Logger interface for protocol logging
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
}

// MetricsCollector interface for protocol metrics
type MetricsCollector interface {
	RecordRoundLatency(protocol string, round int, duration time.Duration)
	RecordMessageCount(protocol string, msgType string, count int)
	RecordError(protocol string, errorType string)
	RecordSuccess(protocol string)
}

// DefaultConfig returns sensible default configuration
func DefaultConfig() Config {
	return Config{
		MaxRounds:                 100,
		RoundTimeout:              30 * time.Second,
		MessageTimeout:            5 * time.Second,
		MaxRetries:                3,
		RetryDelay:                time.Second,
		EnableAbortIdentification: true,
		EnableStateRollback:       true,
		ParallelOperations:        4,
	}
}

// ValidateRuntime checks if runtime parameters are valid
func ValidateRuntime(rt Runtime) error {
	if rt.SessionID == nil || len(rt.SessionID) == 0 {
		return ErrInvalidSessionID
	}
	if rt.SelfID == "" {
		return ErrInvalidSelfID
	}
	if len(rt.PartyIDs) < 2 {
		return ErrInsufficientParties
	}
	if rt.Threshold < 1 || rt.Threshold > len(rt.PartyIDs) {
		return ErrInvalidThreshold
	}
	if rt.Group == nil {
		return ErrInvalidGroup
	}
	return nil
}

// Errors
var (
	ErrInvalidSessionID    = protocol.NewError(1, nil, "invalid session ID")
	ErrInvalidSelfID       = protocol.NewError(2, nil, "invalid self ID")
	ErrInsufficientParties = protocol.NewError(3, nil, "insufficient parties")
	ErrInvalidThreshold    = protocol.NewError(4, nil, "invalid threshold")
	ErrInvalidGroup        = protocol.NewError(5, nil, "invalid group")
)