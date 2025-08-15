package test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/log/level"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

// ProtocolRunner provides a reliable way to run protocol tests
type ProtocolRunner struct {
	t        testing.TB
	config   *TestConfig
	network  *Network
	logger   log.Logger
	registry *prometheus.Registry

	mu       sync.RWMutex
	handlers map[party.ID]*protocol.Handler
	results  map[party.ID]interface{}
	errors   map[party.ID]error
}

// NewRunner creates a new protocol runner with the given config
func NewRunner(t testing.TB, config *TestConfig) *ProtocolRunner {
	if config == nil {
		config = DefaultTestConfig()
	}

	var logger log.Logger
	if config.EnableLogging {
		logger = log.NewTestLogger(level.Info)
	} else {
		logger = log.NewTestLogger(level.Error) // Use Error level to suppress most logs
	}

	return &ProtocolRunner{
		t:        t,
		config:   config,
		logger:   logger,
		registry: prometheus.NewRegistry(),
		handlers: make(map[party.ID]*protocol.Handler),
		results:  make(map[party.ID]interface{}),
		errors:   make(map[party.ID]error),
	}
}

// SetupParties initializes the network and handlers for the given parties
func (r *ProtocolRunner) SetupParties(partyIDs []party.ID, startFuncs map[party.ID]protocol.StartFunc, sessionID []byte) error {
	r.network = NewNetwork(partyIDs)

	// Create protocol config from test config
	protocolConfig := &protocol.Config{
		Workers:         r.config.Workers,
		PriorityWorkers: r.config.PriorityWorkers,
		BufferSize:      r.config.BufferSize,
		PriorityBuffer:  r.config.PriorityBuffer,
		MessageTimeout:  r.config.MessageTimeout,
		RoundTimeout:    r.config.RoundTimeout,
		ProtocolTimeout: r.config.ProtocolTimeout,
	}

	// Create handlers for each party
	for id, startFunc := range startFuncs {
		// Each handler needs its own registry to avoid duplicate registration
		registry := prometheus.NewRegistry()

		handler, err := protocol.NewHandler(
			context.Background(), // Don't use timeout context here
			r.logger,
			registry,
			startFunc,
			sessionID,
			protocolConfig,
		)
		if err != nil {
			return fmt.Errorf("failed to create handler for %s: %w", id, err)
		}
		r.handlers[id] = handler
	}

	return nil
}

// Run executes the protocol with proper synchronization and timeout handling
func (r *ProtocolRunner) Run() error {
	ctx, cancel := r.config.WithContext(r.t)
	defer cancel()

	var wg sync.WaitGroup
	errChan := make(chan error, len(r.handlers))
	resultChan := make(chan struct {
		id     party.ID
		result interface{}
		err    error
	}, len(r.handlers))

	// Start handler loops
	for id, handler := range r.handlers {
		wg.Add(1)
		go func(partyID party.ID, h *protocol.Handler) {
			defer wg.Done()

			// Run handler with message routing
			err := r.runHandler(ctx, partyID, h)

			// Get result or error
			var result interface{}
			if err == nil {
				result, err = h.Result()
			}

			resultChan <- struct {
				id     party.ID
				result interface{}
				err    error
			}{id: partyID, result: result, err: err}

		}(id, handler)
	}

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Collect results with timeout
	select {
	case <-done:
		// All handlers completed
		close(resultChan)
		close(errChan)

		// Collect results
		for res := range resultChan {
			if res.err != nil {
				r.errors[res.id] = res.err
			} else {
				r.results[res.id] = res.result
			}
		}

		// Check for errors
		if len(r.errors) > 0 {
			return fmt.Errorf("protocol failed for %d parties: %v", len(r.errors), r.errors)
		}

		return nil

	case <-ctx.Done():
		// Timeout occurred
		cancel()

		// Give handlers a moment to clean up
		time.Sleep(100 * time.Millisecond)

		return fmt.Errorf("protocol timed out after %v", r.config.TestTimeout)
	}
}

// runHandler runs a single handler with proper message routing
func (r *ProtocolRunner) runHandler(ctx context.Context, id party.ID, handler *protocol.Handler) error {
	// Create a sub-context for this handler
	handlerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Channel for coordinating shutdown
	done := make(chan struct{})
	defer close(done)

	// Route incoming messages
	go func() {
		defer func() {
			// Ensure no panic escapes
			if p := recover(); p != nil {
				r.logger.Debug("recovered from panic in incoming message handler",
					log.Any("panic", p), log.String("party", string(id)))
			}
		}()

		for {
			select {
			case <-done:
				return
			case <-handlerCtx.Done():
				return
			case msg := <-r.network.Next(id):
				if msg != nil {
					select {
					case <-handlerCtx.Done():
						return
					default:
						handler.Accept(msg)
					}
				}
			}
		}
	}()

	// Route outgoing messages
	go func() {
		defer func() {
			// Ensure no panic escapes
			if p := recover(); p != nil {
				r.logger.Debug("recovered from panic in outgoing message handler",
					log.Any("panic", p), log.String("party", string(id)))
			}
		}()

		for {
			select {
			case <-done:
				return
			case <-handlerCtx.Done():
				return
			case msg := <-handler.Listen():
				if msg == nil {
					return // Handler finished
				}
				select {
				case <-handlerCtx.Done():
					return
				default:
					r.network.Send(msg)
				}
			}
		}
	}()

	// Wait for handler to complete or context to cancel
	resultChan := make(chan error, 1)
	go func() {
		_, err := handler.WaitForResult()
		resultChan <- err
	}()

	select {
	case err := <-resultChan:
		cancel() // Clean up goroutines
		return err
	case <-handlerCtx.Done():
		// Give handler a moment to clean up
		select {
		case err := <-resultChan:
			return err
		case <-time.After(100 * time.Millisecond):
			return handlerCtx.Err()
		}
	}
}

// Results returns the results from all parties
func (r *ProtocolRunner) Results() map[party.ID]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	results := make(map[party.ID]interface{})
	for id, result := range r.results {
		results[id] = result
	}
	return results
}

// Errors returns any errors that occurred
func (r *ProtocolRunner) Errors() map[party.ID]error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	errors := make(map[party.ID]error)
	for id, err := range r.errors {
		errors[id] = err
	}
	return errors
}

// Cleanup cleans up resources
func (r *ProtocolRunner) Cleanup() {
	// Clean up handlers
	for _, h := range r.handlers {
		// Handler cleanup if needed
		_ = h
	}

	// Clean up network
	if r.network != nil {
		// Network cleanup if needed
	}
}
