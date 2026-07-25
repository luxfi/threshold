package test

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	log "github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// Harness provides a complete test environment for protocol testing
type Harness struct {
	t        testing.TB
	ctx      context.Context
	cancel   context.CancelFunc
	network  *Network
	logger   log.Logger
	registry metric.Registry

	// timeout bounds both the harness context and each handler's own
	// ProtocolTimeout. Keeping one value for both is what makes WithTimeout
	// mean anything: the handler config used to hard-code 5 minutes, so
	// raising the harness timeout moved the deadline that fired but not the
	// one inside the handler, and a slow protocol (CGGMP21 DKG under -race)
	// still died at five minutes with a misleading error.
	timeout time.Duration

	mu       sync.RWMutex
	handlers map[party.ID]*protocol.Handler
	results  map[party.ID]interface{}
	errors   map[party.ID]error
}

// DefaultTimeout bounds a harness run unless WithTimeout raises it.
const DefaultTimeout = 5 * time.Minute

// NewHarness creates a new test harness with proper context management.
// Default 5-minute timeout matches the per-handler ProtocolTimeout below;
// `go test ./...` runs many packages in parallel and harness wall-clock can
// stretch under CPU contention even when the protocol itself takes <1s.
func NewHarness(t testing.TB, partyIDs []party.ID) *Harness {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)

	h := &Harness{
		t:        t,
		ctx:      ctx,
		cancel:   cancel,
		network:  NewNetwork(partyIDs),
		logger:   log.NewTestLogger(log.InfoLevel),
		registry: metric.NewRegistry(),
		timeout:  DefaultTimeout,
		handlers: make(map[party.ID]*protocol.Handler),
		results:  make(map[party.ID]interface{}),
		errors:   make(map[party.ID]error),
	}

	if t != nil {
		t.Cleanup(func() {
			h.Cleanup()
		})
	}

	return h
}

// WithTimeout sets the deadline for the harness context and for every handler
// created afterwards. Call it before CreateHandler; handlers already created
// keep the timeout they were built with.
func (h *Harness) WithTimeout(timeout time.Duration) *Harness {
	h.cancel() // Cancel old context
	h.ctx, h.cancel = context.WithTimeout(context.Background(), timeout)
	h.timeout = timeout
	return h
}

// WithLogger sets a custom logger
func (h *Harness) WithLogger(logger log.Logger) *Harness {
	h.logger = logger
	return h
}

// CreateHandler creates a new protocol handler for a party
func (h *Harness) CreateHandler(id party.ID, startFunc protocol.StartFunc, sessionID []byte) (*protocol.Handler, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create a new registry for each handler to avoid conflicts
	registry := metric.NewRegistry()

	// Create config with sensible defaults
	config := &protocol.Config{
		Workers:         4, // Need regular workers for p2p messages!
		PriorityWorkers: 4,
		BufferSize:      10000,
		PriorityBuffer:  1000,
		MessageTimeout:  30 * time.Second,
		RoundTimeout:    60 * time.Second,
		ProtocolTimeout: h.timeout, // the harness owns the deadline; see WithTimeout
	}

	// Use a context without timeout - the harness manages timeouts
	handler, err := protocol.NewHandler(
		context.Background(), // Don't use h.ctx to avoid premature cancellation
		h.logger,
		registry,
		startFunc,
		sessionID,
		config,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create handler for party %s: %w", id, err)
	}

	h.handlers[id] = handler
	return handler, nil
}

// Run executes all handlers concurrently with proper synchronization
func (h *Harness) Run() error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(h.handlers))

	// Start all handler loops
	for id, handler := range h.handlers {
		wg.Add(1)
		go func(partyID party.ID, handler *protocol.Handler) {
			defer wg.Done()

			// Run the handler loop with context awareness
			err := h.runHandlerLoop(partyID, handler)
			if err != nil {
				errChan <- fmt.Errorf("party %s: %w", partyID, err)
			}
		}(id, handler)
	}

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All handlers completed successfully
		close(errChan)

		// Check for any errors
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		if len(errs) > 0 {
			return fmt.Errorf("protocol execution failed: %v", errs)
		}
		return nil

	case <-h.ctx.Done():
		// Context canceled or timed out
		h.cancel() // Ensure all handlers are canceled
		return fmt.Errorf("harness context canceled: %w", h.ctx.Err())
	}
}

// runHandlerLoop runs a single handler with proper message routing
func (h *Harness) runHandlerLoop(id party.ID, handler *protocol.Handler) error {
	// Create done channel for coordinating goroutines
	done := make(chan struct{})
	defer close(done)

	// Start goroutine to handle incoming network messages
	go func() {
		for {
			select {
			case <-done:
				return
			case msg := <-h.network.Next(id):
				if msg != nil {
					fmt.Printf("[HARNESS] %s: RECV msg from %s (round=%d, broadcast=%v)\n",
						id, msg.From, msg.RoundNumber, msg.Broadcast)
					handler.Accept(msg)
				}
			}
		}
	}()

	// Start goroutine to handle outgoing messages
	go func() {
		for {
			select {
			case <-done:
				return
			case msg, ok := <-handler.Listen():
				if !ok {
					// Channel closed, handler completed
					fmt.Printf("[HARNESS] %s: Listen channel closed\n", id)
					return
				}
				if msg != nil {
					fmt.Printf("[HARNESS] %s: SEND msg to %s (round=%d, broadcast=%v)\n",
						id, msg.To, msg.RoundNumber, msg.Broadcast)
					h.network.Send(msg)
				}
			}
		}
	}()

	// Wait for handler to complete
	result, err := handler.WaitForResult()
	h.mu.Lock()
	h.results[id] = result
	h.errors[id] = err
	h.mu.Unlock()

	// Don't call network.Done() - it causes deadlocks
	return err
}

// Result returns the result for a specific party
func (h *Harness) Result(id party.ID) (interface{}, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result, ok := h.results[id]
	if !ok {
		return nil, fmt.Errorf("no result for party %s", id)
	}

	err := h.errors[id]
	return result, err
}

// Results returns all results
func (h *Harness) Results() map[party.ID]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	results := make(map[party.ID]interface{})
	for id, result := range h.results {
		results[id] = result
	}
	return results
}

// Errors returns all errors
func (h *Harness) Errors() map[party.ID]error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	errors := make(map[party.ID]error)
	for id, err := range h.errors {
		if err != nil {
			errors[id] = err
		}
	}
	return errors
}

// Cleanup releases all resources
func (h *Harness) Cleanup() {
	h.cancel()

	// Close all handlers
	h.mu.Lock()
	for _, handler := range h.handlers {
		// Handler cleanup is handled by context cancellation
		_ = handler
	}
	h.handlers = nil
	h.mu.Unlock()
}

// RunProtocol is a convenience function to run a protocol with all parties,
// bounded by DefaultTimeout.
func RunProtocol(t testing.TB, partyIDs []party.ID, sessionID []byte, createStart func(party.ID) protocol.StartFunc) (map[party.ID]interface{}, error) {
	return RunProtocolWithTimeout(t, partyIDs, sessionID, DefaultTimeout, createStart)
}

// RunProtocolWithTimeout is RunProtocol with an explicit deadline, for
// protocols that legitimately need longer than DefaultTimeout — a full
// CGGMP21 key generation builds Paillier moduli and their ring-mod proofs for
// every party, which under the race detector runs well past five minutes.
func RunProtocolWithTimeout(t testing.TB, partyIDs []party.ID, sessionID []byte, timeout time.Duration, createStart func(party.ID) protocol.StartFunc) (map[party.ID]interface{}, error) {
	harness := NewHarness(t, partyIDs).WithTimeout(timeout)

	// If no session ID provided, generate a unique one
	if sessionID == nil {
		sessionID = []byte(fmt.Sprintf("session-%d-%d", time.Now().UnixNano(), rand.Int63()))
	}

	// Create handlers for all parties
	for _, id := range partyIDs {
		startFunc := createStart(id)
		_, err := harness.CreateHandler(id, startFunc, sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to create handler for party %s: %w", id, err)
		}
	}

	// Run the protocol
	if err := harness.Run(); err != nil {
		return nil, err
	}

	// Return all results
	return harness.Results(), nil
}
