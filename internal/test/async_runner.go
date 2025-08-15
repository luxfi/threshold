package test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/log/level"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

// AsyncRunner provides fully async, thread-safe protocol execution
type AsyncRunner struct {
	t         testing.TB
	config    *TestConfig
	network   NetworkInterface
	logger    log.Logger
	handlers  sync.Map // party.ID -> *HandlerState
	results   sync.Map // party.ID -> interface{}
	errors    sync.Map // party.ID -> error
	completed atomic.Int32
	total     int32
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// HandlerState tracks individual handler state
type HandlerState struct {
	handler   *protocol.Handler
	incoming  chan *protocol.Message
	outgoing  chan *protocol.Message
	completed atomic.Bool
	result    interface{}
	err       error
	mu        sync.RWMutex
}

// NetworkInterface abstracts network implementation
type NetworkInterface interface {
	Send(*protocol.Message)
	Next(party.ID) <-chan *protocol.Message
	Close()
}

// NewAsyncRunner creates a new async runner
func NewAsyncRunner(t testing.TB, config *TestConfig, network NetworkInterface) *AsyncRunner {
	if config == nil {
		config = DefaultTestConfig()
	}

	var logger log.Logger
	if config.EnableLogging {
		logger = log.NewTestLogger(level.Info)
	} else {
		logger = log.NewTestLogger(level.Error)
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.TestTimeout)

	return &AsyncRunner{
		t:       t,
		config:  config,
		network: network,
		logger:  logger,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// SetupParty initializes a single party handler
func (r *AsyncRunner) SetupParty(id party.ID, startFunc protocol.StartFunc, sessionID []byte) error {
	// Create protocol config
	protocolConfig := &protocol.Config{
		Workers:         r.config.Workers,
		PriorityWorkers: r.config.PriorityWorkers,
		BufferSize:      r.config.BufferSize,
		PriorityBuffer:  r.config.PriorityBuffer,
		MessageTimeout:  r.config.MessageTimeout,
		RoundTimeout:    r.config.RoundTimeout,
		ProtocolTimeout: r.config.ProtocolTimeout,
	}

	// Create handler with its own registry
	registry := prometheus.NewRegistry()
	handler, err := protocol.NewHandler(
		r.ctx,
		r.logger,
		registry,
		startFunc,
		sessionID,
		protocolConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create handler for %s: %w", id, err)
	}

	// Create handler state
	state := &HandlerState{
		handler:  handler,
		incoming: make(chan *protocol.Message, 1000),
		outgoing: make(chan *protocol.Message, 1000),
	}

	r.handlers.Store(id, state)
	r.total++

	return nil
}

// RunAsync executes all handlers asynchronously
func (r *AsyncRunner) RunAsync() error {
	// Start handler workers for each party
	r.handlers.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		state := value.(*HandlerState)

		// Start message router
		r.wg.Add(1)
		go r.runMessageRouter(id, state)

		// Start handler executor
		r.wg.Add(1)
		go r.runHandlerExecutor(id, state)

		return true
	})

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All handlers completed
		return r.collectResults()
	case <-r.ctx.Done():
		// Timeout
		r.cancel()
		return fmt.Errorf("protocol timed out after %v", r.config.TestTimeout)
	}
}

// runMessageRouter handles message routing for a party
func (r *AsyncRunner) runMessageRouter(id party.ID, state *HandlerState) {
	defer r.wg.Done()

	// Create separate goroutines for incoming and outgoing
	var routerWg sync.WaitGroup

	// Incoming message router
	routerWg.Add(1)
	go func() {
		defer routerWg.Done()
		incomingChan := r.network.Next(id)

		for {
			select {
			case <-r.ctx.Done():
				return
			case msg, ok := <-incomingChan:
				if !ok {
					return
				}
				if msg != nil && !state.completed.Load() {
					// Accept message with timeout
					acceptCtx, cancel := context.WithTimeout(r.ctx, 100*time.Millisecond)
					go func() {
						defer cancel()
						state.handler.Accept(msg)
					}()
					<-acceptCtx.Done()
				}
			}
		}
	}()

	// Outgoing message router
	routerWg.Add(1)
	go func() {
		defer routerWg.Done()

		for {
			select {
			case <-r.ctx.Done():
				return
			case msg, ok := <-state.handler.Listen():
				if !ok {
					// Handler finished
					return
				}
				if msg != nil {
					// Send through network
					r.network.Send(msg)
				}
			}
		}
	}()

	// Wait for routers to complete
	routerWg.Wait()
}

// runHandlerExecutor executes the handler and waits for result
func (r *AsyncRunner) runHandlerExecutor(id party.ID, state *HandlerState) {
	defer r.wg.Done()

	// Create result channel
	resultChan := make(chan struct {
		result interface{}
		err    error
	}, 1)

	// Run handler in goroutine
	go func() {
		result, err := state.handler.WaitForResult()
		resultChan <- struct {
			result interface{}
			err    error
		}{result: result, err: err}
	}()

	// Wait for result or timeout
	select {
	case res := <-resultChan:
		// Store result
		state.mu.Lock()
		state.result = res.result
		state.err = res.err
		state.completed.Store(true)
		state.mu.Unlock()

		if res.err != nil {
			r.errors.Store(id, res.err)
		} else {
			r.results.Store(id, res.result)
		}

		// Increment completed counter
		if r.completed.Add(1) == r.total {
			// All parties completed
			r.cancel()
		}

	case <-r.ctx.Done():
		// Timeout
		state.mu.Lock()
		state.err = r.ctx.Err()
		state.completed.Store(true)
		state.mu.Unlock()

		r.errors.Store(id, r.ctx.Err())
	}
}

// collectResults gathers results from all parties
func (r *AsyncRunner) collectResults() error {
	var hasErrors bool
	errorMap := make(map[party.ID]error)

	r.errors.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		err := value.(error)
		errorMap[id] = err
		hasErrors = true
		return true
	})

	if hasErrors {
		return fmt.Errorf("protocol failed for %d parties: %v", len(errorMap), errorMap)
	}

	return nil
}

// Results returns the results from all parties
func (r *AsyncRunner) Results() map[party.ID]interface{} {
	results := make(map[party.ID]interface{})

	r.results.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		result := value
		results[id] = result
		return true
	})

	return results
}

// Errors returns any errors that occurred
func (r *AsyncRunner) Errors() map[party.ID]error {
	errors := make(map[party.ID]error)

	r.errors.Range(func(key, value interface{}) bool {
		id := key.(party.ID)
		err := value.(error)
		errors[id] = err
		return true
	})

	return errors
}

// Cleanup cleans up resources
func (r *AsyncRunner) Cleanup() {
	r.cancel()
	r.wg.Wait()

	if r.network != nil {
		r.network.Close()
	}
}

// RunProtocolAsync is a helper to run a protocol with async handling
func RunProtocolAsync(t testing.TB, parties []party.ID, startFuncs map[party.ID]protocol.StartFunc, config *TestConfig) (map[party.ID]interface{}, error) {
	// Use simple in-memory network for testing
	network := NewNetwork(parties)

	runner := NewAsyncRunner(t, config, network)
	defer runner.Cleanup()

	// Setup all parties
	sessionID := []byte(fmt.Sprintf("async-test-%d", time.Now().UnixNano()))
	for id, startFunc := range startFuncs {
		err := runner.SetupParty(id, startFunc, sessionID)
		if err != nil {
			return nil, err
		}
	}

	// Run protocol
	err := runner.RunAsync()
	if err != nil {
		return nil, err
	}

	return runner.Results(), nil
}
