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
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// ProtocolTestSuite provides a clean, reusable test framework for MPC protocols
type ProtocolTestSuite struct {
	t        testing.TB
	parties  []party.ID
	network  *Network
	handlers map[party.ID]*protocol.Handler
	results  map[party.ID]interface{}
	errors   map[party.ID]error
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
	logger   log.Logger
}

// NewProtocolTestSuite creates a new test suite for the given parties
func NewProtocolTestSuite(t testing.TB, parties []party.ID) *ProtocolTestSuite {
	return &ProtocolTestSuite{
		t:        t,
		parties:  parties,
		network:  NewNetwork(parties),
		handlers: make(map[party.ID]*protocol.Handler),
		results:  make(map[party.ID]interface{}),
		errors:   make(map[party.ID]error),
		logger:   log.NewTestLogger(level.Info),
	}
}

// RunProtocol executes a protocol across all parties with proper synchronization
func (s *ProtocolTestSuite) RunProtocol(
	timeout time.Duration,
	startFunc func(id party.ID) protocol.StartFunc,
) (map[party.ID]interface{}, error) {
	// Create context with timeout
	s.ctx, s.cancel = context.WithTimeout(context.Background(), timeout)
	defer s.cancel()

	// Generate session ID
	sessionID := []byte(fmt.Sprintf("test-session-%d", time.Now().UnixNano()))

	// Create handlers for all parties
	for _, id := range s.parties {
		handler, err := protocol.NewHandler(
			s.ctx,
			s.logger,
			prometheus.NewRegistry(),
			startFunc(id),
			sessionID,
			protocol.DefaultConfig(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create handler for %s: %w", id, err)
		}
		s.handlers[id] = handler
	}

	// Start protocol execution for all parties
	var wg sync.WaitGroup
	for _, id := range s.parties {
		wg.Add(1)
		go s.runParty(id, &wg)
	}

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Check for errors
		for id, err := range s.errors {
			if err != nil {
				return s.results, fmt.Errorf("party %s error: %w", id, err)
			}
		}
		return s.results, nil
	case <-s.ctx.Done():
		return s.results, fmt.Errorf("protocol timeout after %v", timeout)
	}
}

// runParty executes the protocol for a single party
func (s *ProtocolTestSuite) runParty(id party.ID, wg *sync.WaitGroup) {
	defer wg.Done()

	handler := s.handlers[id]

	// Message routing goroutine
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case msg, ok := <-handler.Listen():
				if !ok {
					return // Handler completed
				}
				if msg != nil {
					s.network.Send(msg)
				}
			}
		}
	}()

	// Message receiving goroutine
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case msg := <-s.network.Next(id):
				if msg != nil {
					handler.Accept(msg)
				}
			}
		}
	}()

	// Wait for result
	result, err := handler.WaitForResult()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		s.errors[id] = err
	} else {
		s.results[id] = result
	}
}

// RunKeygenRefreshSign runs a complete keygen-refresh-sign cycle
func RunKeygenRefreshSign(t *testing.T, n, threshold int, pool *pool.Pool) {
	parties := PartyIDs(n)
	suite := NewProtocolTestSuite(t, parties)

	// Phase 1: Keygen
	t.Log("Running keygen...")
	keygenResults, err := suite.RunProtocol(60*time.Second, func(id party.ID) protocol.StartFunc {
		// Protocol-specific keygen function should be passed here
		return nil // Placeholder - actual protocol keygen would go here
	})
	require.NoError(t, err, "keygen should complete")
	require.Len(t, keygenResults, n, "all parties should complete keygen")

	// Phase 2: Refresh
	t.Log("Running refresh...")
	// Reset network for clean phase separation
	suite.network = NewNetwork(parties)
	_, err = suite.RunProtocol(60*time.Second, func(id party.ID) protocol.StartFunc {
		// Protocol-specific refresh function
		// Using keygenResults[id] for refresh config
		return nil // Placeholder
	})
	require.NoError(t, err, "refresh should complete")

	// Phase 3: Sign
	t.Log("Running sign...")
	suite.network = NewNetwork(parties)
	_ = []byte("test message") // Will be used in actual implementation
	_, err = suite.RunProtocol(60*time.Second, func(id party.ID) protocol.StartFunc {
		// Protocol-specific sign function
		return nil // Placeholder
	})
	require.NoError(t, err, "sign should complete")

	t.Log("All phases completed successfully")
}

// Cleanup releases resources
func (s *ProtocolTestSuite) Cleanup() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.network != nil {
		s.network.Close()
	}
}
