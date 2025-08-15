package test

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/log/level"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/prometheus/client_golang/prometheus"
)

// PhaseHarness provides phase-gated test environment for protocol testing
type PhaseHarness struct {
	t      testing.TB
	ids    []party.ID
	net    *Network
	logger log.Logger
}

// NewPhaseHarness creates a new phase-gated test harness
func NewPhaseHarness(t testing.TB, ids []party.ID) *PhaseHarness {
	return &PhaseHarness{
		t:      t,
		ids:    ids,
		net:    NewNetwork(ids),
		logger: log.NewTestLogger(level.Info),
	}
}

// RunPhase starts all handlers for a single phase, waits for all results, then returns them.
// It guarantees: (1) fresh session; (2) all handlers live before traffic; (3) phase timeout ownership.
func (h *PhaseHarness) RunPhase(timeout time.Duration, startFor func(id party.ID) protocol.StartFunc) (map[party.ID]interface{}, error) {
	// 1) fresh session id
	sessionID := []byte(fmt.Sprintf("session-%d-%d", time.Now().UnixNano(), rand.Int63()))

	// Configure network to only route messages for this session
	h.net.SetSession(sessionID)

	// 2) per-phase context that we cancel after all done or on timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 3) build handlers with proper config
	cfg := &protocol.Config{
		Workers:         0, // Auto-detect
		PriorityWorkers: 4,
		BufferSize:      8192,
		PriorityBuffer:  1024,
		MessageTimeout:  15 * time.Second,
		RoundTimeout:    30 * time.Second,
		ProtocolTimeout: timeout, // generous; ctx still governs outer timeout
	}

	handlers := make(map[party.ID]*protocol.Handler, len(h.ids))
	for _, id := range h.ids {
		start := startFor(id)
		reg := prometheus.NewRegistry()
		hd, err := protocol.NewHandler(ctx, h.logger, reg, start, sessionID, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create handler for party %s: %w", id, err)
		}
		handlers[id] = hd
	}

	// 4) start all loops before any party progresses
	var wg sync.WaitGroup
	errChan := make(chan error, len(h.ids))

	for id, hd := range handlers {
		wg.Add(1)
		go func(id party.ID, hd *protocol.Handler) {
			defer wg.Done()

			// Run handler loop - this routes messages on h.net and blocks until hd finishes
			for {
				select {
				case <-ctx.Done():
					return
				case msg, ok := <-hd.Listen():
					if !ok {
						// Handler completed
						return
					}
					if msg != nil {
						// Send through network directly - it's non-blocking now
						h.net.Send(msg)
					}
				case msg := <-h.net.Next(id):
					// Receive from network
					if msg != nil {
						hd.Accept(msg)
					}
				}
			}
		}(id, hd)
	}

	// 5) wait for results from all parties
	results := make(map[party.ID]interface{}, len(h.ids))
	resultsMu := sync.Mutex{}

	// Collect results in parallel
	var resultWg sync.WaitGroup
	for id, hd := range handlers {
		resultWg.Add(1)
		go func(id party.ID, hd *protocol.Handler) {
			defer resultWg.Done()

			res, err := hd.WaitForResult()
			if err != nil {
				errChan <- fmt.Errorf("party %s result: %w", id, err)
				return
			}

			resultsMu.Lock()
			results[id] = res
			resultsMu.Unlock()
		}(id, hd)
	}

	// Wait for all results or timeout
	done := make(chan struct{})
	go func() {
		resultWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All results collected successfully
	case <-ctx.Done():
		// Timeout - cancel and wait for cleanup
		cancel()
		wg.Wait()
		return nil, fmt.Errorf("phase timed out after %v", timeout)
	case err := <-errChan:
		// Error from a party - cancel and wait for cleanup
		cancel()
		wg.Wait()
		return nil, err
	}

	// 6) all results acquired – now wait for loops to exit cleanly
	cancel() // Signal loops to exit
	wg.Wait()

	// Check for any errors
	close(errChan)
	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}

// Reset creates a fresh network for the next phase (optional)
func (h *PhaseHarness) Reset() {
	h.net = NewNetwork(h.ids)
}
