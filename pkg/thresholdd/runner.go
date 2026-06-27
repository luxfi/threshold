package thresholdd

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	log "github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// runMultiparty drives a synchronous in-process MPC round trip for every
// listed party and returns the final per-party result map.
//
// This is the production path the daemon uses for the protocols that
// actually need a round-based exchange (cmp / frost / doerner). Pulsar
// and corona have direct single-process keygen functions and skip
// this runner.
func runMultiparty(
	partyIDs []party.ID,
	sessionID []byte,
	start func(party.ID) protocol.StartFunc,
	timeout time.Duration,
) (map[party.ID]any, error) {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	cfg := &protocol.Config{
		Workers:         4,
		PriorityWorkers: 4,
		BufferSize:      10000,
		PriorityBuffer:  1000,
		MessageTimeout:  30 * time.Second,
		RoundTimeout:    60 * time.Second,
		ProtocolTimeout: timeout,
	}
	// Use a writer-backed logger at FatalLevel so NewHandler accepts it
	// (NoOpLogger.IsZero() == true and is rejected). Discarding output
	// keeps the daemon silent under load.
	logger := log.NewWriter(io.Discard).Level(log.FatalLevel)

	network := test.NewNetwork(partyIDs)
	handlers := make(map[party.ID]*protocol.Handler, len(partyIDs))

	for _, id := range partyIDs {
		h, err := protocol.NewHandler(
			context.Background(),
			logger,
			metric.NewRegistry(),
			start(id),
			sessionID,
			cfg,
		)
		if err != nil {
			return nil, fmt.Errorf("create handler %s: %w", id, err)
		}
		handlers[id] = h
	}

	results := make(map[party.ID]any, len(partyIDs))
	errs := make(map[party.ID]error, len(partyIDs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for id, h := range handlers {
		wg.Add(1)
		go func(id party.ID, h *protocol.Handler) {
			defer wg.Done()
			// per-party done channel scopes the router goroutines so
			// fast finishers don't race the global ctx cancel.
			done := make(chan struct{})
			defer close(done)
			go func() {
				for {
					select {
					case <-done:
						return
					case <-ctx.Done():
						return
					case msg := <-network.Next(id):
						if msg != nil {
							h.Accept(msg)
						}
					}
				}
			}()
			go func() {
				for {
					select {
					case <-done:
						return
					case <-ctx.Done():
						return
					case msg, ok := <-h.Listen():
						if !ok {
							return
						}
						if msg != nil {
							network.Send(msg)
						}
					}
				}
			}()
			res, err := h.WaitForResult()
			mu.Lock()
			results[id] = res
			errs[id] = err
			mu.Unlock()
		}(id, h)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		return nil, fmt.Errorf("protocol timeout after %s", timeout)
	}

	for id, err := range errs {
		if err != nil {
			return results, fmt.Errorf("party %s: %w", id, err)
		}
	}
	return results, nil
}

// partyIDs returns deterministic sorted party.IDs for n parties.
func partyIDs(n int) []party.ID {
	out := make([]party.ID, n)
	base := ""
	for i := 0; i < n; i++ {
		if i%26 == 0 && i > 0 {
			base += "a"
		}
		out[i] = party.ID(base + string('a'+rune(i%26)))
	}
	return out
}
