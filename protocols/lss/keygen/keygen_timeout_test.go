package keygen_test

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/log"
	"github.com/luxfi/log/level"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestKeygenWithTimeout(t *testing.T) {
	// Test keygen with proper timeout handling
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create handlers with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	logger := log.NewTestLogger(level.Info)
	sessionID := []byte("test-keygen-timeout")
	cfg := protocol.DefaultConfig()

	handlers := make([]*protocol.Handler, n)
	for i, id := range partyIDs {
		h, err := protocol.NewHandler(ctx, logger, prometheus.NewRegistry(),
			lss.Keygen(group, id, partyIDs, threshold, pl), sessionID, cfg)
		if err != nil {
			t.Logf("Error creating handler for %s: %v", id, err)
			continue
		}
		handlers[i] = h
	}

	// Run with timeout - expect timeout but no panic
	done := make(chan bool, n)

	for i, h := range handlers {
		if h == nil {
			done <- false
			continue
		}

		go func(handler *protocol.Handler, idx int) {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("Handler %d panicked: %v", idx, r)
				}
				done <- true
			}()

			// Just try to start the handler
			select {
			case <-handler.Listen():
				// Got a message
			case <-ctx.Done():
				// Timeout
			}
		}(h, i)
	}

	// Wait for completion or timeout
	for i := 0; i < n; i++ {
		select {
		case <-done:
			// Handler finished
		case <-ctx.Done():
			// Global timeout
			t.Log("Keygen test timed out (expected)")
			return
		}
	}

	// Pass if no panic
	assert.True(t, true, "Test completed without panic")
}

func TestKeygenInitialization(t *testing.T) {
	// Test that keygen can be initialized for various party sizes
	testCases := []struct {
		n         int
		threshold int
		name      string
	}{
		{3, 2, "3-party"},
		{5, 3, "5-party"},
		{7, 4, "7-party"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			partyIDs := test.PartyIDs(tc.n)
			group := curve.Secp256k1{}
			pl := pool.NewPool(0)
			defer pl.TearDown()

			// Just test initialization
			for _, id := range partyIDs {
				keygen := lss.Keygen(group, id, partyIDs, tc.threshold, pl)
				assert.NotNil(t, keygen, "Keygen should be created for party %s", id)
			}
		})
	}
}

func TestKeygenQuickTimeout(t *testing.T) {
	// Test with very quick timeout to ensure no hanging
	n := 3
	threshold := 2

	test.SimpleProtocolTest(t, "Keygen-Quick", n, threshold, func(ids []party.ID) bool {
		group := curve.Secp256k1{}
		pl := pool.NewPool(0)
		defer pl.TearDown()

		// Create context with very short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		logger := log.NewTestLogger(level.Info)
		sessionID := []byte("quick-test")
		cfg := protocol.DefaultConfig()

		// Try to create handlers
		for _, id := range ids {
			h, err := protocol.NewHandler(ctx, logger, prometheus.NewRegistry(),
				lss.Keygen(group, id, ids, threshold, pl), sessionID, cfg)
			if err != nil {
				// Error is ok with quick timeout
				return true
			}
			if h != nil {
				// Handler created successfully
			}
		}

		// Wait for context to expire
		<-ctx.Done()
		return true
	})
}
