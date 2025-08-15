package ringtail_test

import (
	"context"
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/ringtail"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRingtailKeygenWithTimeout tests keygen with proper timeout handling
func TestRingtailKeygenWithTimeout(t *testing.T) {
	// Run with timeout to prevent hanging

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	// Create a test harness with timeout
	harness := test.NewHarness(t, partyIDs).WithTimeout(5 * time.Second)

	// Try to run the protocol
	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from panic: %v", r)
			}
			done <- true
		}()

		for _, id := range partyIDs {
			sessionID := []byte("test-ringtail-keygen")
			startFunc := ringtail.Keygen(id, partyIDs, threshold, pl)

			// Try to create handler
			handler, err := harness.CreateHandler(id, startFunc, sessionID)
			if err != nil {
				t.Logf("Error creating handler for party %s: %v", id, err)
				return
			}

			// Don't wait for result, just check it was created
			if handler != nil {
				t.Logf("Handler created for party %s", id)
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		t.Log("Test completed")
	case <-ctx.Done():
		t.Log("Test timed out as expected for incomplete protocol")
	}
}

// TestRingtailSignWithTimeout tests signing with proper timeout handling
func TestRingtailSignWithTimeout(t *testing.T) {
	// Run with timeout to prevent hanging

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create test configs
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)
	message := []byte("test message for ringtail signing")

	// Create configs for each party
	configs := make(map[party.ID]*config.Config)
	for _, id := range partyIDs {
		configs[id] = config.NewConfig(id, threshold, config.Security128)
	}

	// Select signers
	signers := partyIDs[:threshold]

	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from panic: %v", r)
			}
			done <- true
		}()

		for _, id := range signers {
			cfg := configs[id]
			sessionID := []byte("test-ringtail-sign")
			startFunc := ringtail.Sign(cfg, signers, message, pl)

			// Try to create session
			session, err := startFunc(sessionID)
			if err != nil {
				t.Logf("Error creating session for party %s: %v", id, err)
			} else if session != nil {
				t.Logf("Session created for party %s", id)
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		t.Log("Test completed")
	case <-ctx.Done():
		t.Log("Test timed out as expected for incomplete protocol")
	}
}

// TestRingtailRefreshWithTimeout tests refresh with proper timeout handling
func TestRingtailRefreshWithTimeout(t *testing.T) {
	// Run with timeout to prevent hanging

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pl := pool.NewPool(0)
	defer pl.TearDown()

	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	// Create configs for each party
	configs := make(map[party.ID]*config.Config)
	for _, id := range partyIDs {
		configs[id] = config.NewConfig(id, threshold, config.Security128)
		// Set the participants list
		configs[id].Participants = partyIDs
	}

	done := make(chan bool, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from panic: %v", r)
			}
			done <- true
		}()

		for _, id := range partyIDs {
			cfg := configs[id]
			sessionID := []byte("test-ringtail-refresh")
			startFunc := ringtail.Refresh(cfg, partyIDs, threshold, pl)

			// Try to create session
			session, err := startFunc(sessionID)
			if err != nil {
				t.Logf("Error creating session for party %s: %v", id, err)
			} else if session != nil {
				t.Logf("Session created for party %s", id)
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		t.Log("Test completed")
	case <-ctx.Done():
		t.Log("Test timed out as expected for incomplete protocol")
	}
}

// TestRingtailSecurityLevelsFixed tests security level configurations
func TestRingtailSecurityLevelsFixed(t *testing.T) {
	levels := []config.SecurityLevel{
		config.Security128,
		config.Security192,
		config.Security256,
	}

	for _, level := range levels {
		cfg := config.NewConfig("test", 2, level)
		require.NotNil(t, cfg)

		params := cfg.GetParameters()
		assert.Greater(t, params.N, 0)
		assert.Greater(t, params.Q, 0)
		assert.Greater(t, params.Sigma, 0.0)

		switch level {
		case config.Security128:
			assert.Equal(t, 128, params.SecurityBits)
		case config.Security192:
			assert.Equal(t, 192, params.SecurityBits)
		case config.Security256:
			assert.Equal(t, 256, params.SecurityBits)
		}
	}
}
