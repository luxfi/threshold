package keygen_test

import (
	"testing"
	"time"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestLSSKeygenNetwork(t *testing.T) {
	group := curve.Secp256k1{}
	n := 5  // Test with 5 parties
	threshold := 3  // 3-of-5 threshold
	partyIDs := test.PartyIDs(n)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create handlers
	handlers := make([]*protocol.MultiHandler, n)
	for i, id := range partyIDs {
		startFunc := keygen.Start(id, partyIDs, threshold, group, pl)
		h, err := protocol.NewMultiHandler(startFunc, nil)
		require.NoError(t, err)
		handlers[i] = h
	}

	// Process protocol messages until completion
	done := false
	iterations := 0
	for !done && iterations < 10 {
		iterations++
		
		// Collect all outgoing messages
		allMessages := make([]*protocol.Message, 0)
		for _, h := range handlers {
			timeout := time.After(100 * time.Millisecond)
			for {
				select {
				case msg := <-h.Listen():
					if msg != nil {
						allMessages = append(allMessages, msg)
					}
				case <-timeout:
					goto nextHandler
				}
			}
		nextHandler:
		}
		
		if len(allMessages) == 0 {
			// No more messages, check if done
			done = true
			for _, h := range handlers {
				if _, err := h.Result(); err != nil {
					if err.Error() == "protocol: not finished" {
						done = false
						t.Fatal("Protocol stuck - no messages but not finished")
					}
				}
			}
			continue
		}
		
		// Deliver messages
		for _, msg := range allMessages {
			if msg.Broadcast {
				// Deliver to all parties except sender
				for i, h := range handlers {
					if msg.From != partyIDs[i] && h.CanAccept(msg) {
						h.Accept(msg)
					}
				}
			} else {
				// Deliver to specific party
				for i, h := range handlers {
					if msg.To == partyIDs[i] && h.CanAccept(msg) {
						h.Accept(msg)
						break
					}
				}
			}
		}
		
		// Give handlers time to process
		time.Sleep(50 * time.Millisecond)
		
		// Check if all completed
		allDone := true
		for _, h := range handlers {
			if _, err := h.Result(); err != nil && err.Error() == "protocol: not finished" {
				allDone = false
				break
			}
		}
		if allDone {
			done = true
		}
	}
	
	require.True(t, done, "Protocol should complete")
	require.LessOrEqual(t, iterations, 5, "Protocol should complete in reasonable iterations")
	
	// Verify results
	configs := make([]*config.Config, 0, n)
	publicKeys := make([]curve.Point, 0, n)
	
	for i, h := range handlers {
		result, err := h.Result()
		require.NoError(t, err, "Party %s should complete successfully", partyIDs[i])
		
		cfg, ok := result.(*config.Config)
		require.True(t, ok, "Result should be a Config")
		require.NotNil(t, cfg)
		
		configs = append(configs, cfg)
		
		// Verify config
		require.Equal(t, partyIDs[i], cfg.ID)
		require.Equal(t, threshold, cfg.Threshold)
		require.NotNil(t, cfg.ECDSA)
		require.Len(t, cfg.Public, n)
		
		// Get public key
		pk, err := cfg.PublicKey()
		require.NoError(t, err)
		require.NotNil(t, pk)
		publicKeys = append(publicKeys, pk)
	}
	
	// Verify all parties have the same public key
	for i := 1; i < n; i++ {
		require.True(t, publicKeys[0].Equal(publicKeys[i]), 
			"All parties should have the same public key")
	}
	
	t.Logf("LSS keygen completed successfully with %d parties, threshold %d", n, threshold)
	t.Logf("Public key: %x", publicKeys[0].(*curve.Secp256k1Point).XBytes())
}