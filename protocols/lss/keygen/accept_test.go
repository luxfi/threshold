package keygen_test

import (
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestHandlerAcceptDebug(t *testing.T) {
	group := curve.Secp256k1{}
	n := 3
	threshold := 2
	partyIDs := []party.ID{"alice", "bob", "charlie"}
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sessionID := []byte("test-session")

	// Create handlers for all parties with same session ID
	handlers := make([]*protocol.MultiHandler, n)
	for i, id := range partyIDs {
		startFunc := keygen.Start(id, partyIDs, threshold, group, pl)
		h, err := protocol.NewMultiHandler(startFunc, sessionID)
		require.NoError(t, err)
		handlers[i] = h
	}

	// Collect initial messages
	messages := make([]*protocol.Message, 0)
	for i, h := range handlers {
		msgChan := h.Listen()
		select {
		case msg := <-msgChan:
			if msg != nil {
				t.Logf("Party %s sent broadcast from %s", partyIDs[i], msg.From)
				messages = append(messages, msg)
			}
		case <-time.After(100 * time.Millisecond):
			t.Logf("Party %s sent no initial message", partyIDs[i])
		}
	}

	t.Logf("Collected %d initial messages", len(messages))

	// Try to deliver messages
	for _, msg := range messages {
		if msg.Broadcast {
			// Deliver to all parties except sender
			for i, h := range handlers {
				if partyIDs[i] != msg.From {
					canAccept := h.CanAccept(msg)
					t.Logf("Checking if %s can accept from %s: %v", partyIDs[i], msg.From, canAccept)
					t.Logf("  To: %s", msg.To)
					t.Logf("  RoundNumber: %d", msg.RoundNumber)
					t.Logf("  Data length: %d", len(msg.Data))
					
					if canAccept {
						t.Logf("  ACCEPTED - calling Accept")
						h.Accept(msg)
					} else {
						t.Logf("  REJECTED")
					}
				}
			}
		}
	}

	// Check if any handler progressed
	for i, h := range handlers {
		result, err := h.Result()
		if err != nil && err.Error() != "protocol: not finished" {
			t.Logf("Party %s error: %v", partyIDs[i], err)
		} else if result != nil {
			t.Logf("Party %s has result!", partyIDs[i])
		}
		
		// Check for more messages
		msgChan := h.Listen()
		select {
		case msg := <-msgChan:
			if msg != nil {
				t.Logf("Party %s has new message after accept", partyIDs[i])
			}
		default:
			// No message
		}
	}
}