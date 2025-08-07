package keygen_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestSimpleKeygen(t *testing.T) {
	group := curve.Secp256k1{}
	selfID := party.ID("alice")
	participants := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create handler
	startFunc := keygen.Start(selfID, participants, threshold, group, pl)
	h, err := protocol.NewMultiHandler(startFunc, nil)
	require.NoError(t, err)

	// Check if the handler is expecting messages
	msgChan := h.Listen()
	
	// Wait for a message or timeout
	select {
	case msg := <-msgChan:
		if msg != nil {
			t.Logf("Got initial message: Broadcast=%v, Round=%d, From=%s", 
				msg.Broadcast, msg.RoundNumber, msg.From)
		} else {
			t.Log("Channel closed immediately")
		}
	case <-time.After(1 * time.Second):
		t.Log("No message within 1 second")
	}

	// Try to get result
	result, err := h.Result()
	if err != nil {
		t.Logf("Result error: %v", err)
	} else {
		t.Logf("Result: %v", result)
	}
}

func TestDebugHandler(t *testing.T) {
	group := curve.Secp256k1{}
	selfID := party.ID("alice") 
	participants := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create handler
	startFunc := keygen.Start(selfID, participants, threshold, group, pl)
	session, err := startFunc(nil)
	require.NoError(t, err)
	
	// Check round details
	fmt.Printf("Round number: %d\n", session.Number())
	fmt.Printf("Final round: %d\n", session.FinalRoundNumber())
	fmt.Printf("Protocol ID: %s\n", session.ProtocolID())
	fmt.Printf("Self ID: %s\n", session.SelfID())
	fmt.Printf("Party IDs: %v\n", session.PartyIDs())
	fmt.Printf("Other Party IDs: %v\n", session.OtherPartyIDs())
}