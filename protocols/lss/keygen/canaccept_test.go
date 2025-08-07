package keygen_test

import (
	"bytes"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestCanAcceptDetailed(t *testing.T) {
	group := curve.Secp256k1{}
	sessionID := []byte("test-session")
	partyIDs := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create alice's handler
	aliceStart := keygen.Start("alice", partyIDs, threshold, group, pl)
	aliceHandler, err := protocol.NewMultiHandler(aliceStart, sessionID)
	require.NoError(t, err)

	// Create bob's handler 
	bobStart := keygen.Start("bob", partyIDs, threshold, group, pl)
	bobHandler, err := protocol.NewMultiHandler(bobStart, sessionID)
	require.NoError(t, err)

	// Get alice's broadcast message
	var aliceMsg *protocol.Message
	select {
	case msg := <-aliceHandler.Listen():
		aliceMsg = msg
		t.Logf("Got alice's message")
	default:
		t.Fatal("No message from alice")
	}

	// Create a test handler to check internal state
	bobStartFunc := keygen.Start("bob", partyIDs, threshold, group, pl)
	bobSession, err := bobStartFunc(sessionID)
	require.NoError(t, err)

	// Check each condition manually
	t.Logf("Message checks:")
	t.Logf("  msg != nil: %v", aliceMsg != nil)
	t.Logf("  msg.IsFor(bob): %v", aliceMsg.IsFor("bob"))
	t.Logf("  msg.Protocol == bobSession.ProtocolID(): %v (Protocol: %s, Expected: %s)", 
		aliceMsg.Protocol == bobSession.ProtocolID(), aliceMsg.Protocol, bobSession.ProtocolID())
	t.Logf("  SSID equal: %v", bytes.Equal(aliceMsg.SSID, bobSession.SSID()))
	t.Logf("  PartyIDs contains sender: %v", bobSession.PartyIDs().Contains(aliceMsg.From))
	t.Logf("  msg.Data != nil: %v", aliceMsg.Data != nil)
	t.Logf("  msg.RoundNumber <= FinalRoundNumber: %v (%d <= %d)", 
		aliceMsg.RoundNumber <= bobSession.FinalRoundNumber(), 
		aliceMsg.RoundNumber, bobSession.FinalRoundNumber())
	t.Logf("  msg.RoundNumber >= currentRound || msg.RoundNumber == 0: %v (%d >= %d)",
		aliceMsg.RoundNumber >= bobSession.Number() || aliceMsg.RoundNumber == 0,
		aliceMsg.RoundNumber, bobSession.Number())

	// Now check with the actual handler
	canAccept := bobHandler.CanAccept(aliceMsg)
	t.Logf("bobHandler.CanAccept(aliceMsg): %v", canAccept)
	
	// Check handler's current state
	result, err := bobHandler.Result()
	t.Logf("bobHandler result: %v, error: %v", result, err)
}