package keygen_test

import (
	"fmt"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestSimpleKeygen(t *testing.T) {
	// This test just verifies the protocol can be initialized
	// Full protocol testing is done in integration tests
	group := curve.Secp256k1{}
	selfID := party.ID("alice")
	participants := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create start function
	startFunc := keygen.Start(selfID, participants, threshold, group, pl)

	// Verify it can create a session
	session, err := startFunc([]byte("test-session"))
	require.NoError(t, err)
	require.NotNil(t, session)

	// Check basic properties
	require.Equal(t, selfID, session.SelfID())
	require.Equal(t, party.IDSlice(participants), session.PartyIDs())
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
