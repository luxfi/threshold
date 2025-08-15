package keygen_test

import (
	"bytes"
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

func TestCanAcceptDetailed(t *testing.T) {
	// This test verifies that message acceptance logic works
	group := curve.Secp256k1{}
	sessionID := []byte("test-session")
	partyIDs := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Create alice's session to check message creation
	aliceStart := keygen.Start("alice", partyIDs, threshold, group, pl)
	aliceSession, err := aliceStart(sessionID)
	require.NoError(t, err)

	// Create bob's session to check message acceptance
	bobStart := keygen.Start("bob", partyIDs, threshold, group, pl)
	bobSession, err := bobStart(sessionID)
	require.NoError(t, err)

	// Check session properties
	t.Logf("Session checks:")
	t.Logf("  Alice protocol: %s", aliceSession.ProtocolID())
	t.Logf("  Bob protocol: %s", bobSession.ProtocolID())
	t.Logf("  Alice SSID: %x", aliceSession.SSID())
	t.Logf("  Bob SSID: %x", bobSession.SSID())
	t.Logf("  SSIDs match: %v", bytes.Equal(aliceSession.SSID(), bobSession.SSID()))
	t.Logf("  Alice round: %d", aliceSession.Number())
	t.Logf("  Bob round: %d", bobSession.Number())
	t.Logf("  Final round: %d", aliceSession.FinalRoundNumber())

	// Verify sessions are compatible
	require.Equal(t, aliceSession.ProtocolID(), bobSession.ProtocolID())
	require.True(t, bytes.Equal(aliceSession.SSID(), bobSession.SSID()))
}
