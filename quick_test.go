package threshold_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
)

func TestQuickFrost(t *testing.T) {
	N := 3
	T := 2

	partyIDs := test.PartyIDs(N)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Generate a unique session ID
	sessionID := []byte("test-frost-session")

	// Use the correct RunProtocol signature
	results, err := test.RunProtocol(t, partyIDs, sessionID, func(id party.ID) protocol.StartFunc {
		return frost.Keygen(curve.Secp256k1{}, id, partyIDs, T)
	})

	require.NoError(t, err, "keygen should complete without error")
	require.Len(t, results, N, "should get N results")

	t.Log("Quick FROST test passed")
}
