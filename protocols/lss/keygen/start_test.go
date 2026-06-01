package keygen_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/lss/keygen"
	"github.com/stretchr/testify/require"
)

// TestStartFuncBuildsSession verifies that keygen.Start returns a StartFunc
// that, when invoked with a session ID, materializes a round.Session whose
// self-ID and party set match the inputs. The full keygen round-trip is
// exercised by the protocol-level integration tests; this is the init
// smoke test.
func TestStartFuncBuildsSession(t *testing.T) {
	group := curve.Secp256k1{}
	selfID := party.ID("alice")
	participants := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	pl := pool.NewPool(0)
	defer pl.TearDown()

	startFunc := keygen.Start(selfID, participants, threshold, group, pl)

	session, err := startFunc([]byte("test-session"))
	require.NoError(t, err)
	require.NotNil(t, session)

	require.Equal(t, selfID, session.SelfID())
	require.Equal(t, party.IDSlice(participants), session.PartyIDs())
}
