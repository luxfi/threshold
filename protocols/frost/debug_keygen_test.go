package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
)

func TestDebugKeygen(t *testing.T) {
	group := curve.Secp256k1{}
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	// Run keygen multiple times to see if it's consistent
	for attempt := 1; attempt <= 5; attempt++ {
		t.Logf("\n=== Attempt %d ===", attempt)

		keygenResults, err := test.RunProtocol(t, partyIDs, []byte("debug-keygen"), func(id party.ID) protocol.StartFunc {
			return frost.Keygen(group, id, partyIDs, threshold)
		})
		require.NoError(t, err)

		configs := make(map[party.ID]*frost.Config, n)
		for id, result := range keygenResults {
			configs[id] = result.(*frost.Config)
		}

		// Check if all parties have the same public key
		var refPK curve.Point
		for id, cfg := range configs {
			if refPK == nil {
				refPK = cfg.PublicKey
				t.Logf("Reference public key from %s", id)
			} else {
				if !refPK.Equal(cfg.PublicKey) {
					t.Errorf("Party %s has different public key!", id)
				}
			}
		}

		// Check if verification shares are consistent
		refShares := configs[partyIDs[0]].VerificationShares.Points
		for id, cfg := range configs {
			for pid, share := range cfg.VerificationShares.Points {
				if !share.Equal(refShares[pid]) {
					t.Errorf("Party %s has different verification share for %s", id, pid)
				}
			}
		}

		// Check if shares match private keys
		for id, cfg := range configs {
			expected := cfg.PrivateShare.ActOnBase()
			actual := cfg.VerificationShares.Points[id]
			if !expected.Equal(actual) {
				t.Errorf("Party %s: verification share doesn't match private share", id)
			}
		}

		t.Logf("Attempt %d: All consistency checks passed", attempt)
	}
}
