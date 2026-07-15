package cmp_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/require"
)

// TestDegree2Requires3Signers pins the exact cryptographic property that a
// genuine "3-of-5" CGGMP21 key must have, and that the KMS/MPC threshold fix
// (mpc 1e1d318: --threshold=3 -> keygen degree 2 -> keyInfo.Threshold=2) relies
// on.
//
// A CGGMP21 key generated at polynomial degree t = 2 (the value stored as
// keyInfo.Threshold for a 3-of-5 wallet) can be signed by ANY 3 of its 5
// shareholders, and CANNOT be signed by any 2. This is the difference between
// genuine threshold security and the degree-0 (1-of-n) bug the fix closed.
//
// The negative branch is what makes "3-of-5" meaningful: with only 2 signers
// the protocol is refused at cmp.Sign -> sign.StartSign -> config.CanSign ->
// ValidThreshold(t=2, n=2) == false (t > n-1), before any round runs. No share,
// no partial signature, nothing to aggregate.
func TestDegree2Requires3Signers(t *testing.T) {
	const (
		n = 5 // shareholders (5 nodes)
		T = 2 // CGGMP21 polynomial degree => 3-of-5 (needs T+1 = 3 signers)
	)
	ids := test.PartyIDs(n)

	pools := make(map[party.ID]*pool.Pool, n)
	for _, id := range ids {
		pools[id] = pool.NewPool(0)
	}
	defer func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	}()

	// DKG across all 5 parties at degree T=2.
	kgResults, err := test.RunProtocol(t, ids, []byte("proof/degree2/keygen"),
		func(id party.ID) protocol.StartFunc {
			return cmp.Keygen(curve.Secp256k1{}, id, ids, T, pools[id])
		})
	require.NoError(t, err, "DKG at degree 2 must complete")
	require.Len(t, kgResults, n, "every shareholder gets a share")

	configs := make(map[party.ID]*cmp.Config, n)
	var groupKey curve.Point
	for id, r := range kgResults {
		cfg := r.(*cmp.Config)
		configs[id] = cfg
		require.Equal(t, T, cfg.Threshold, "stored keyInfo.Threshold must be the degree 2")
		if groupKey == nil {
			groupKey = cfg.PublicPoint()
		} else {
			require.True(t, groupKey.Equal(cfg.PublicPoint()), "all shares share one group key")
		}
	}

	digest := make([]byte, 32)
	copy(digest, []byte("genuine-3of5-threshold-proof----"))

	// --- NEGATIVE: any 2-of-5 subset FAILS to sign (rejected before round 1).
	twoSigners := ids[:2]
	_, negErr := test.RunProtocol(t, twoSigners, []byte("proof/degree2/sign-2"),
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(configs[id], twoSigners, digest, pools[id])
		})
	require.Error(t, negErr, "2-of-5 MUST be refused: degree-2 key needs 3 signers")

	// --- POSITIVE: a 3-of-5 subset SUCCEEDS and yields a valid ECDSA signature.
	threeSigners := ids[:3]
	sigResults, posErr := test.RunProtocol(t, threeSigners, []byte("proof/degree2/sign-3"),
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(configs[id], threeSigners, digest, pools[id])
		})
	require.NoError(t, posErr, "3-of-5 MUST complete")
	for _, r := range sigResults {
		sig := r.(*ecdsa.Signature)
		require.True(t, sig.Verify(groupKey, digest),
			"3-of-5 signature MUST verify against the group public key")
	}
}
