package frost

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestDebugShares(t *testing.T) {
	group := curve.Secp256k1{}
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	// Run keygen
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("debug-shares"), func(id party.ID) protocol.StartFunc {
		return Keygen(group, id, partyIDs, threshold)
	})
	require.NoError(t, err)

	configs := make(map[party.ID]*Config, n)
	for id, result := range keygenResults {
		configs[id] = result.(*Config)
	}

	publicKey := configs[partyIDs[0]].PublicKey
	verificationShares := configs[partyIDs[0]].VerificationShares.Points

	t.Logf("Public key: %v", publicKey)
	t.Logf("Number of parties: %d, threshold: %d", n, threshold)

	// Test with ALL parties
	allParties := partyIDs
	allLambdas := polynomial.Lagrange(group, allParties)
	reconstructedAll := group.NewPoint()
	for _, id := range allParties {
		share := verificationShares[id]
		lambda := allLambdas[id]
		contribution := lambda.Act(share)
		reconstructedAll = reconstructedAll.Add(contribution)
		t.Logf("ALL: Party %s - lambda=%v, Y_i=%v, lambda*Y_i=%v", id, lambda, share, contribution)
	}
	t.Logf("ALL parties reconstruction: %v, matches=%v", reconstructedAll, reconstructedAll.Equal(publicKey))

	// Test with threshold subset
	subset := partyIDs[:threshold]
	subsetLambdas := polynomial.Lagrange(group, subset)
	reconstructedSubset := group.NewPoint()
	for _, id := range subset {
		share := verificationShares[id]
		lambda := subsetLambdas[id]
		contribution := lambda.Act(share)
		reconstructedSubset = reconstructedSubset.Add(contribution)
		t.Logf("SUBSET: Party %s - lambda=%v, Y_i=%v, lambda*Y_i=%v", id, lambda, share, contribution)
	}
	t.Logf("Threshold subset reconstruction: %v, matches=%v", reconstructedSubset, reconstructedSubset.Equal(publicKey))

	// The issue: The verification shares Y_i are computed as evaluations of the sum polynomial
	// Y_i = F(i)*G where F = f_1 + f_2 + ... + f_n (sum of all n degree-t polynomials)
	// This means the shares correspond to a polynomial with the right degree (t),
	// but the reconstruction formula is different.

	// For Shamir secret sharing to work with threshold reconstruction:
	// We need Y such that Y = F(0)*G
	// And Y_i = F(i)*G for some degree-t polynomial F
	// Then Y = sum(lambda_i * Y_i) for any t shares (Lagrange interpolation at 0)

	// But in FROST keygen, each party contributes a polynomial, and the final shares
	// are sums of evaluations. This is correct for the private shares (s_i),
	// but the verification shares Y_i = s_i*G should then work for reconstruction.

	// Let's verify that the private shares match the verification shares
	for id, cfg := range configs {
		expected := cfg.PrivateShare.ActOnBase()
		actual := verificationShares[id]
		match := expected.Equal(actual)
		t.Logf("Party %s: s_i*G matches Y_i? %v", id, match)
		if !match {
			t.Errorf("Verification share mismatch for party %s", id)
		}
	}
}
