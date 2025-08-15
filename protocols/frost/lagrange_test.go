package frost_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLagrangeInterpolation tests that Lagrange coefficients correctly reconstruct secrets
func TestLagrangeInterpolation(t *testing.T) {
	group := curve.Secp256k1{}
	n := 5
	threshold := 3

	// Create party IDs
	partyIDs := test.PartyIDs(n)
	t.Logf("Party IDs: %v", partyIDs)

	// Create a secret polynomial with degree threshold-1
	secret := group.NewScalar()
	secret.SetNat(new(saferith.Nat).SetUint64(42))
	poly := polynomial.NewPolynomial(group, threshold-1, secret)

	// Evaluate shares for each party
	shares := make(map[party.ID]curve.Scalar)
	for _, id := range partyIDs {
		shares[id] = poly.Evaluate(id.Scalar(group))
	}

	// Test 1: All parties can reconstruct the secret
	{
		lambdas := polynomial.Lagrange(group, partyIDs)
		reconstructed := group.NewScalar()
		for _, id := range partyIDs {
			reconstructed.Add(lambdas[id].Mul(shares[id]))
		}
		assert.True(t, reconstructed.Equal(secret), "All parties should reconstruct the secret")
	}

	// Test 2: Any threshold subset can reconstruct the secret
	{
		// Take first threshold parties
		subset := partyIDs[:threshold]
		t.Logf("Subset for signing: %v", subset)

		lambdas := polynomial.Lagrange(group, subset)
		reconstructed := group.NewScalar()
		for _, id := range subset {
			reconstructed.Add(lambdas[id].Mul(shares[id]))
		}
		assert.True(t, reconstructed.Equal(secret), "Threshold subset should reconstruct the secret")
	}

	// Test 3: Less than threshold parties cannot reconstruct
	{
		subset := partyIDs[:threshold-1]
		lambdas := polynomial.Lagrange(group, subset)
		reconstructed := group.NewScalar()
		for _, id := range subset {
			reconstructed.Add(lambdas[id].Mul(shares[id]))
		}
		assert.False(t, reconstructed.Equal(secret), "Less than threshold should not reconstruct the secret")
	}

	// Test 4: Verify public key reconstruction
	{
		// Create verification shares (public shares)
		publicKey := secret.ActOnBase()
		verificationShares := make(map[party.ID]curve.Point)
		for id, share := range shares {
			verificationShares[id] = share.ActOnBase()
		}

		// Any threshold subset should reconstruct the public key
		subset := partyIDs[:threshold]
		lambdas := polynomial.Lagrange(group, subset)

		reconstructedPK := group.NewPoint()
		for _, id := range subset {
			reconstructedPK = reconstructedPK.Add(lambdas[id].Act(verificationShares[id]))
		}

		require.True(t, reconstructedPK.Equal(publicKey),
			"Threshold subset should reconstruct the public key correctly")
		t.Logf("Successfully reconstructed public key from %d parties", threshold)
	}

	// Test 5: Different threshold subsets should all reconstruct same public key
	{
		publicKey := secret.ActOnBase()
		verificationShares := make(map[party.ID]curve.Point)
		for id, share := range shares {
			verificationShares[id] = share.ActOnBase()
		}

		// Try different subsets
		subset1 := partyIDs[:threshold]      // [a, b, c]
		subset2 := partyIDs[1 : threshold+1] // [b, c, d]
		subset3 := partyIDs[2 : threshold+2] // [c, d, e]

		for i, subset := range [][]party.ID{subset1, subset2, subset3} {
			lambdas := polynomial.Lagrange(group, subset)
			reconstructedPK := group.NewPoint()
			for _, id := range subset {
				reconstructedPK = reconstructedPK.Add(lambdas[id].Act(verificationShares[id]))
			}
			assert.True(t, reconstructedPK.Equal(publicKey),
				"Subset %d should reconstruct the same public key", i+1)
		}
	}
}
