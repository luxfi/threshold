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

// TestFROSTMath tests the mathematical foundation of FROST
func TestFROSTMath(t *testing.T) {
	group := curve.Secp256k1{}
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n)

	// Run keygen
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("test-math"), func(id party.ID) protocol.StartFunc {
		return Keygen(group, id, partyIDs, threshold)
	})
	require.NoError(t, err)

	configs := make(map[party.ID]*Config, n)
	for id, result := range keygenResults {
		configs[id] = result.(*Config)
	}

	// Get the public key and verification shares
	Y := configs[partyIDs[0]].PublicKey
	verificationShares := configs[partyIDs[0]].VerificationShares.Points

	// Test signing with all parties
	signers := partyIDs
	lambdas := polynomial.Lagrange(group, signers)

	// The key equation in FROST:
	// z = sum(z_i) where z_i = d_i + e_i*ρ_i + λ_i*s_i*c
	// For the signature to verify: z*G = R + c*Y
	// Where R = sum(D_i) + sum(ρ_i*E_i)

	// Let's verify the fundamental property:
	// sum(λ_i * s_i) should equal the secret key x when using all parties
	// And Y = x*G

	// Compute sum(λ_i * Y_i) where Y_i = s_i*G
	reconstructed := group.NewPoint()
	for _, id := range signers {
		Yi := verificationShares[id]
		lambdaYi := lambdas[id].Act(Yi)
		reconstructed = reconstructed.Add(lambdaYi)
		t.Logf("Party %s: λ_i=%v, Y_i=%v, λ_i*Y_i=%v", id, lambdas[id], Yi, lambdaYi)
	}

	t.Logf("Reconstructed Y: %v", reconstructed)
	t.Logf("Original Y: %v", Y)
	t.Logf("Match: %v", reconstructed.Equal(Y))

	// The issue is that with FROST keygen, the shares s_i come from summing
	// evaluations of n degree-t polynomials. This means:
	// s_i = f_1(i) + f_2(i) + ... + f_n(i)
	// where each f_j is a degree-t polynomial from party j
	//
	// The secret x = f_1(0) + f_2(0) + ... + f_n(0)
	//
	// For Lagrange interpolation to work with threshold parties, we need
	// the shares to come from a single degree-t polynomial.
	//
	// FROST handles this by using ALL n parties' shares during keygen,
	// but then allowing any threshold subset to sign. The trick is that
	// the Lagrange coefficients are computed for the signing subset,
	// not for reconstruction of the secret.

	// Test with threshold subset
	subset := partyIDs[:threshold]
	subsetLambdas := polynomial.Lagrange(group, subset)

	reconstructedSubset := group.NewPoint()
	for _, id := range subset {
		Yi := verificationShares[id]
		lambdaYi := subsetLambdas[id].Act(Yi)
		reconstructedSubset = reconstructedSubset.Add(lambdaYi)
		t.Logf("Subset Party %s: λ_i=%v, Y_i=%v, λ_i*Y_i=%v", id, subsetLambdas[id], Yi, lambdaYi)
	}

	t.Logf("Subset Reconstructed Y: %v", reconstructedSubset)
	t.Logf("Original Y: %v", Y)
	t.Logf("Subset Match: %v", reconstructedSubset.Equal(Y))

	// This will fail because the shares are not from a single polynomial
	// This is the core issue with the current implementation
}
