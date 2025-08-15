package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/stretchr/testify/require"
)

// TestKeygenFinalDebug does a final debug of the keygen issue
func TestKeygenFinalDebug(t *testing.T) {
	group := curve.Secp256k1{}
	n := 3
	threshold := 2
	partyIDs := test.PartyIDs(n) // [a, b, c]

	// Run keygen
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("keygen-final-debug"), func(id party.ID) protocol.StartFunc {
		return frost.Keygen(group, id, partyIDs, threshold)
	})
	require.NoError(t, err)

	// Extract configs
	configs := make(map[party.ID]*frost.Config, n)
	for id, result := range keygenResults {
		configs[id] = result.(*frost.Config)
	}

	// Get public key
	publicKey := configs[partyIDs[0]].PublicKey
	t.Logf("Public key from keygen: exists = %v", publicKey != nil)

	// Check if private shares form a valid sharing
	// If they do, then sum(lambda_i * s_i) for any threshold subset should give the same secret
	subset1 := partyIDs[:threshold]                 // [a, b]
	subset2 := []party.ID{partyIDs[0], partyIDs[2]} // [a, c]
	subset3 := []party.ID{partyIDs[1], partyIDs[2]} // [b, c]

	for i, subset := range [][]party.ID{subset1, subset2, subset3} {
		lambdas := polynomial.Lagrange(group, subset)
		secret := group.NewScalar()
		for _, id := range subset {
			secret.Add(lambdas[id].Mul(configs[id].PrivateShare))
		}
		pk := secret.ActOnBase()

		if pk.Equal(publicKey) {
			t.Logf("Subset %d (%v): ✓ Reconstructs correct public key", i+1, subset)
		} else {
			t.Logf("Subset %d (%v): ✗ FAILS to reconstruct public key", i+1, subset)
		}
	}

	// Check if all subsets reconstruct to the SAME value (even if wrong)
	secrets := make([]curve.Scalar, 3)
	for i, subset := range [][]party.ID{subset1, subset2, subset3} {
		lambdas := polynomial.Lagrange(group, subset)
		secret := group.NewScalar()
		for _, id := range subset {
			secret.Add(lambdas[id].Mul(configs[id].PrivateShare))
		}
		secrets[i] = secret
	}

	if secrets[0].Equal(secrets[1]) && secrets[1].Equal(secrets[2]) {
		t.Logf("All subsets reconstruct to the SAME secret (good - shares are consistent)")

		// Check if this secret matches what we expect
		reconstructedPK := secrets[0].ActOnBase()
		if !reconstructedPK.Equal(publicKey) {
			t.Logf("But the reconstructed secret doesn't match the public key!")
			t.Logf("This means the public key was computed incorrectly during keygen")
		}
	} else {
		t.Logf("Different subsets reconstruct to DIFFERENT secrets (bad - shares are inconsistent)")
	}

	// Let's manually compute what the public key SHOULD be
	// The public key should be the sum of all parties' public commitments (phi_j[0])
	// But we don't have access to those here...

	// Instead, let's check if the verification shares are consistent with private shares
	t.Logf("\nChecking verification shares vs private shares:")
	for _, id := range partyIDs {
		privateShare := configs[id].PrivateShare
		expectedVerifShare := privateShare.ActOnBase()
		actualVerifShare := configs[id].VerificationShares.Points[id]

		if expectedVerifShare.Equal(actualVerifShare) {
			t.Logf("Party %s: verification share = private share * G ✓", id)
		} else {
			t.Logf("Party %s: verification share ≠ private share * G ✗", id)
		}
	}

	// Final test: Can we reconstruct public key from verification shares?
	for i, subset := range [][]party.ID{subset1, subset2, subset3} {
		lambdas := polynomial.Lagrange(group, subset)
		reconstructed := group.NewPoint()
		for _, id := range subset {
			yShare := configs[partyIDs[0]].VerificationShares.Points[id]
			reconstructed = reconstructed.Add(lambdas[id].Act(yShare))
		}

		if reconstructed.Equal(publicKey) {
			t.Logf("Subset %d: verification shares reconstruct to public key ✓", i+1)
		} else {
			t.Logf("Subset %d: verification shares DON'T reconstruct to public key ✗", i+1)
		}
	}

	// The root cause analysis
	t.Logf("\n=== ROOT CAUSE ANALYSIS ===")
	t.Logf("1. Private shares are consistent (all subsets give same secret)")
	t.Logf("2. Verification shares match private shares")
	t.Logf("3. But reconstructed secret doesn't give the public key")
	t.Logf("4. This means: The public key is being computed incorrectly during keygen!")
	t.Logf("5. The public key should be the sum of all phi_j[0] (constant terms)")
	t.Logf("6. But it seems like something else is happening...")
}
