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

// TestKeygenVerificationShares tests that keygen produces correct verification shares
func TestKeygenVerificationShares(t *testing.T) {
	n := 5
	threshold := 3
	partyIDs := test.PartyIDs(n)
	group := curve.Secp256k1{}
	
	t.Logf("Party IDs: %v", partyIDs)
	
	// Run keygen
	keygenResults, err := test.RunProtocol(t, partyIDs, []byte("keygen-verify-shares"), func(id party.ID) protocol.StartFunc {
		return frost.Keygen(group, id, partyIDs, threshold)
	})
	require.NoError(t, err, "keygen failed")
	require.Len(t, keygenResults, n, "missing keygen results")
	
	// Extract configs
	configs := make(map[party.ID]*frost.Config)
	for id, result := range keygenResults {
		cfg, ok := result.(*frost.Config)
		require.True(t, ok, "invalid keygen result type")
		require.NotNil(t, cfg, "nil config")
		configs[id] = cfg
		t.Logf("Party %s: private share exists, public key exists", id)
	}
	
	// Get reference public key
	publicKey := configs[partyIDs[0]].PublicKey
	t.Logf("Public key from keygen: %v", publicKey)
	
	// Test 1: All parties have the same public key
	for id, cfg := range configs {
		require.True(t, cfg.PublicKey.Equal(publicKey), "Party %s has different public key", id)
	}
	
	// Test 2: Verify that each party's verification share matches their private share
	for id, cfg := range configs {
		// Y_i should equal s_i * G
		expectedShare := cfg.PrivateShare.ActOnBase()
		actualShare := cfg.VerificationShares.Points[id]
		require.True(t, expectedShare.Equal(actualShare), 
			"Party %s verification share doesn't match private share", id)
	}
	
	// Test 2b: Verify all configs have the same verification shares
	refConfig := configs[partyIDs[0]]
	for id, cfg := range configs {
		for pid := range cfg.VerificationShares.Points {
			refShare := refConfig.VerificationShares.Points[pid]
			cfgShare := cfg.VerificationShares.Points[pid]
			require.True(t, refShare.Equal(cfgShare),
				"Party %s has different verification share for party %s", id, pid)
		}
	}
	
	// Test 3: Verify that any threshold subset can reconstruct the public key
	subsets := [][]party.ID{
		partyIDs[:threshold],      // [a, b, c]
		partyIDs[1:threshold+1],   // [b, c, d]
		partyIDs[2:threshold+2],   // [c, d, e]
	}
	
	for i, subset := range subsets {
		t.Logf("Testing subset %d: %v", i+1, subset)
		
		// Compute Lagrange coefficients for this subset
		lambdas := polynomial.Lagrange(group, subset)
		
		// Reconstruct public key from verification shares
		reconstructed := group.NewPoint()
		for _, id := range subset {
			// Get verification share from any config (they should all have the same shares)
			yShare := configs[partyIDs[0]].VerificationShares.Points[id]
			contribution := lambdas[id].Act(yShare)
			t.Logf("  ID %s: lambda=%v, yShare exists=%v", id, lambdas[id], yShare != nil)
			reconstructed = reconstructed.Add(contribution)
		}
		
		require.True(t, reconstructed.Equal(publicKey),
			"Subset %d failed to reconstruct public key", i+1)
		t.Logf("✓ Subset %d successfully reconstructed public key", i+1)
	}
	
	// Test 4: Verify the sum of all verification shares weighted by Lagrange coefficients
	// equals the public key (using all parties)
	{
		lambdas := polynomial.Lagrange(group, partyIDs)
		reconstructed := group.NewPoint()
		for _, id := range partyIDs {
			yShare := configs[partyIDs[0]].VerificationShares.Points[id]
			reconstructed = reconstructed.Add(lambdas[id].Act(yShare))
		}
		require.True(t, reconstructed.Equal(publicKey),
			"All parties failed to reconstruct public key")
		t.Logf("✓ All parties successfully reconstructed public key")
	}
	
	// Test 5: Verify that the private shares also reconstruct correctly
	{
		// Using all parties
		lambdas := polynomial.Lagrange(group, partyIDs)
		reconstructedSecret := group.NewScalar()
		for _, id := range partyIDs {
			reconstructedSecret.Add(lambdas[id].Mul(configs[id].PrivateShare))
		}
		// The reconstructed secret * G should equal the public key
		reconstructedPK := reconstructedSecret.ActOnBase()
		require.True(t, reconstructedPK.Equal(publicKey),
			"Reconstructed secret doesn't match public key")
		t.Logf("✓ Private shares correctly reconstruct to match public key")
	}
	
	// Test 6: Same test with threshold subset
	{
		subset := partyIDs[:threshold]
		lambdas := polynomial.Lagrange(group, subset)
		reconstructedSecret := group.NewScalar()
		for _, id := range subset {
			reconstructedSecret.Add(lambdas[id].Mul(configs[id].PrivateShare))
		}
		reconstructedPK := reconstructedSecret.ActOnBase()
		require.True(t, reconstructedPK.Equal(publicKey),
			"Threshold subset: reconstructed secret doesn't match public key")
		t.Logf("✓ Threshold subset private shares correctly reconstruct")
	}
}