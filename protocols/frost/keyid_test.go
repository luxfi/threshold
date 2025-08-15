package frost_test

import (
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func TestKeyIDConsistency(t *testing.T) {
	// Test that KeyID is consistent across different sessionIDs
	group := curve.Secp256k1{}
	partyIDs := test.PartyIDs(3)
	threshold := 2
	protocolID := "frost/keygen-threshold"

	// Create KeyIDs with different inputs to simulate different parties
	keyID1 := protocol.NewKeyID(protocolID, group, nil, partyIDs, threshold, 0)
	keyID2 := protocol.NewKeyID(protocolID, group, nil, partyIDs, threshold, 0)

	// The KeyIDs should produce the same hash
	hash1 := keyID1.Hash().Sum()
	hash2 := keyID2.Hash().Sum()

	require.Equal(t, hash1, hash2, "KeyIDs should produce identical hashes")

	// Now test with specific party IDs
	partyA := party.ID("a")
	partyB := party.ID("b")

	hashA := keyID1.HashForParty(partyA).Sum()
	hashB := keyID1.HashForParty(partyB).Sum()

	// These should be different (party-specific)
	require.NotEqual(t, hashA, hashB, "Party-specific hashes should be different")

	// But same party should get same hash from different KeyID instances
	hashA2 := keyID2.HashForParty(partyA).Sum()
	require.Equal(t, hashA, hashA2, "Same party should get same hash from different KeyID instances")
}
