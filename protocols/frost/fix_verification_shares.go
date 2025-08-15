package frost

import (
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// VerifyShareConsistency checks if the verification shares are consistent with the public key
func VerifyShareConsistency(publicKey curve.Point, verificationShares map[party.ID]curve.Point, partyIDs []party.ID, threshold int) bool {
	// Take any threshold subset
	if len(partyIDs) < threshold {
		return false
	}

	subset := partyIDs[:threshold]
	lambdas := polynomial.Lagrange(publicKey.Curve(), subset)

	// Reconstruct public key from verification shares
	reconstructed := publicKey.Curve().NewPoint()
	for _, id := range subset {
		yShare := verificationShares[id]
		if yShare == nil {
			return false
		}
		reconstructed = reconstructed.Add(lambdas[id].Act(yShare))
	}

	return reconstructed.Equal(publicKey)
}

// FixVerificationShares adjusts verification shares to ensure they properly reconstruct the public key
// This is a workaround for the keygen issue
func FixVerificationShares(config *Config) {
	// This is a no-op for now, but could be used to fix the shares if needed
	// The proper fix should be in the keygen protocol itself
}
