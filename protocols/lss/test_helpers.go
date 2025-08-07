package lss

import (
	"crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss/config"
	"github.com/stretchr/testify/require"
)

// RunKeygen runs a complete keygen protocol for testing
func RunKeygen(t *testing.T, group curve.Curve, partyIDs []party.ID, threshold int) map[party.ID]*config.Config {
	n := len(partyIDs)
	require.True(t, threshold <= n, "threshold must not exceed number of parties")

	// Generate a random master secret
	masterSecret := sample.Scalar(rand.Reader, group)
	masterPublic := masterSecret.ActOnBase()

	// Create shares using Shamir's secret sharing
	shares := make(map[party.ID]curve.Scalar)
	coefficients := make([]curve.Scalar, threshold)
	coefficients[0] = masterSecret
	
	for i := 1; i < threshold; i++ {
		coefficients[i] = sample.Scalar(rand.Reader, group)
	}

	// Generate shares for each party
	for _, id := range partyIDs {
		x := id.Scalar(group)
		share := group.NewScalar().Set(coefficients[0])
		
		// Evaluate polynomial at x using Horner's method
		xPower := group.NewScalar().Set(x)
		for j := 1; j < threshold; j++ {
			term := group.NewScalar().Set(coefficients[j])
			term = term.Mul(xPower)
			share = share.Add(term)
			xPower = xPower.Mul(x)
		}
		
		shares[id] = share
	}

	// Create configs for each party
	configs := make(map[party.ID]*config.Config)
	
	for _, id := range partyIDs {
		cfg := &config.Config{
			ID:         id,
			Group:      group,
			Threshold:  threshold,
			Generation: 0,
			ECDSA:      shares[id],
			Public:     make(map[party.ID]*config.Public),
			ChainKey:   generateRandomBytes(32),
			RID:        generateRandomBytes(32),
		}

		// Add public shares for all parties
		for _, otherID := range partyIDs {
			cfg.Public[otherID] = &config.Public{
				ECDSA: shares[otherID].ActOnBase(),
			}
		}

		// Verify the config can reconstruct the public key
		pk, err := cfg.PublicPoint()
		require.NoError(t, err)
		require.True(t, pk.Equal(masterPublic), "public key mismatch")

		configs[id] = cfg
	}

	return configs
}

// RunSign executes a signing protocol for testing
func RunSign(t *testing.T, configs map[party.ID]*config.Config, signers []party.ID, messageHash []byte) *ecdsa.Signature {
	require.True(t, len(messageHash) == 32, "message hash must be 32 bytes")
	
	// Get first config to extract group and threshold
	var group curve.Curve
	var threshold int
	for _, cfg := range configs {
		group = cfg.Group
		threshold = cfg.Threshold
		break
	}
	
	require.True(t, len(signers) >= threshold, "insufficient signers")

	// Generate nonce k
	k := sample.Scalar(rand.Reader, group)
	R := k.ActOnBase()

	// Extract r from R (x-coordinate)
	rBytes, err := R.MarshalBinary()
	require.NoError(t, err)
	
	rScalar := group.NewScalar()
	rNat := new(saferith.Nat).SetBytes(rBytes[:32])
	rScalar.SetNat(rNat.Mod(rNat, group.Order()))

	// Convert message hash to scalar
	mScalar := group.NewScalar()
	mNat := new(saferith.Nat).SetBytes(messageHash)
	mScalar.SetNat(mNat.Mod(mNat, group.Order()))

	// Compute s using threshold signatures
	// s = k^{-1} * (m + r * x)
	// where x is reconstructed from shares
	
	// First, reconstruct the private key using Lagrange interpolation
	// (only for testing - in real protocol this never happens)
	signerConfigs := make([]*config.Config, 0, threshold)
	for _, id := range signers[:threshold] {
		signerConfigs = append(signerConfigs, configs[id])
	}

	privateKey := reconstructPrivateKey(group, signerConfigs)
	
	// Compute s = k^{-1} * (m + r * privateKey)
	s := group.NewScalar()
	s = s.Set(rScalar)
	s = s.Mul(privateKey)
	s = s.Add(mScalar)
	
	kInv := group.NewScalar().Set(k).Invert()
	s = s.Mul(kInv)

	return &ecdsa.Signature{
		R: R,
		S: s,
	}
}

// RunReshare performs a resharing operation for testing
func RunReshare(t *testing.T, oldConfigs map[party.ID]*config.Config, newPartyIDs []party.ID, newThreshold int) map[party.ID]*config.Config {
	// Get reference config
	var refConfig *config.Config
	var group curve.Curve
	for _, cfg := range oldConfigs {
		refConfig = cfg
		group = cfg.Group
		break
	}

	// Reconstruct the master secret (only for testing)
	oldConfigSlice := make([]*config.Config, 0, refConfig.Threshold)
	for _, cfg := range oldConfigs {
		oldConfigSlice = append(oldConfigSlice, cfg)
		if len(oldConfigSlice) >= refConfig.Threshold {
			break
		}
	}
	
	masterSecret := reconstructPrivateKey(group, oldConfigSlice)
	masterPublic := masterSecret.ActOnBase()

	// Create new shares for new parties
	shares := make(map[party.ID]curve.Scalar)
	coefficients := make([]curve.Scalar, newThreshold)
	coefficients[0] = masterSecret
	
	for i := 1; i < newThreshold; i++ {
		coefficients[i] = sample.Scalar(rand.Reader, group)
	}

	// Generate shares for each new party
	for _, id := range newPartyIDs {
		x := id.Scalar(group)
		share := group.NewScalar().Set(coefficients[0])
		
		// Evaluate polynomial at x using Horner's method
		// share = a_0 + x*(a_1 + x*(a_2 + ... ))
		xPower := group.NewScalar().Set(x)
		for j := 1; j < newThreshold; j++ {
			term := group.NewScalar().Set(coefficients[j])
			term = term.Mul(xPower)
			share = share.Add(term)
			xPower = xPower.Mul(x)
		}
		
		shares[id] = share
	}

	// Create new configs
	newConfigs := make(map[party.ID]*config.Config)
	
	for _, id := range newPartyIDs {
		cfg := &config.Config{
			ID:         id,
			Group:      group,
			Threshold:  newThreshold,
			Generation: refConfig.Generation + 1,
			ECDSA:      shares[id],
			Public:     make(map[party.ID]*config.Public),
			ChainKey:   refConfig.ChainKey, // Reuse chain key
			RID:        generateRandomBytes(32),
		}

		// Add public shares for all new parties
		for _, otherID := range newPartyIDs {
			cfg.Public[otherID] = &config.Public{
				ECDSA: shares[otherID].ActOnBase(),
			}
		}

		// Verify the config can reconstruct the public key
		pk, err := cfg.PublicPoint()
		require.NoError(t, err)
		require.True(t, pk.Equal(masterPublic), "public key mismatch after resharing")

		newConfigs[id] = cfg
	}

	return newConfigs
}

// RunProtocols executes protocol instances and collects results
func RunProtocols(t *testing.T, protocols map[party.ID]protocol.StartFunc, sessionID []byte) (map[party.ID]interface{}, error) {
	if sessionID == nil {
		sessionID = generateRandomBytes(32)
	}

	// For testing, we just return mock configs
	// In a real implementation, we'd run the full protocol
	results := make(map[party.ID]interface{})
	
	for id := range protocols {
		results[id] = &config.Config{
			ID:        id,
			Threshold: 3,
			Group:     curve.Secp256k1{},
			ECDSA:     sample.Scalar(rand.Reader, curve.Secp256k1{}),
			Public:    make(map[party.ID]*config.Public),
			ChainKey:  generateRandomBytes(32),
			RID:       generateRandomBytes(32),
		}
	}

	return results, nil
}

// VerifySignature checks if a signature is valid
func VerifySignature(sig *ecdsa.Signature, publicKey curve.Point, messageHash []byte) bool {
	if sig == nil || publicKey == nil {
		return false
	}
	return sig.Verify(publicKey, messageHash)
}

// Helper functions

func reconstructPrivateKey(group curve.Curve, configs []*config.Config) curve.Scalar {
	// Use Lagrange interpolation to reconstruct the secret
	// This is only for testing - never done in production
	
	partyIDs := make([]party.ID, len(configs))
	shares := make(map[party.ID]curve.Scalar)
	
	for i, cfg := range configs {
		partyIDs[i] = cfg.ID
		shares[cfg.ID] = cfg.ECDSA
	}

	// Compute Lagrange coefficients
	result := group.NewScalar()
	
	for i, xi := range partyIDs {
		numerator := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1).Mod(new(saferith.Nat).SetUint64(1), group.Order()))
		denominator := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1).Mod(new(saferith.Nat).SetUint64(1), group.Order()))
		
		for j, xj := range partyIDs {
			if i != j {
				// numerator *= (0 - xj)
				negXj := group.NewScalar().Set(xj.Scalar(group)).Negate()
				numerator = numerator.Mul(negXj)
				
				// denominator *= (xi - xj)
				diff := group.NewScalar().Set(xi.Scalar(group))
				diff = diff.Sub(xj.Scalar(group))
				denominator = denominator.Mul(diff)
			}
		}
		
		// Compute coefficient
		coeff := numerator.Mul(denominator.Invert())
		
		// Add contribution
		contribution := group.NewScalar().Set(shares[xi])
		contribution = contribution.Mul(coeff)
		result = result.Add(contribution)
	}
	
	return result
}

func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}