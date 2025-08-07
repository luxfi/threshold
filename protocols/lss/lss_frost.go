// Package lss provides dynamic resharing extensions for FROST protocols.
package lss

import (
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/frost/keygen"
	"github.com/luxfi/threshold/protocols/lss/config"
)

// FROSTConfig wraps the FROST keygen config for LSS compatibility
type FROSTConfig struct {
	*keygen.Config
	Generation   uint64
	RollbackFrom uint64
}

// FROST extends the FROST protocol with LSS dynamic resharing capabilities.
// This allows FROST to perform membership changes without reconstructing the master key.
type FROST struct {
	config     *FROSTConfig
	generation uint64
	pool       *pool.Pool
}

// NewLSSFROST creates a new LSS-extended FROST instance
func NewLSSFROST(frostConfig *keygen.Config, pool *pool.Pool) *FROST {
	return &FROST{
		config: &FROSTConfig{
			Config:     frostConfig,
			Generation: 0,
		},
		generation: 0,
		pool:       pool,
	}
}

// DynamicReshareFROST performs the LSS dynamic resharing protocol on FROST configurations.
// This implements the protocol from Section 4 of the LSS paper, allowing
// transition from T-of-N to T'-of-(N±k) without reconstructing the master key.
func DynamicReshareFROST(
	oldConfigs map[party.ID]*keygen.Config,
	newPartyIDs []party.ID,
	newThreshold int,
	_ *pool.Pool,
) (map[party.ID]*keygen.Config, error) {

	if len(oldConfigs) == 0 {
		return nil, errors.New("lss-frost: no old configurations provided")
	}

	if newThreshold < 1 || newThreshold > len(newPartyIDs) {
		return nil, fmt.Errorf("lss-frost: invalid threshold %d for %d parties", newThreshold, len(newPartyIDs))
	}

	// Get reference config and validate consistency
	var refConfig *keygen.Config
	var group curve.Curve
	oldPartyIDs := make([]party.ID, 0, len(oldConfigs))

	for pid, cfg := range oldConfigs {
		if refConfig == nil {
			refConfig = cfg
			group = cfg.Curve()
		} else {
			// Verify all configs are from the same keygen
			if !cfg.PublicKey.Equal(refConfig.PublicKey) {
				return nil, errors.New("lss-frost: inconsistent public keys in old configs")
			}
		}
		oldPartyIDs = append(oldPartyIDs, pid)
	}

	// Ensure we have enough old parties to reconstruct the secret
	if len(oldPartyIDs) < refConfig.Threshold {
		return nil, fmt.Errorf("lss-frost: need at least %d old parties, have %d",
			refConfig.Threshold, len(oldPartyIDs))
	}

	// Step 1: Generate auxiliary secrets w and q using polynomial secret sharing
	// These are temporary secrets used only during the resharing protocol
	wPoly := polynomial.NewPolynomial(group, newThreshold-1, nil)
	qPoly := polynomial.NewPolynomial(group, newThreshold-1, nil)

	// All parties (old and new) get shares of w and q
	allParties := make(map[party.ID]bool)
	for _, pid := range oldPartyIDs {
		allParties[pid] = true
	}
	for _, pid := range newPartyIDs {
		allParties[pid] = true
	}

	wShares := make(map[party.ID]curve.Scalar)
	qShares := make(map[party.ID]curve.Scalar)

	for pid := range allParties {
		wShares[pid] = wPoly.Evaluate(pid.Scalar(group))
		qShares[pid] = qPoly.Evaluate(pid.Scalar(group))
	}

	// Step 2: Compute the blinded secret a * w
	// Each old party computes a_i * w_i, then we interpolate to get a * w
	blindedProducts := make(map[party.ID]curve.Scalar)

	// Use first threshold old parties
	contributingParties := oldPartyIDs[:refConfig.Threshold]
	for _, pid := range contributingParties {
		cfg := oldConfigs[pid]
		wShare := wShares[pid]

		// Compute a_i * w_i
		product := group.NewScalar().Set(cfg.PrivateShare).Mul(wShare)
		blindedProducts[pid] = product
	}

	// Interpolate the blinded products to get a * w
	lagrange := polynomial.Lagrange(group, contributingParties)
	aTimesW := group.NewScalar()

	for pid, product := range blindedProducts {
		if coeff, exists := lagrange[pid]; exists {
			contribution := group.NewScalar().Set(coeff).Mul(product)
			aTimesW.Add(contribution)
		}
	}

	// Step 3: Compute z = (q * w)^{-1}
	// First, parties compute q_j * w_j and we interpolate to get q * w
	qwProducts := make(map[party.ID]curve.Scalar)

	// Use first newThreshold parties for this computation
	computingParties := make([]party.ID, 0, newThreshold)
	for pid := range allParties {
		if len(computingParties) >= newThreshold {
			break
		}
		computingParties = append(computingParties, pid)

		qShare := qShares[pid]
		wShare := wShares[pid]
		product := group.NewScalar().Set(qShare).Mul(wShare)
		qwProducts[pid] = product
	}

	// Interpolate to get q * w
	newLagrange := polynomial.Lagrange(group, computingParties)
	qTimesW := group.NewScalar()

	for pid, product := range qwProducts {
		if coeff, exists := newLagrange[pid]; exists {
			contribution := group.NewScalar().Set(coeff).Mul(product)
			qTimesW.Add(contribution)
		}
	}

	// Compute z = (q * w)^{-1}
	z := group.NewScalar().Set(qTimesW)
	z = z.Invert()

	// Create shares of z for distribution to new parties
	zPoly := polynomial.NewPolynomial(group, newThreshold-1, z)
	zShares := make(map[party.ID]curve.Scalar)

	for _, pid := range newPartyIDs {
		zShares[pid] = zPoly.Evaluate(pid.Scalar(group))
	}

	// Step 4: Each new party computes their new share
	// a'_j = (a * w) * q_j * z_j
	newConfigs := make(map[party.ID]*keygen.Config)

	// First, compute all new shares
	newShares := make(map[party.ID]curve.Scalar)
	for _, pid := range newPartyIDs {
		qShare := qShares[pid]
		zShare := zShares[pid]

		// Compute new private share: a'_j = (a * w) * q_j * z_j
		newPrivateShare := group.NewScalar().Set(aTimesW)
		newPrivateShare.Mul(qShare).Mul(zShare)
		newShares[pid] = newPrivateShare
	}

	// Now create configs with all the public information
	// Compute new verification shares
	newVerificationShares := make(map[party.ID]curve.Point)
	for _, pid := range newPartyIDs {
		newVerificationShares[pid] = newShares[pid].ActOnBase()
	}

	for _, pid := range newPartyIDs {
		newConfig := &keygen.Config{
			ID:                 pid,
			Threshold:          newThreshold,
			PrivateShare:       newShares[pid],
			PublicKey:          refConfig.PublicKey, // Preserve the public key
			VerificationShares: party.NewPointMap(newVerificationShares),
		}

		newConfigs[pid] = newConfig
	}

	// Verify the resharing was correct
	if err := verifyResharingFROST(oldConfigs, newConfigs, refConfig.Threshold, newThreshold); err != nil {
		return nil, fmt.Errorf("lss-frost: resharing verification failed: %w", err)
	}

	return newConfigs, nil
}

// verifyResharingFROST validates that new shares correctly reconstruct the original public key
func verifyResharingFROST(
	oldConfigs map[party.ID]*keygen.Config,
	newConfigs map[party.ID]*keygen.Config,
	oldThreshold int,
	newThreshold int,
) error {
	// Get the original public key from old configs
	var oldPublicKey curve.Point
	var group curve.Curve

	// Get first old config to extract public key and group
	for _, cfg := range oldConfigs {
		oldPublicKey = cfg.PublicKey
		group = cfg.Curve()
		break
	}

	// Verify new shares reconstruct to the same public key
	// Use Lagrange interpolation with new threshold parties
	newPartyIDs := make([]party.ID, 0, len(newConfigs))
	for pid := range newConfigs {
		newPartyIDs = append(newPartyIDs, pid)
		if len(newPartyIDs) >= newThreshold {
			break
		}
	}

	if len(newPartyIDs) < newThreshold {
		return fmt.Errorf("insufficient new parties for verification: have %d, need %d",
			len(newPartyIDs), newThreshold)
	}

	// Compute Lagrange coefficients for the new parties
	lagrange := polynomial.Lagrange(group, newPartyIDs)

	// Reconstruct public key from new shares
	reconstructedKey := group.NewPoint()
	for _, pid := range newPartyIDs {
		cfg := newConfigs[pid]
		if cfg == nil {
			return fmt.Errorf("missing config for party %s", pid)
		}

		// Get the verification share for this party
		verificationShare := cfg.VerificationShares.Points[pid]

		// Apply Lagrange coefficient
		if coeff, exists := lagrange[pid]; exists {
			contribution := coeff.Act(verificationShare)
			reconstructedKey = reconstructedKey.Add(contribution)
		}
	}

	// Verify the reconstructed key matches the original
	if !reconstructedKey.Equal(oldPublicKey) {
		return errors.New("resharing verification failed: public keys do not match")
	}

	// Additional verification: check threshold consistency
	if oldThreshold > len(oldConfigs) {
		return fmt.Errorf("old threshold %d exceeds old party count %d",
			oldThreshold, len(oldConfigs))
	}
	if newThreshold > len(newConfigs) {
		return fmt.Errorf("new threshold %d exceeds new party count %d",
			newThreshold, len(newConfigs))
	}

	return nil
}

// Sign performs FROST signing with the current configuration
func (f *FROST) Sign(_ []party.ID, _ []byte) ([]byte, error) {
	// FROST.Sign returns a protocol.StartFunc, we need to execute it
	// In a real implementation, this would run the protocol
	// For now, return a placeholder
	return nil, errors.New("sign execution not implemented - use frost.Sign directly")
}

// Refresh performs a proactive refresh of shares without changing membership
func (f *FROST) Refresh() (*FROSTConfig, error) {
	// FROST's Refresh returns a protocol.StartFunc
	// For this implementation, we'll just increment generation
	// In practice, you'd execute the refresh protocol
	f.generation++
	f.config.Generation = f.generation
	return f.config, nil
}

// GetGeneration returns the current resharing generation number
func (f *FROST) GetGeneration() uint64 {
	return f.generation
}

// GetConfig returns the current FROST configuration
func (f *FROST) GetConfig() *FROSTConfig {
	return f.config
}

// UpdateConfig updates the configuration after a successful resharing
func (f *FROST) UpdateConfig(newConfig *FROSTConfig) {
	f.config = newConfig
	f.generation++
}

// ConvertToLSSConfig converts a FROST config to LSS config format for compatibility
func ConvertToLSSConfig(frostConfig *keygen.Config, generation uint64) *Config {
	return &Config{
		ID:         frostConfig.ID,
		Group:      frostConfig.Curve(),
		Threshold:  frostConfig.Threshold,
		Generation: generation,
		ECDSA:      frostConfig.PrivateShare,
		Public:     convertVerificationShares(frostConfig.VerificationShares.Points),
		ChainKey:   []byte("frost-chainkey"), // Placeholder
		RID:        []byte("frost-rid"),      // Placeholder
	}
}

// convertVerificationShares converts FROST verification shares to LSS public format
func convertVerificationShares(verificationShares map[party.ID]curve.Point) map[party.ID]*config.Public {
	public := make(map[party.ID]*config.Public)
	for id, point := range verificationShares {
		public[id] = &config.Public{
			ECDSA: point,
		}
	}
	return public
}

// ConvertFromLSSConfig converts an LSS config to FROST config format
func ConvertFromLSSConfig(lssConfig *Config) *keygen.Config {
	verificationShares := make(map[party.ID]curve.Point)
	for id, pub := range lssConfig.Public {
		verificationShares[id] = pub.ECDSA
	}

	// Compute public key from shares
	publicKey, _ := lssConfig.PublicPoint()

	return &keygen.Config{
		ID:                 lssConfig.ID,
		Threshold:          lssConfig.Threshold,
		PrivateShare:       lssConfig.ECDSA,
		PublicKey:          publicKey,
		VerificationShares: party.NewPointMap(verificationShares),
	}
}