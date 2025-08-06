// Package lss provides dynamic resharing extensions for CMP and FROST protocols.
package lss

import (
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/cmp/config"
)

// CMP extends the CMP protocol with LSS dynamic resharing capabilities.
// This allows CMP to perform membership changes without reconstructing the master key.
type CMP struct {
	config     *config.Config
	generation uint64
	pool       *pool.Pool
}

// NewLSSCMP creates a new LSS-extended CMP instance
func NewLSSCMP(cmpConfig *config.Config, pool *pool.Pool) *CMP {
	return &CMP{
		config:     cmpConfig,
		generation: 0,
		pool:       pool,
	}
}

// DynamicReshare performs the LSS dynamic resharing protocol on CMP configurations.
// This implements the protocol from Section 4 of the LSS paper, allowing
// transition from T-of-N to T'-of-(N±k) without reconstructing the master key.
func DynamicReshareCMP(
	oldConfigs map[party.ID]*config.Config,
	newPartyIDs []party.ID,
	newThreshold int,
	pool *pool.Pool,
) (map[party.ID]*config.Config, error) {
	
	if len(oldConfigs) == 0 {
		return nil, errors.New("lss-cmp: no old configurations provided")
	}
	
	if newThreshold < 1 || newThreshold > len(newPartyIDs) {
		return nil, fmt.Errorf("lss-cmp: invalid threshold %d for %d parties", newThreshold, len(newPartyIDs))
	}
	
	// Get reference config and validate consistency
	var refConfig *config.Config
	var group curve.Curve
	oldPartyIDs := make([]party.ID, 0, len(oldConfigs))
	
	for pid, cfg := range oldConfigs {
		if refConfig == nil {
			refConfig = cfg
			group = cfg.Group
		} else {
			// Verify all configs are from the same keygen
			if !cfg.PublicPoint().Equal(refConfig.PublicPoint()) {
				return nil, errors.New("lss-cmp: inconsistent public keys in old configs")
			}
		}
		oldPartyIDs = append(oldPartyIDs, pid)
	}
	
	// Ensure we have enough old parties to reconstruct the secret
	if len(oldPartyIDs) < refConfig.Threshold {
		return nil, fmt.Errorf("lss-cmp: need at least %d old parties, have %d", 
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
		product := group.NewScalar().Set(cfg.ECDSA).Mul(wShare)
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
	if err := z.Invert(); err != nil {
		return nil, fmt.Errorf("lss-cmp: failed to invert q*w: %w", err)
	}
	
	// Create shares of z for distribution to new parties
	zPoly := polynomial.NewPolynomial(group, newThreshold-1, z)
	zShares := make(map[party.ID]curve.Scalar)
	
	for _, pid := range newPartyIDs {
		zShares[pid] = zPoly.Evaluate(pid.Scalar(group))
	}
	
	// Step 4: Each new party computes their new share
	// a'_j = (a * w) * q_j * z_j
	newConfigs := make(map[party.ID]*config.Config)
	
	for _, pid := range newPartyIDs {
		qShare := qShares[pid]
		zShare := zShares[pid]
		
		// Compute new ECDSA share: a'_j = (a * w) * q_j * z_j
		newECDSAShare := group.NewScalar().Set(aTimesW)
		newECDSAShare.Mul(qShare).Mul(zShare)
		
		// Create new CMP config with the reshared secret
		newConfig := &config.Config{
			Group:     group,
			ID:        pid,
			Threshold: newThreshold,
			ECDSA:     newECDSAShare,
			
			// For now, reuse auxiliary values from reference config
			// In production, these should be refreshed independently
			ElGamal:  refConfig.ElGamal,
			Paillier: refConfig.Paillier,
			RID:      refConfig.RID,
			ChainKey: refConfig.ChainKey,
			Public:   make(map[party.ID]*config.Public),
		}
		
		// Compute public key shares for all new parties
		for _, otherPID := range newPartyIDs {
			otherQShare := qShares[otherPID]
			otherZShare := zShares[otherPID]
			
			// Compute other party's share for verification
			otherShare := group.NewScalar().Set(aTimesW)
			otherShare.Mul(otherQShare).Mul(otherZShare)
			
			// Store public information
			newConfig.Public[otherPID] = &config.Public{
				ECDSA:    otherShare.ActOnBase(),
				ElGamal:  refConfig.Public[refConfig.ID].ElGamal,  // Temporary reuse
				Paillier: refConfig.Public[refConfig.ID].Paillier, // Temporary reuse
				Pedersen: refConfig.Public[refConfig.ID].Pedersen, // Temporary reuse
			}
		}
		
		newConfigs[pid] = newConfig
	}
	
	// Verify the resharing was correct
	if err := verifyResharingCMP(oldConfigs, newConfigs, refConfig.Threshold, newThreshold); err != nil {
		return nil, fmt.Errorf("lss-cmp: resharing verification failed: %w", err)
	}
	
	return newConfigs, nil
}

// verifyResharingCMP validates that new shares correctly reconstruct the original public key
func verifyResharingCMP(
	oldConfigs map[party.ID]*config.Config,
	newConfigs map[party.ID]*config.Config,
	oldThreshold int,
	newThreshold int,
) error {
	
	// Get original public key
	var originalPublicKey curve.Point
	for _, cfg := range oldConfigs {
		originalPublicKey = cfg.PublicPoint()
		break
	}
	
	// Compute public key from new shares
	var newPublicKey curve.Point
	for _, cfg := range newConfigs {
		newPublicKey = cfg.PublicPoint()
		break
	}
	
	// Verify they match
	if !originalPublicKey.Equal(newPublicKey) {
		return errors.New("public keys don't match after resharing")
	}
	
	return nil
}

// Sign performs CMP signing with the current configuration
func (c *CMP) Sign(signers []party.ID, message []byte) ([]byte, error) {
	return cmp.Sign(c.config, signers, message, c.pool)
}

// Refresh performs a proactive refresh of shares without changing membership
func (c *CMP) Refresh() (*config.Config, error) {
	newConfig, err := c.config.Refresh(c.pool)
	if err != nil {
		return nil, err
	}
	
	c.config = newConfig
	c.generation++
	return newConfig, nil
}

// GetGeneration returns the current resharing generation number
func (c *CMP) GetGeneration() uint64 {
	return c.generation
}

// GetConfig returns the current CMP configuration
func (c *CMP) GetConfig() *config.Config {
	return c.config
}

// UpdateConfig updates the configuration after a successful resharing
func (c *CMP) UpdateConfig(newConfig *config.Config) {
	c.config = newConfig
	c.generation++
}