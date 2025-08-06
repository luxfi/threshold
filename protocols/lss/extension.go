package lss

import (
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	frostconfig "github.com/luxfi/threshold/protocols/frost"
)

// DynamicReshareExtension provides dynamic resharing capabilities for both CMP and FROST protocols.
// This implements the core resharing protocol from Section 4 of the LSS paper without
// requiring protocol-specific messaging or coordination.
type DynamicReshareExtension struct {
	group curve.Curve
	pool  *pool.Pool
}

// NewDynamicReshareExtension creates a new extension instance
func NewDynamicReshareExtension(group curve.Curve, pool *pool.Pool) *DynamicReshareExtension {
	return &DynamicReshareExtension{
		group: group,
		pool:  pool,
	}
}

// ReshareCMP performs dynamic resharing for CMP configurations.
// It transitions from T-of-N to T'-of-N' without reconstructing the master key.
func (ext *DynamicReshareExtension) ReshareCMP(
	oldConfigs map[party.ID]*cmpconfig.Config,
	newPartyIDs []party.ID,
	newThreshold int,
) (map[party.ID]*cmpconfig.Config, error) {
	
	if len(oldConfigs) == 0 {
		return nil, errors.New("no old configurations provided")
	}
	
	// Get reference config
	var refConfig *cmpconfig.Config
	oldPartyIDs := make([]party.ID, 0, len(oldConfigs))
	for pid, cfg := range oldConfigs {
		if refConfig == nil {
			refConfig = cfg
		}
		oldPartyIDs = append(oldPartyIDs, pid)
	}
	
	// Perform the core resharing computation
	newShares, err := ext.computeResharedSecrets(
		oldPartyIDs,
		newPartyIDs,
		refConfig.Threshold,
		newThreshold,
		func(pid party.ID) curve.Scalar {
			if cfg, ok := oldConfigs[pid]; ok {
				return cfg.ECDSA
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("resharing failed: %w", err)
	}
	
	// Create new CMP configurations
	newConfigs := make(map[party.ID]*cmpconfig.Config)
	for _, pid := range newPartyIDs {
		newConfig := &cmpconfig.Config{
			Group:     refConfig.Group,
			ID:        pid,
			Threshold: newThreshold,
			ECDSA:     newShares[pid],
			// Reuse auxiliary values (these would be refreshed in practice)
			ElGamal:  refConfig.ElGamal,
			Paillier: refConfig.Paillier,
			RID:      refConfig.RID,
			ChainKey: refConfig.ChainKey,
			Public:   make(map[party.ID]*cmpconfig.Public),
		}
		
		// Update public information
		for _, otherPID := range newPartyIDs {
			publicPoint := newShares[otherPID].ActOnBase()
			newConfig.Public[otherPID] = &cmpconfig.Public{
				ECDSA:    publicPoint,
				ElGamal:  refConfig.Public[otherPID].ElGamal,
				Paillier: refConfig.Public[otherPID].Paillier,
				Pedersen: refConfig.Public[otherPID].Pedersen,
			}
		}
		
		newConfigs[pid] = newConfig
	}
	
	return newConfigs, nil
}

// ReshareFROST performs dynamic resharing for FROST configurations.
func (ext *DynamicReshareExtension) ReshareFROST(
	oldConfigs map[party.ID]*frostconfig.Config,
	newPartyIDs []party.ID,
	newThreshold int,
) (map[party.ID]*frostconfig.Config, error) {
	
	if len(oldConfigs) == 0 {
		return nil, errors.New("no old configurations provided")
	}
	
	// Get reference config
	var refConfig *frostconfig.Config
	oldPartyIDs := make([]party.ID, 0, len(oldConfigs))
	for pid, cfg := range oldConfigs {
		if refConfig == nil {
			refConfig = cfg
		}
		oldPartyIDs = append(oldPartyIDs, pid)
	}
	
	// Perform the core resharing computation
	newShares, err := ext.computeResharedSecrets(
		oldPartyIDs,
		newPartyIDs,
		refConfig.Threshold,
		newThreshold,
		func(pid party.ID) curve.Scalar {
			if cfg, ok := oldConfigs[pid]; ok {
				return cfg.SecretShare
			}
			return nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("resharing failed: %w", err)
	}
	
	// Create new FROST configurations
	newConfigs := make(map[party.ID]*frostconfig.Config)
	for _, pid := range newPartyIDs {
		newConfig := &frostconfig.Config{
			ID:               pid,
			Group:            refConfig.Group,
			PublicKey:        refConfig.PublicKey,
			SecretShare:      newShares[pid],
			VerificationKey:  newShares[pid].ActOnBase(),
			Threshold:        newThreshold,
			VerificationKeys: make(map[party.ID]curve.Point),
		}
		
		// Update verification keys for all parties
		for _, otherPID := range newPartyIDs {
			newConfig.VerificationKeys[otherPID] = newShares[otherPID].ActOnBase()
		}
		
		newConfigs[pid] = newConfig
	}
	
	return newConfigs, nil
}

// computeResharedSecrets implements the core LSS resharing protocol (Section 4)
func (ext *DynamicReshareExtension) computeResharedSecrets(
	oldPartyIDs []party.ID,
	newPartyIDs []party.ID,
	oldThreshold int,
	newThreshold int,
	getOldShare func(party.ID) curve.Scalar,
) (map[party.ID]curve.Scalar, error) {
	
	group := ext.group
	
	// Step 1: Generate auxiliary secrets w and q
	// These are temporary secrets used only during resharing
	wPoly := polynomial.NewPolynomial(group, newThreshold-1, nil)
	qPoly := polynomial.NewPolynomial(group, newThreshold-1, nil)
	
	wShares := make(map[party.ID]curve.Scalar)
	qShares := make(map[party.ID]curve.Scalar)
	
	// All parties (old and new) need shares of w and q
	allParties := make(map[party.ID]bool)
	for _, pid := range oldPartyIDs {
		allParties[pid] = true
	}
	for _, pid := range newPartyIDs {
		allParties[pid] = true
	}
	
	for pid := range allParties {
		wShares[pid] = wPoly.Evaluate(pid.Scalar(group))
		qShares[pid] = qPoly.Evaluate(pid.Scalar(group))
	}
	
	// Step 2: Compute a * w
	// Old parties compute a_i * w_i and these are interpolated
	blindedProducts := make(map[party.ID]curve.Scalar)
	for _, pid := range oldPartyIDs[:oldThreshold] {
		oldShare := getOldShare(pid)
		if oldShare == nil {
			continue
		}
		wShare := wShares[pid]
		product := group.NewScalar().Set(oldShare).Mul(wShare)
		blindedProducts[pid] = product
	}
	
	// Interpolate to get a * w
	lagrange := polynomial.Lagrange(group, oldPartyIDs[:oldThreshold])
	aTimesW := group.NewScalar()
	for pid, product := range blindedProducts {
		if coeff, exists := lagrange[pid]; exists {
			contribution := group.NewScalar().Set(coeff).Mul(product)
			aTimesW.Add(contribution)
		}
	}
	
	// Step 3: Compute z = (q * w)^{-1}
	// Parties compute q_j * w_j and these are interpolated
	qwProducts := make(map[party.ID]curve.Scalar)
	count := 0
	for pid := range allParties {
		if count >= newThreshold {
			break
		}
		qShare := qShares[pid]
		wShare := wShares[pid]
		product := group.NewScalar().Set(qShare).Mul(wShare)
		qwProducts[pid] = product
		count++
	}
	
	// Get first newThreshold parties for interpolation
	interpolationParties := make([]party.ID, 0, newThreshold)
	for pid := range qwProducts {
		interpolationParties = append(interpolationParties, pid)
		if len(interpolationParties) >= newThreshold {
			break
		}
	}
	
	// Interpolate to get q * w
	newLagrange := polynomial.Lagrange(group, interpolationParties)
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
		return nil, fmt.Errorf("failed to invert q*w: %w", err)
	}
	
	// Create shares of z
	zPoly := polynomial.NewPolynomial(group, newThreshold-1, z)
	zShares := make(map[party.ID]curve.Scalar)
	for _, pid := range newPartyIDs {
		zShares[pid] = zPoly.Evaluate(pid.Scalar(group))
	}
	
	// Step 4: Each party computes their new share
	// a'_j = (a * w) * q_j * z_j
	newShares := make(map[party.ID]curve.Scalar)
	for _, pid := range newPartyIDs {
		qShare := qShares[pid]
		zShare := zShares[pid]
		
		// Compute new share: a'_j = (a * w) * q_j * z_j
		newShare := group.NewScalar().Set(aTimesW)
		newShare.Mul(qShare).Mul(zShare)
		newShares[pid] = newShare
	}
	
	return newShares, nil
}

// VerifyResharing validates that the new shares correctly reconstruct the original secret
func (ext *DynamicReshareExtension) VerifyResharing(
	oldShares map[party.ID]curve.Scalar,
	newShares map[party.ID]curve.Scalar,
	oldThreshold int,
	newThreshold int,
) error {
	group := ext.group
	
	// Reconstruct original secret from old shares
	oldPartyIDs := make([]party.ID, 0, oldThreshold)
	for pid := range oldShares {
		oldPartyIDs = append(oldPartyIDs, pid)
		if len(oldPartyIDs) >= oldThreshold {
			break
		}
	}
	
	oldLagrange := polynomial.Lagrange(group, oldPartyIDs)
	originalSecret := group.NewScalar()
	for _, pid := range oldPartyIDs {
		if coeff, exists := oldLagrange[pid]; exists {
			contribution := group.NewScalar().Set(coeff).Mul(oldShares[pid])
			originalSecret.Add(contribution)
		}
	}
	
	// Reconstruct secret from new shares
	newPartyIDs := make([]party.ID, 0, newThreshold)
	for pid := range newShares {
		newPartyIDs = append(newPartyIDs, pid)
		if len(newPartyIDs) >= newThreshold {
			break
		}
	}
	
	newLagrange := polynomial.Lagrange(group, newPartyIDs)
	newSecret := group.NewScalar()
	for _, pid := range newPartyIDs {
		if coeff, exists := newLagrange[pid]; exists {
			contribution := group.NewScalar().Set(coeff).Mul(newShares[pid])
			newSecret.Add(contribution)
		}
	}
	
	// Verify they're equal
	if !originalSecret.Equal(newSecret) {
		return errors.New("resharing verification failed: secrets don't match")
	}
	
	return nil
}