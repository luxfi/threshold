package reshare

import (
	"errors"
	"fmt"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/unified/config"
)

// Reshare initiates a dynamic resharing protocol for the unified MPC-LSS
// This works for both ECDSA and EdDSA configurations
func Reshare(cfg *config.UnifiedConfig, newParties []party.ID, newThreshold int) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Validate inputs
		if err := validateReshareParams(cfg, newParties, newThreshold); err != nil {
			return nil, fmt.Errorf("reshare validation failed: %w", err)
		}

		// Create reshare state
		reshareState := &config.ReshareState{
			OldParties:    cfg.PartyIDs,
			NewParties:    newParties,
			NewThreshold:  newThreshold,
			AuxiliaryData: make(map[string][]byte),
		}

		// Update config with reshare state
		cfg.ReshareData = reshareState

		// Determine all participants (old + new parties)
		allParties := combineParties(cfg.PartyIDs, newParties)

		info := round.Info{
			ProtocolID:       fmt.Sprintf("unified/reshare-%s", cfg.SignatureScheme),
			FinalRoundNumber: 4, // 4 rounds for complete resharing
			SelfID:           cfg.ID,
			PartyIDs:         allParties,
			Threshold:        cfg.Threshold, // Use old threshold for initial rounds
			Group:            cfg.Group,
		}

		_, err := round.NewSession(info, sessionID, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create reshare session: %w", err)
		}

		// Start with auxiliary secret generation (JVSS)
		// TODO: Implement proper round.Session interface
		return nil, errors.New("reshare not yet fully implemented")
	}
}

// auxiliaryRound generates auxiliary secrets w and q via JVSS
type auxiliaryRound struct {
	*round.Helper
	config       *config.UnifiedConfig
	newParties   []party.ID
	newThreshold int
}

// validateReshareParams checks if resharing parameters are valid
func validateReshareParams(cfg *config.UnifiedConfig, newParties []party.ID, newThreshold int) error {
	if cfg == nil {
		return errors.New("config cannot be nil")
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if len(newParties) == 0 {
		return errors.New("new parties list cannot be empty")
	}

	if newThreshold < 1 {
		return errors.New("new threshold must be at least 1")
	}

	if newThreshold > len(newParties) {
		return fmt.Errorf("new threshold %d exceeds new party count %d", newThreshold, len(newParties))
	}

	// Check if we have enough old parties to perform resharing
	activeOldParties := 0
	for _, oldParty := range cfg.PartyIDs {
		for _, participant := range append(cfg.PartyIDs, newParties...) {
			if oldParty == participant {
				activeOldParties++
				break
			}
		}
	}

	if activeOldParties < cfg.Threshold {
		return fmt.Errorf("need at least %d old parties for resharing, have %d", cfg.Threshold, activeOldParties)
	}

	return nil
}

// combineParties creates a unique list of all parties (old and new)
func combineParties(oldParties, newParties []party.ID) []party.ID {
	partySet := make(map[party.ID]bool)
	for _, p := range oldParties {
		partySet[p] = true
	}
	for _, p := range newParties {
		partySet[p] = true
	}

	allParties := make([]party.ID, 0, len(partySet))
	for p := range partySet {
		allParties = append(allParties, p)
	}
	return allParties
}

// ReshareResult contains the output of a successful resharing
type ReshareResult struct {
	// NewConfig is the updated configuration after resharing
	NewConfig *config.UnifiedConfig

	// OldGeneration is the generation number before resharing
	OldGeneration uint64

	// Success indicates if resharing completed successfully
	Success bool
}

// TransferShare performs the core share transfer during resharing
// This is signature-agnostic and works for both ECDSA and EdDSA
func TransferShare(
	oldShare curve.Scalar,
	wShare curve.Scalar,
	qShare curve.Scalar,
	recipientID party.ID,
	newThreshold int,
	group curve.Curve,
) (curve.Scalar, error) {
	// Step 1: Blind the old share with w
	blindedShare := group.NewScalar().Set(oldShare).Mul(wShare)

	// Step 2: Create polynomial for share distribution
	poly := polynomial.NewPolynomial(group, newThreshold-1, blindedShare)

	// Step 3: Evaluate at recipient's point
	recipientPoint := recipientID.Scalar(group)
	newBlindedShare := poly.Evaluate(recipientPoint)

	// Step 4: Multiply with q for double blinding
	// This will be unblinded later with z = (q * w)^{-1}
	finalShare := group.NewScalar().Set(newBlindedShare).Mul(qShare)

	return finalShare, nil
}

// VerifyResharedConfig validates that a reshared configuration is correct
func VerifyResharedConfig(oldConfig, newConfig *config.UnifiedConfig) error {
	// Public key must remain unchanged
	if !oldConfig.PublicKey.Equal(newConfig.PublicKey) {
		return errors.New("public key changed during resharing")
	}

	// Signature scheme must remain the same
	if oldConfig.SignatureScheme != newConfig.SignatureScheme {
		return errors.New("signature scheme cannot change during resharing")
	}

	// Generation must increment
	if newConfig.Generation != oldConfig.Generation+1 {
		return fmt.Errorf("generation should be %d, got %d", oldConfig.Generation+1, newConfig.Generation)
	}

	// Verify threshold is as expected
	if newConfig.ReshareData != nil && newConfig.Threshold != newConfig.ReshareData.NewThreshold {
		return errors.New("threshold mismatch after resharing")
	}

	// For ECDSA, verify Paillier keys are present
	if newConfig.SignatureScheme == config.SignatureECDSA {
		if newConfig.ECDSAExtensions == nil || newConfig.ECDSAExtensions.PaillierKey == nil {
			return errors.New("ECDSA configuration missing after resharing")
		}
	}

	return nil
}

// MigrateECDSAExtensions handles the migration of ECDSA-specific data during resharing
func MigrateECDSAExtensions(
	oldExtensions *config.ECDSAExtensions,
	newPartyID party.ID,
	newParties []party.ID,
) (*config.ECDSAExtensions, error) {
	if oldExtensions == nil {
		return nil, errors.New("no ECDSA extensions to migrate")
	}

	// For new parties, generate fresh Paillier keys
	// For existing parties, keep their Paillier keys
	// This is a simplified version - full implementation would coordinate this

	newExtensions := &config.ECDSAExtensions{
		PaillierKey:    oldExtensions.PaillierKey,    // Keep if same party
		PedersenParams: oldExtensions.PedersenParams, // Shared params remain
		// PublicPaillierKeys: make(map[party.ID]*paillier.PublicKey),
	}

	// In practice, this would involve:
	// 1. New parties generating Paillier keys
	// 2. Broadcasting public keys
	// 3. Verifying zero-knowledge proofs
	// 4. Storing all public keys

	return newExtensions, nil
}

// CompleteReshare finalizes the resharing process
func CompleteReshare(cfg *config.UnifiedConfig) (*config.UnifiedConfig, error) {
	if cfg.ReshareData == nil {
		return nil, errors.New("no resharing in progress")
	}

	// Create new configuration
	newConfig := &config.UnifiedConfig{
		ID:                 cfg.ID,
		Threshold:          cfg.ReshareData.NewThreshold,
		Generation:         cfg.Generation + 1,
		PartyIDs:           cfg.ReshareData.NewParties,
		SignatureScheme:    cfg.SignatureScheme,
		Group:              cfg.Group,
		SecretShare:        cfg.SecretShare,        // Will be updated with new share
		PublicKey:          cfg.PublicKey,          // Remains unchanged
		VerificationShares: cfg.VerificationShares, // Copy existing verification shares
		ChainKey:           cfg.ChainKey,
	}

	// Handle signature-specific migration
	if cfg.SignatureScheme == config.SignatureECDSA && cfg.ECDSAExtensions != nil {
		var err error
		newConfig.ECDSAExtensions, err = MigrateECDSAExtensions(
			cfg.ECDSAExtensions,
			cfg.ID,
			cfg.ReshareData.NewParties,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to migrate ECDSA extensions: %w", err)
		}
	}

	// Clear temporary reshare data
	newConfig.ReshareData = nil

	// Validate the new configuration
	if err := newConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid reshared config: %w", err)
	}

	return newConfig, nil
}
