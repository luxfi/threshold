package refresh

import (
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"golang.org/x/crypto/blake2b"
)

// refreshRound3 combines refresh shares to create new key shares
type refreshRound3 struct {
	*round.Helper
	config          *config.Config
	newParticipants []party.ID
	newThreshold    int
	refreshShares   map[party.ID][]byte
}

// Number implements round.Round
func (r *refreshRound3) Number() round.Number {
	return 3
}

// MessageContent implements round.Round
func (r *refreshRound3) MessageContent() round.Content {
	return nil // Round 3 is finalization only
}

// VerifyMessage implements round.Round
func (r *refreshRound3) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *refreshRound3) StoreMessage(_ round.Message) error {
	return nil
}

// Finalize implements round.Round
func (r *refreshRound3) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Verify we have enough refresh shares
	if len(r.refreshShares) < r.newThreshold {
		return nil, errors.New("insufficient refresh shares")
	}

	// Combine old share with refresh shares
	newPrivateShare := make([]byte, len(r.config.PrivateShare))
	copy(newPrivateShare, r.config.PrivateShare)

	// Add refresh shares to old share
	for _, refreshShare := range r.refreshShares {
		for i := 0; i < len(newPrivateShare) && i < len(refreshShare); i++ {
			newPrivateShare[i] ^= refreshShare[i]
		}
	}

	// Public key remains the same (property of refresh)
	// but we recompute it for verification
	h, _ := blake2b.New256(nil)
	h.Write(r.config.PublicKey)
	h.Write([]byte("refresh"))
	verificationHash := h.Sum(nil)

	// Create refreshed configuration
	refreshedConfig := &config.Config{
		ID:           r.SelfID(),
		Threshold:    r.newThreshold,
		Level:        r.config.Level,
		PublicKey:    r.config.PublicKey, // Same public key
		PrivateShare: newPrivateShare,
		Participants: r.newParticipants,
	}

	// Return the result
	return r.ResultRound(&RefreshOutput{
		Config:           refreshedConfig,
		VerificationHash: verificationHash,
	}), nil
}

// RefreshOutput represents the result of key refresh
type RefreshOutput struct {
	Config           *config.Config
	VerificationHash []byte
}

// PublicKey returns the public key (unchanged)
func (o *RefreshOutput) PublicKey() []byte {
	return o.Config.PublicKey
}

// NewPrivateShare returns the refreshed private key share
func (o *RefreshOutput) NewPrivateShare() []byte {
	return o.Config.PrivateShare
}

// NewThreshold returns the new threshold value
func (o *RefreshOutput) NewThreshold() int {
	return o.Config.Threshold
}

// NewParticipants returns the new participant list
func (o *RefreshOutput) NewParticipants() []party.ID {
	return o.Config.Participants
}
