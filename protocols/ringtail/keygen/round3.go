package keygen

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"golang.org/x/crypto/blake2b"
)

// round3 combines shares to create the final threshold key
type round3 struct {
	*round.Helper

	config        *config.Config
	polynomial    []int
	shares        map[party.ID][]byte
	polynomials   map[party.ID][]int
	decommitments map[party.ID]hash.Decommitment
}

// Number implements round.Round
func (r *round3) Number() round.Number {
	return 3
}

// MessageContent implements round.Round
func (r *round3) MessageContent() round.Content {
	return nil // Round 3 is finalization only
}

// VerifyMessage implements round.Round
func (r *round3) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *round3) StoreMessage(_ round.Message) error {
	return nil
}

// Finalize implements round.Round
func (r *round3) Finalize(_ chan<- *round.Message) (round.Session, error) {
	// Verify we have all shares
	if len(r.shares) < r.Threshold() {
		return nil, errors.New("insufficient shares received")
	}

	// Combine shares to create private key share
	params := r.config.GetParameters()
	privateShare := make([]byte, params.N*8)

	// Simple combination - real implementation would use proper lattice operations
	for _, share := range r.shares {
		for i := 0; i < len(share); i++ {
			privateShare[i] ^= share[i]
		}
	}

	// Generate public key from combined polynomials
	h, _ := blake2b.New256(nil)
	for _, poly := range r.polynomials {
		for _, coeff := range poly {
			coeffBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(coeffBytes, uint64(coeff))
			h.Write(coeffBytes)
		}
	}
	publicKey := h.Sum(nil)

	// Create the final configuration
	finalConfig := &config.Config{
		ID:           r.SelfID(),
		Threshold:    r.Threshold(),
		Level:        r.config.Level,
		PublicKey:    publicKey,
		PrivateShare: privateShare,
		Participants: r.PartyIDs(),
	}

	// Return the result
	return r.ResultRound(&KeygenOutput{
		Config: finalConfig,
	}), nil
}

// KeygenOutput represents the result of key generation
type KeygenOutput struct {
	Config *config.Config
}

// PublicKey returns the generated public key
func (o *KeygenOutput) PublicKey() []byte {
	return o.Config.PublicKey
}

// PrivateShare returns this party's private key share
func (o *KeygenOutput) PrivateShare() []byte {
	return o.Config.PrivateShare
}
