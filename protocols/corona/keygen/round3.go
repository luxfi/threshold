package keygen

import (
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/corona/config"

	realring "github.com/luxfi/corona/threshold"
)

// round3 finalizes key generation and outputs the config with real corona shares
type round3 struct {
	*round.Helper

	config       *config.Config
	selfIndex    int
	participants []party.ID

	// Real corona key generation results
	keyShares []*realring.KeyShare
	groupKey  *realring.GroupKey

	shares map[party.ID][]byte
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

	// Get our real corona key share
	myKeyShare := r.keyShares[r.selfIndex]
	if myKeyShare == nil {
		return nil, errors.New("missing own key share")
	}

	// Serialize private share for storage
	privateShare := serializeSkShare(myKeyShare)

	// Serialize public key (group key)
	publicKey := serializeGroupKey(r.groupKey)

	// Create verification shares for each participant
	verificationShares := make(map[party.ID][]byte)
	for i, partyID := range r.participants {
		if i < len(r.keyShares) && r.keyShares[i] != nil {
			verificationShares[partyID] = computeVerificationShare(r.keyShares[i])
		}
	}

	// Create the final configuration with real corona data
	finalConfig := &config.Config{
		ID:                 r.SelfID(),
		Threshold:          r.Threshold(),
		Level:              r.config.Level,
		SecurityLevel:      r.config.SecurityLevel,
		PublicKey:          publicKey,
		PrivateShare:       privateShare,
		VerificationShares: verificationShares,
		Participants:       r.PartyIDs(),
		Ring:               r.config.Ring,
		RingXi:             r.config.RingXi,
		RingNu:             r.config.RingNu,
	}

	// Return the result with real corona objects
	return r.ResultRound(&KeygenOutput{
		Config:   finalConfig,
		KeyShare: myKeyShare,
		GroupKey: r.groupKey,
	}), nil
}

// serializeSkShare serializes the secret key share polynomials
func serializeSkShare(share *realring.KeyShare) []byte {
	if share == nil || len(share.SkShare) == 0 {
		return nil
	}

	var data []byte

	// Add number of polynomials
	numPolys := make([]byte, 4)
	binary.LittleEndian.PutUint32(numPolys, uint32(len(share.SkShare)))
	data = append(data, numPolys...)

	// Serialize each polynomial's coefficients
	for _, poly := range share.SkShare {
		if poly.Coeffs == nil {
			continue
		}
		for _, modCoeffs := range poly.Coeffs {
			// Add number of coefficients
			numCoeffs := make([]byte, 4)
			binary.LittleEndian.PutUint32(numCoeffs, uint32(len(modCoeffs)))
			data = append(data, numCoeffs...)

			for _, coeff := range modCoeffs {
				coeffBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(coeffBytes, coeff)
				data = append(data, coeffBytes...)
			}
		}
	}

	return data
}

// computeVerificationShare creates a verification hash for a key share
func computeVerificationShare(share *realring.KeyShare) []byte {
	// Use the Lambda (Lagrange coefficient) as verification material
	if share.Lambda.Coeffs == nil {
		return nil
	}

	var data []byte
	for _, modCoeffs := range share.Lambda.Coeffs {
		for _, coeff := range modCoeffs {
			coeffBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(coeffBytes, coeff)
			data = append(data, coeffBytes...)
		}
	}

	return data
}
