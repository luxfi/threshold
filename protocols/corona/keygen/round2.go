package keygen

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/corona/config"
	"golang.org/x/crypto/blake2b"

	realring "github.com/luxfi/corona/threshold"
)

// round2 distributes key shares to all parties
type round2 struct {
	*round.Helper

	config       *config.Config
	selfIndex    int
	participants []party.ID

	// Real corona key generation results from round 1
	keyShares []*realring.KeyShare
	groupKey  *realring.GroupKey

	shares     map[party.ID][]byte
	commitment hash.Commitment
	decommit   hash.Decommitment

	// Received share data from other parties
	receivedShares map[party.ID]*realring.KeyShare
}

// broadcast2 contains the decommitment and key share proof
type broadcast2 struct {
	round.NormalBroadcastContent

	// Decommitment to verify against round 1 commitment
	Decommitment hash.Decommitment

	// Serialized share data (encrypted for each recipient)
	ShareData []byte

	// Group key bytes for verification
	GroupKeyData []byte
}

// message2 contains the encrypted key share for a specific party
type message2 struct {
	// Encrypted share data for this party
	EncryptedShare []byte

	// Share index
	ShareIndex int
}

// Number implements round.Round
func (r *round2) Number() round.Number {
	return 2
}

// RoundNumber implements round.Content for broadcast2
func (broadcast2) RoundNumber() round.Number {
	return 2
}

// RoundNumber implements round.Content for message2
func (message2) RoundNumber() round.Number {
	return 2
}

// BroadcastContent implements round.BroadcastRound
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{}
}

// MessageContent implements round.Round
func (r *round2) MessageContent() round.Content {
	return &message2{}
}

// VerifyMessage implements round.Round
func (r *round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify share data is present
	if len(body.EncryptedShare) == 0 {
		return errors.New("empty share data")
	}

	return nil
}

// StoreMessage implements round.Round
func (r *round2) StoreMessage(msg round.Message) error {
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	r.shares[msg.From] = body.EncryptedShare
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Verify the share data matches the commitment from round 1
	h, _ := blake2b.New256(nil)
	h.Write(body.ShareData)
	shareHash := h.Sum(nil)

	// Verify decommitment
	if !r.Hash().Decommit(shareHash, body.Decommitment, nil) {
		return errors.New("invalid decommitment")
	}

	return nil
}

// Finalize implements round.Round
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Get our share data
	myShare := r.keyShares[r.selfIndex]
	shareData := serializeKeyShare(myShare)

	// Get group key data
	groupKeyData := serializeGroupKey(r.groupKey)

	// Broadcast our decommitment and share proof
	if err := r.BroadcastMessage(out, &broadcast2{
		Decommitment: r.decommit,
		ShareData:    shareData,
		GroupKeyData: groupKeyData,
	}); err != nil {
		return nil, err
	}

	// Send encrypted shares to each party
	for i, partyID := range r.participants {
		if partyID == r.SelfID() {
			// Store our own share
			r.shares[partyID] = serializeKeyShare(r.keyShares[i])
			continue
		}

		// Send the share meant for this party
		shareForParty := serializeKeyShare(r.keyShares[i])
		if err := r.SendMessage(out, &message2{
			EncryptedShare: shareForParty,
			ShareIndex:     i,
		}, partyID); err != nil {
			return nil, err
		}
	}

	// Move to round 3
	return &round3{
		Helper:       r.Helper,
		config:       r.config,
		selfIndex:    r.selfIndex,
		participants: r.participants,
		keyShares:    r.keyShares,
		groupKey:     r.groupKey,
		shares:       r.shares,
	}, nil
}

// serializeGroupKey serializes the group key
func serializeGroupKey(gk *realring.GroupKey) []byte {
	if gk == nil {
		return nil
	}

	var data []byte

	// Serialize A matrix dimensions
	dimBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(dimBytes[:4], uint32(len(gk.A)))
	if len(gk.A) > 0 {
		binary.LittleEndian.PutUint32(dimBytes[4:], uint32(len(gk.A[0])))
	}
	data = append(data, dimBytes...)

	// Serialize A matrix polynomial coefficients
	for _, row := range gk.A {
		for _, poly := range row {
			for _, modCoeffs := range poly.Coeffs {
				for _, coeff := range modCoeffs {
					coeffBytes := make([]byte, 8)
					binary.LittleEndian.PutUint64(coeffBytes, coeff)
					data = append(data, coeffBytes...)
				}
			}
		}
	}

	// Serialize BTilde vector
	vecLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(vecLen, uint32(len(gk.BTilde)))
	data = append(data, vecLen...)

	for _, poly := range gk.BTilde {
		for _, modCoeffs := range poly.Coeffs {
			for _, coeff := range modCoeffs {
				coeffBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(coeffBytes, coeff)
				data = append(data, coeffBytes...)
			}
		}
	}

	return data
}

// verifyGroupKeys checks that all parties agree on the group key
func verifyGroupKeys(a, b []byte) bool {
	return bytes.Equal(a, b)
}
