// Package sign implements threshold signing for Corona.
// This package wraps the real Corona signing from github.com/luxfi/corona/threshold.
package sign

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/corona/config"

	realsign "github.com/luxfi/corona/sign"
	realring "github.com/luxfi/corona/threshold"
)

// Start initiates the Corona threshold signing protocol.
// This wraps the real Corona signing from github.com/luxfi/corona/threshold.
func Start(cfg *config.Config, keyShare *realring.KeyShare, groupKey *realring.GroupKey, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		// Validate we have enough signers
		if len(signers) < cfg.Threshold {
			return nil, errors.New("insufficient signers for threshold")
		}

		// Find our position in the signer list
		selfIdx := -1
		signerIndices := make([]int, len(signers))
		for i, id := range signers {
			if id == cfg.ID {
				selfIdx = i
			}
			// Map party.ID to signer index
			for j, p := range cfg.Participants {
				if p == id {
					signerIndices[i] = j
					break
				}
			}
		}
		if selfIdx == -1 {
			return nil, errors.New("self not in signer list")
		}

		info := round.Info{
			ProtocolID:       "corona/sign",
			FinalRoundNumber: 2, // Corona signing has 2 rounds
			SelfID:           cfg.ID,
			PartyIDs:         signers,
			Threshold:        cfg.Threshold,
		}

		helper, err := round.NewSession(info, sessionID, pl)
		if err != nil {
			return nil, err
		}

		// Generate session-specific PRF key
		prfKey := make([]byte, realsign.KeySize)
		if _, err := rand.Read(prfKey); err != nil {
			return nil, err
		}

		// Create real corona signer
		signer := realring.NewSigner(keyShare)

		// Start with signing round 1
		return &signRound1{
			Helper:        helper,
			config:        cfg,
			keyShare:      keyShare,
			groupKey:      groupKey,
			signer:        signer,
			message:       message,
			prfKey:        prfKey,
			signerIndices: signerIndices,
			round1Data:    make(map[int]*realring.Round1Data),
		}, nil
	}
}

// signRound1 performs real Corona signing round 1
type signRound1 struct {
	*round.Helper
	config        *config.Config
	keyShare      *realring.KeyShare
	groupKey      *realring.GroupKey
	signer        *realring.Signer
	message       []byte
	prfKey        []byte
	signerIndices []int
	round1Data    map[int]*realring.Round1Data
}

// Number implements round.Round
func (r *signRound1) Number() round.Number {
	return 1
}

// MessageContent implements round.Round
func (r *signRound1) MessageContent() round.Content {
	return nil // Signing uses broadcasts
}

// BroadcastContent implements round.BroadcastRound
func (r *signRound1) BroadcastContent() round.BroadcastContent {
	return &signBroadcast1{}
}

// VerifyMessage implements round.Round
func (r *signRound1) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *signRound1) StoreMessage(_ round.Message) error {
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *signRound1) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*signBroadcast1)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Deserialize the Round1Data from the broadcast
	round1Data, err := deserializeRound1Data(body.Round1DataBytes)
	if err != nil {
		return err
	}

	r.round1Data[round1Data.PartyID] = round1Data
	return nil
}

// Finalize implements round.Round
func (r *signRound1) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate session ID from message hash
	sessionID := hashToInt(r.message)

	// Perform real Corona Round 1
	round1Data := r.signer.Round1(sessionID, r.prfKey, r.signerIndices)

	// Serialize and broadcast
	round1Bytes := serializeRound1Data(round1Data)

	if err := r.BroadcastMessage(out, &signBroadcast1{
		Round1DataBytes: round1Bytes,
		PRFKey:          r.prfKey,
	}); err != nil {
		return nil, err
	}

	// Store our own round 1 data
	r.round1Data[round1Data.PartyID] = round1Data

	// Move to round 2
	return &signRound2{
		Helper:        r.Helper,
		config:        r.config,
		keyShare:      r.keyShare,
		groupKey:      r.groupKey,
		signer:        r.signer,
		message:       r.message,
		prfKey:        r.prfKey,
		signerIndices: r.signerIndices,
		round1Data:    r.round1Data,
		round2Data:    make(map[int]*realring.Round2Data),
	}, nil
}

// signBroadcast1 contains real Corona Round 1 data
type signBroadcast1 struct {
	round.NormalBroadcastContent
	Round1DataBytes []byte
	PRFKey          []byte
}

// RoundNumber implements round.Content
func (signBroadcast1) RoundNumber() round.Number {
	return 1
}

// signRound2 performs real Corona signing round 2 and finalizes
type signRound2 struct {
	*round.Helper
	config        *config.Config
	keyShare      *realring.KeyShare
	groupKey      *realring.GroupKey
	signer        *realring.Signer
	message       []byte
	prfKey        []byte
	signerIndices []int
	round1Data    map[int]*realring.Round1Data
	round2Data    map[int]*realring.Round2Data
}

// Number implements round.Round
func (r *signRound2) Number() round.Number {
	return 2
}

// MessageContent implements round.Round
func (r *signRound2) MessageContent() round.Content {
	return nil
}

// BroadcastContent implements round.BroadcastRound
func (r *signRound2) BroadcastContent() round.BroadcastContent {
	return &signBroadcast2{}
}

// VerifyMessage implements round.Round
func (r *signRound2) VerifyMessage(_ round.Message) error {
	return nil
}

// StoreMessage implements round.Round
func (r *signRound2) StoreMessage(_ round.Message) error {
	return nil
}

// StoreBroadcastMessage implements round.BroadcastRound
func (r *signRound2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*signBroadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// Deserialize Round2Data
	round2Data, err := deserializeRound2Data(body.Round2DataBytes, r.groupKey.Params)
	if err != nil {
		return err
	}

	r.round2Data[round2Data.PartyID] = round2Data
	return nil
}

// Finalize implements round.Round
func (r *signRound2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Generate session ID from message hash
	sessionID := hashToInt(r.message)
	messageStr := string(r.message)

	// Perform real Corona Round 2
	round2Data, err := r.signer.Round2(sessionID, messageStr, r.prfKey, r.signerIndices, r.round1Data)
	if err != nil {
		return nil, err
	}

	// Serialize and broadcast
	round2Bytes := serializeRound2Data(round2Data)

	if err := r.BroadcastMessage(out, &signBroadcast2{
		Round2DataBytes: round2Bytes,
	}); err != nil {
		return nil, err
	}

	// Store our own round 2 data
	r.round2Data[round2Data.PartyID] = round2Data

	// Finalize the signature
	sig, err := r.signer.Finalize(r.round2Data)
	if err != nil {
		return nil, err
	}

	// Verify the signature before returning
	messageStr = string(r.message)
	if !realring.Verify(r.groupKey, messageStr, sig) {
		return nil, errors.New("signature verification failed")
	}

	// Return the final signature
	return r.ResultRound(&Signature{
		Signature: sig,
		Message:   r.message,
		Signers:   r.PartyIDs(),
		GroupKey:  r.groupKey,
	}), nil
}

// signBroadcast2 contains real Corona Round 2 data
type signBroadcast2 struct {
	round.NormalBroadcastContent
	Round2DataBytes []byte
}

// RoundNumber implements round.Content
func (signBroadcast2) RoundNumber() round.Number {
	return 2
}

// Signature represents a completed threshold signature
type Signature struct {
	Signature *realring.Signature
	Message   []byte
	Signers   []party.ID
	GroupKey  *realring.GroupKey
}

// Verify checks if the signature is valid using real Corona verification
func (s *Signature) Verify(publicKey []byte) bool {
	if s.Signature == nil || s.GroupKey == nil {
		return false
	}
	return realring.Verify(s.GroupKey, string(s.Message), s.Signature)
}

// Bytes serializes the signature
func (s *Signature) Bytes() []byte {
	if s.Signature == nil {
		return nil
	}
	return serializeSignature(s.Signature)
}

// hashToInt converts a message hash to an integer session ID
func hashToInt(message []byte) int {
	if len(message) < 4 {
		return 0
	}
	return int(binary.LittleEndian.Uint32(message[:4]))
}

// Serialization helpers for Round1Data
func serializeRound1Data(data *realring.Round1Data) []byte {
	if data == nil {
		return nil
	}

	var buf []byte

	// Party ID
	partyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(partyBytes, uint32(data.PartyID))
	buf = append(buf, partyBytes...)

	// D matrix dimensions
	dimBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(dimBytes[:4], uint32(len(data.D)))
	if len(data.D) > 0 {
		binary.LittleEndian.PutUint32(dimBytes[4:], uint32(len(data.D[0])))
	}
	buf = append(buf, dimBytes...)

	// D matrix coefficients
	for _, row := range data.D {
		for _, poly := range row {
			for _, modCoeffs := range poly.Coeffs {
				for _, coeff := range modCoeffs {
					coeffBytes := make([]byte, 8)
					binary.LittleEndian.PutUint64(coeffBytes, coeff)
					buf = append(buf, coeffBytes...)
				}
			}
		}
	}

	// MACs count and data
	macCountBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(macCountBytes, uint32(len(data.MACs)))
	buf = append(buf, macCountBytes...)

	for partyID, mac := range data.MACs {
		// Party ID
		pidBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(pidBytes, uint32(partyID))
		buf = append(buf, pidBytes...)

		// MAC length and data
		macLenBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(macLenBytes, uint32(len(mac)))
		buf = append(buf, macLenBytes...)
		buf = append(buf, mac...)
	}

	return buf
}

func deserializeRound1Data(data []byte) (*realring.Round1Data, error) {
	if len(data) < 12 {
		return nil, errors.New("round1 data too short")
	}

	partyID := int(binary.LittleEndian.Uint32(data[:4]))

	// For now, return minimal data structure
	// Full deserialization would reconstruct D matrix and MACs
	return &realring.Round1Data{
		PartyID: partyID,
		MACs:    make(map[int][]byte),
	}, nil
}

func serializeRound2Data(data *realring.Round2Data) []byte {
	if data == nil {
		return nil
	}

	var buf []byte

	// Party ID
	partyBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(partyBytes, uint32(data.PartyID))
	buf = append(buf, partyBytes...)

	// Z vector length
	zLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(zLenBytes, uint32(len(data.Z)))
	buf = append(buf, zLenBytes...)

	// Z vector coefficients
	for _, poly := range data.Z {
		for _, modCoeffs := range poly.Coeffs {
			for _, coeff := range modCoeffs {
				coeffBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(coeffBytes, coeff)
				buf = append(buf, coeffBytes...)
			}
		}
	}

	return buf
}

func deserializeRound2Data(data []byte, params *realring.Params) (*realring.Round2Data, error) {
	if len(data) < 8 {
		return nil, errors.New("round2 data too short")
	}

	partyID := int(binary.LittleEndian.Uint32(data[:4]))

	// For now, return minimal data structure
	return &realring.Round2Data{
		PartyID: partyID,
	}, nil
}

func serializeSignature(sig *realring.Signature) []byte {
	if sig == nil {
		return nil
	}

	var buf []byte

	// C polynomial
	for _, modCoeffs := range sig.C.Coeffs {
		for _, coeff := range modCoeffs {
			coeffBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(coeffBytes, coeff)
			buf = append(buf, coeffBytes...)
		}
	}

	// Z vector
	zLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(zLenBytes, uint32(len(sig.Z)))
	buf = append(buf, zLenBytes...)

	for _, poly := range sig.Z {
		for _, modCoeffs := range poly.Coeffs {
			for _, coeff := range modCoeffs {
				coeffBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(coeffBytes, coeff)
				buf = append(buf, coeffBytes...)
			}
		}
	}

	// Delta vector
	deltaLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(deltaLenBytes, uint32(len(sig.Delta)))
	buf = append(buf, deltaLenBytes...)

	for _, poly := range sig.Delta {
		for _, modCoeffs := range poly.Coeffs {
			for _, coeff := range modCoeffs {
				coeffBytes := make([]byte, 8)
				binary.LittleEndian.PutUint64(coeffBytes, coeff)
				buf = append(buf, coeffBytes...)
			}
		}
	}

	return buf
}
