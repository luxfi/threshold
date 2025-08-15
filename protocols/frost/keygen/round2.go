package keygen

import (
	"fmt"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	sch "github.com/luxfi/threshold/pkg/zk/sch"
)

// This round corresponds with steps 5 of Round 1, 1 of Round 2, Figure 1 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
type round2 struct {
	*round1
	// fI is the polynomial this participant uses to share their contribution to
	// the secret
	fI *polynomial.Polynomial
	// Phi contains the polynomial commitment for each participant, ourselves included.
	//
	// Phi[l][k] corresponds to ϕₗₖ in the Frost paper.
	// Using sync.Map for thread-safe concurrent access
	Phi sync.Map // map[party.ID]*polynomial.Exponent
	// ChainKeyDecommitment will be used to decommit our contribution to the chain key
	ChainKeyDecommitment hash.Decommitment

	// ChainKey will be the final bit of randomness everybody contributes to.
	//
	// This is an addition to FROST, which we include for key derivation
	// Using sync.Map for thread-safe concurrent access
	ChainKeys sync.Map // map[party.ID]types.RID
	// ChainKeyCommitments holds the commitments for the chain key contributions
	// Using sync.Map for thread-safe concurrent access
	ChainKeyCommitments sync.Map // map[party.ID]hash.Commitment

	// finalized indicates whether this round has been finalized
	finalized     bool
	finalizedLock sync.Mutex
}

type broadcast2 struct {
	round.NormalBroadcastContent
	// PhiI is the commitment to the polynomial that this participant generated.
	PhiI *polynomial.Exponent
	// SigmaI is the Schnorr proof of knowledge of the participant's secret
	SigmaI *sch.Proof
	// Commitment = H(cᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	// Protect concurrent access and check if finalized
	r.finalizedLock.Lock()
	if r.finalized {
		r.finalizedLock.Unlock()
		return nil // Ignore messages after finalization
	}
	r.finalizedLock.Unlock()

	from := msg.From
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if (!r.refresh && !body.SigmaI.IsValid()) || body.PhiI == nil {
		return round.ErrNilFields
	}

	// During refresh, commitment can be empty
	if !r.refresh {
		if err := body.Commitment.Validate(); err != nil {
			return fmt.Errorf("commitment: %w", err)
		}
	}

	// These steps come from Figure 1, Round 1 of the Frost paper

	// 5. "Upon receiving ϕₗ, σₗ from participants 1 ⩽ l ⩽ n, participant
	// Pᵢ verifies σₗ = (Rₗ, μₗ), aborting on failure, by checking
	// Rₗ = μₗ * G - cₗ * ϕₗ₀, where cₗ = H(l, ctx, ϕₗ₀, Rₗ).
	//
	// Upon success, participants delete { σₗ | 1 ⩽ l ⩽ n }"
	//
	// Note: I've renamed Cₗ to Φₗ, as in the previous round.
	// R_l = Rₗ, mu_l = μₗ
	//
	// To see why this is correct, compare this verification with the proof we
	// produced in the previous round. Note how we do the same hash cloning,
	// but this time with the ID of the message sender.

	// Refresh: There's no proof to verify, but instead check that the constant is identity
	if r.refresh {
		if !body.PhiI.Constant().IsIdentity() {
			return fmt.Errorf("party %s sent a non-zero constant while refreshing", from)
		}
	} else {
		if !body.SigmaI.Verify(r.Helper.HashForID(from), body.PhiI.Constant(), nil) {
			return fmt.Errorf("failed to verify Schnorr proof for party %s", from)
		}
	}

	// Store using sync.Map for thread-safe concurrent access
	r.Phi.Store(from, body.PhiI)

	// Store chain key commitments - make a defensive copy to avoid issues with shared slices
	var commitmentCopy []byte
	if body.Commitment != nil {
		commitmentCopy = make([]byte, len(body.Commitment))
		copy(commitmentCopy, body.Commitment)
	}
	r.ChainKeyCommitments.Store(from, commitmentCopy)

	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// These steps come from Figure 1, Round 2 of the Frost paper

	// 1. "Each P_i securely sends to each other participant Pₗ a secret share
	// (l, fᵢ(l)), deleting f_i and each share afterward except for (i, fᵢ(i)),
	// which they keep for themselves."

	// Load our chain key from sync.Map
	ckValue, _ := r.ChainKeys.Load(r.SelfID())
	ck, _ := ckValue.(types.RID)

	if err := r.BroadcastMessage(out, &broadcast3{
		CL:           ck,
		Decommitment: r.ChainKeyDecommitment,
	}); err != nil {
		return r, err
	}

	for _, l := range r.OtherPartyIDs() {
		if err := r.SendMessage(out, &message3{
			FLi: r.fI.Evaluate(l.Scalar(r.Group())),
		}, l); err != nil {
			return r, err
		}
	}

	selfShare := r.fI.Evaluate(r.SelfID().Scalar(r.Group()))

	// Mark as finalized to prevent further modifications
	r.finalizedLock.Lock()
	r.finalized = true
	r.finalizedLock.Unlock()

	// Count commitments in sync.Map
	commitmentCount := 0
	r.ChainKeyCommitments.Range(func(_, _ interface{}) bool {
		commitmentCount++
		return true
	})

	// We should have commitments from all other parties (not including ourselves)
	if !r.refresh && commitmentCount != r.PartyIDs().Len()-1 {
		return r, fmt.Errorf("missing chain key commitments: have %d, need %d", commitmentCount, r.PartyIDs().Len()-1)
	}

	// Create shareFrom as sync.Map and store self share
	shareFrom := &sync.Map{}
	shareFrom.Store(r.SelfID(), selfShare)

	return &round3{
		round2:    r,
		shareFrom: shareFrom,
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		PhiI:   polynomial.EmptyExponent(r.Group()),
		SigmaI: sch.EmptyProof(r.Group()),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
