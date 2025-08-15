package keygen

import (
	"sync"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/paillier"
	"github.com/luxfi/threshold/pkg/pedersen"
	zksch "github.com/luxfi/threshold/pkg/zk/sch"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	// Using sync.Map for thread-safe concurrent access
	VSSPolynomials sync.Map // map[party.ID]*polynomial.Exponent

	// Commitments[j] = H(Keygen3ⱼ ∥ Decommitments[j])
	// Using sync.Map for thread-safe concurrent access
	Commitments sync.Map // map[party.ID]hash.Commitment

	// RIDs[j] = ridⱼ
	// Using sync.Map for thread-safe concurrent access
	RIDs sync.Map // map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	// Using sync.Map for thread-safe concurrent access
	ChainKeys sync.Map // map[party.ID]types.RID

	// ShareReceived[j] = xʲᵢ
	// share received from party j
	// Using sync.Map for thread-safe concurrent access
	ShareReceived sync.Map // map[party.ID]curve.Scalar

	// Using sync.Map for thread-safe concurrent access
	ElGamalPublic sync.Map // map[party.ID]curve.Point
	// PaillierPublic[j] = Nⱼ
	// Using sync.Map for thread-safe concurrent access
	PaillierPublic sync.Map // map[party.ID]*paillier.PublicKey

	// Pedersen[j] = (Nⱼ,Sⱼ,Tⱼ)
	// Using sync.Map for thread-safe concurrent access
	Pedersen sync.Map // map[party.ID]*pedersen.Parameters

	ElGamalSecret curve.Scalar

	// PaillierSecret = (pᵢ, qᵢ)
	PaillierSecret *paillier.SecretKey

	// PedersenSecret = λᵢ
	// Used to generate the Pedersen parameters
	PedersenSecret *saferith.Nat

	// SchnorrRand = aᵢ
	// Randomness used to compute Schnorr commitment of proof of knowledge of secret share
	SchnorrRand *zksch.Randomness

	// Decommitment for Keygen3ᵢ
	Decommitment hash.Decommitment // uᵢ
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// Commitment = Vᵢ = H(ρᵢ, Fᵢ(X), Aᵢ, Yᵢ, Nᵢ, sᵢ, tᵢ, uᵢ)
	Commitment hash.Commitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if err := body.Commitment.Validate(); err != nil {
		return err
	}
	// Store using sync.Map for thread-safe concurrent access
	r.Commitments.Store(msg.From, body.Commitment)
	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Load values from sync.Map for self ID
	ridValue, _ := r.RIDs.Load(r.SelfID())
	rid, _ := ridValue.(types.RID)

	chainKeyValue, _ := r.ChainKeys.Load(r.SelfID())
	chainKey, _ := chainKeyValue.(types.RID)

	vssPolyValue, _ := r.VSSPolynomials.Load(r.SelfID())
	vssPoly, _ := vssPolyValue.(*polynomial.Exponent)

	elGamalValue, _ := r.ElGamalPublic.Load(r.SelfID())
	elGamal, _ := elGamalValue.(curve.Point)

	pedersenValue, _ := r.Pedersen.Load(r.SelfID())
	pedersen, _ := pedersenValue.(*pedersen.Parameters)

	// Send the message we created in Round1 to all
	err := r.BroadcastMessage(out, &broadcast3{
		RID:                rid,
		C:                  chainKey,
		VSSPolynomial:      vssPoly,
		SchnorrCommitments: r.SchnorrRand.Commitment(),
		ElGamalPublic:      elGamal,
		N:                  pedersen.N(),
		S:                  pedersen.S(),
		T:                  pedersen.T(),
		Decommitment:       r.Decommitment,
	})
	if err != nil {
		return r, err
	}
	nextRound := &round3{
		round2: r,
	}
	// SchnorrCommitments sync.Map is already initialized (zero value)
	return nextRound, nil
}

// PreviousRound implements round.Round.
func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (round2) BroadcastContent() round.BroadcastContent { return &broadcast2{} }

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
