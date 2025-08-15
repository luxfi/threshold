package keygen

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/arith"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/paillier"
	"github.com/luxfi/threshold/pkg/pedersen"
	zkfac "github.com/luxfi/threshold/pkg/zk/fac"
	zkmod "github.com/luxfi/threshold/pkg/zk/mod"
	zkprm "github.com/luxfi/threshold/pkg/zk/prm"
	zksch "github.com/luxfi/threshold/pkg/zk/sch"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2
	// SchnorrCommitments[j] = Aⱼ
	// Commitment for proof of knowledge in the last round
	// Using sync.Map for thread-safe concurrent access
	SchnorrCommitments sync.Map // map[party.ID]*zksch.Commitment
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// RID = RIDᵢ
	RID types.RID
	C   types.RID
	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent
	// SchnorrCommitments = Aᵢ Schnorr commitment for the final confirmation
	SchnorrCommitments *zksch.Commitment
	ElGamalPublic      curve.Point
	// N Paillier and Pedersen N = p•q, p ≡ q ≡ 3 mod 4
	N *saferith.Modulus
	// S = r² mod N
	S *saferith.Nat
	// T = Sˡ mod N
	T *saferith.Nat
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - verify length of Schnorr commitments
// - verify degree of VSS polynomial Fⱼ "in-the-exponent"
//   - if keygen, verify Fⱼ(0) != ∞
//   - if refresh, verify Fⱼ(0) == ∞
//
// - validate Paillier
// - validate Pedersen
// - validate commitments.
// - store ridⱼ, Cⱼ, Nⱼ, Sⱼ, Tⱼ, Fⱼ(X), Aⱼ.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.N == nil || body.S == nil || body.T == nil || body.VSSPolynomial == nil || body.SchnorrCommitments == nil {
		return round.ErrNilFields
	}
	// check RID length
	if err := body.RID.Validate(); err != nil {
		return fmt.Errorf("rid: %w", err)
	}
	if err := body.C.Validate(); err != nil {
		return fmt.Errorf("chainkey: %w", err)
	}
	// check decommitment
	if err := body.Decommitment.Validate(); err != nil {
		return err
	}

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		return errors.New("vss polynomial has incorrect constant")
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold() {
		return errors.New("vss polynomial has incorrect degree")
	}

	// Set Paillier
	if err := paillier.ValidateN(body.N); err != nil {
		return err
	}

	// Verify Pedersen
	if err := pedersen.ValidateParameters(body.N, body.S, body.T); err != nil {
		return err
	}
	// Verify decommit
	// Use KeyID for stable cross-phase verification instead of sessionID-based hash
	commitmentValue, _ := r.Commitments.Load(from)
	commitment, _ := commitmentValue.(hash.Commitment)
	if !r.keyID.HashForParty(from).Decommit(commitment, body.Decommitment,
		body.RID, body.C, VSSPolynomial, body.SchnorrCommitments, body.ElGamalPublic, body.N, body.S, body.T) {
		return errors.New("failed to decommit")
	}
	// Store using sync.Map for thread-safe concurrent access
	r.RIDs.Store(from, body.RID)
	r.ChainKeys.Store(from, body.C)
	r.PaillierPublic.Store(from, paillier.NewPublicKey(body.N))
	r.Pedersen.Store(from, pedersen.New(arith.ModulusFromN(body.N), body.S, body.T))
	r.VSSPolynomials.Store(from, body.VSSPolynomial)
	r.SchnorrCommitments.Store(from, body.SchnorrCommitments)
	r.ElGamalPublic.Store(from, body.ElGamalPublic)

	return nil
}

// VerifyMessage implements round.Round.
func (round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - set rid = ⊕ⱼ ridⱼ and update hash state
// - prove Nᵢ is Blum
// - prove Pedersen parameters
// - prove Schnorr for all coefficients of fᵢ(X)
//   - if refresh skip constant coefficient
//
// - send proofs and encryption of share for Pⱼ.
func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Check if we have received all broadcasts before proceeding
	// Count ChainKeys and RIDs in sync.Map
	chainKeyCount := 0
	r.ChainKeys.Range(func(_, _ interface{}) bool {
		chainKeyCount++
		return true
	})
	ridCount := 0
	r.RIDs.Range(func(_, _ interface{}) bool {
		ridCount++
		return true
	})
	if chainKeyCount < r.N() || ridCount < r.N() {
		// Not ready to advance yet - return ourselves to wait for more messages
		return r, nil
	}

	// c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			ckValue, _ := r.ChainKeys.Load(j)
			ck, _ := ckValue.(types.RID)
			chainKey.XOR(ck)
		}
	}
	// RID = ⊕ⱼ RIDⱼ
	rid := types.EmptyRID()
	for _, j := range r.PartyIDs() {
		ridValue, exists := r.RIDs.Load(j)
		if !exists {
			return r, fmt.Errorf("missing RID for party %s", j)
		}
		ridJ, _ := ridValue.(types.RID)
		if ridJ == nil {
			return r, fmt.Errorf("missing RID for party %s", j)
		}
		rid.XOR(ridJ)
	}

	// Use a fresh hash for proof generation to ensure consistency across parties
	// All parties will use the same empty hash state for proof generation/verification
	h := hash.New()

	// Load Paillier public key for self
	paillierValue, ok := r.PaillierPublic.Load(r.SelfID())
	if !ok {
		return r, errors.New("paillier public key not found for self")
	}
	paillierSelf, ok := paillierValue.(*paillier.PublicKey)
	if !ok || paillierSelf == nil {
		return r, errors.New("invalid paillier public key for self")
	}

	// Load Pedersen parameters for self
	pedersenValue, ok := r.Pedersen.Load(r.SelfID())
	if !ok {
		return r, errors.New("pedersen parameters not found for self")
	}
	pedersenSelf, ok := pedersenValue.(*pedersen.Parameters)
	if !ok || pedersenSelf == nil {
		return r, errors.New("invalid pedersen parameters for self")
	}

	// Prove N is a blum prime with zkmod
	mod := zkmod.NewProof(h.Clone(), zkmod.Private{
		P:   r.PaillierSecret.P(),
		Q:   r.PaillierSecret.Q(),
		Phi: r.PaillierSecret.Phi(),
	}, zkmod.Public{N: paillierSelf.N()}, r.Pool)

	// prove s, t are correct as aux parameters with zkprm
	prm := zkprm.NewProof(zkprm.Private{
		Lambda: r.PedersenSecret,
		Phi:    r.PaillierSecret.Phi(),
		P:      r.PaillierSecret.P(),
		Q:      r.PaillierSecret.Q(),
	}, h.Clone(), zkprm.Public{Aux: pedersenSelf}, r.Pool)

	if err := r.BroadcastMessage(out, &broadcast4{
		Mod: mod,
		Prm: prm,
	}); err != nil {
		return r, err
	}

	// create P2P messages with encrypted shares and zkfac proof
	for _, j := range r.OtherPartyIDs() {
		// Load Pedersen parameters for party j
		pedersenJValue, ok := r.Pedersen.Load(j)
		if !ok {
			return r, fmt.Errorf("pedersen parameters not found for party %s", j)
		}
		pedersenJ, ok := pedersenJValue.(*pedersen.Parameters)
		if !ok || pedersenJ == nil {
			return r, fmt.Errorf("invalid pedersen parameters for party %s", j)
		}

		// Prove that the factors of N are relatively large
		fac := zkfac.NewProof(zkfac.Private{P: r.PaillierSecret.P(), Q: r.PaillierSecret.Q()}, h.Clone(), zkfac.Public{
			N:   paillierSelf.N(),
			Aux: pedersenJ,
		})

		// compute fᵢ(j)
		share := r.VSSSecret.Evaluate(j.Scalar(r.Group()))
		// Encrypt share
		// Load Paillier public key for party j
		paillierJValue, ok := r.PaillierPublic.Load(j)
		if !ok {
			return r, fmt.Errorf("paillier public key not found for party %s", j)
		}
		paillierJ, ok := paillierJValue.(*paillier.PublicKey)
		if !ok || paillierJ == nil {
			return r, fmt.Errorf("invalid paillier public key for party %s", j)
		}
		C, _ := paillierJ.Enc(curve.MakeInt(share))

		err := r.SendMessage(out, &message4{
			Share: C,
			Fac:   fac,
		}, j)
		if err != nil {
			return r, err
		}
	}

	// Don't update hash state with RID here - it will be done in round4 after verification
	// This ensures proofs created with pre-RID hash can be verified with pre-RID hash
	return &round4{
		round3:   r,
		RID:      rid,
		ChainKey: chainKey,
	}, nil
}

// MessageContent implements round.Round.
func (round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		VSSPolynomial:      polynomial.EmptyExponent(r.Group()),
		SchnorrCommitments: zksch.EmptyCommitment(r.Group()),
		ElGamalPublic:      r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
