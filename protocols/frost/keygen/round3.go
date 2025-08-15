package keygen

import (
	"fmt"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/internal/types"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// This round corresponds with steps 2-4 of Round 2, Figure 1 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
type round3 struct {
	*round2

	// shareFrom is the secret share sent to us by a given party, including ourselves.
	//
	// shareFrom[l] corresponds to fₗ(i) in the Frost paper, with i our own ID.
	// Using sync.Map for thread-safe concurrent access
	shareFrom *sync.Map // map[party.ID]curve.Scalar
}

type message3 struct {
	// FLi is the secret share sent from party l to this party.
	FLi curve.Scalar
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// CL is contribution to the chaining key for this party.
	CL types.RID
	// Decommitment = uᵢ decommitment bytes
	Decommitment hash.Decommitment
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// During refresh, skip chain key verification
	if !r.refresh {
		if err := body.CL.Validate(); err != nil {
			return err
		}
		// Verify that the commitment to the chain key contribution matches
		commitmentValue, exists := r.ChainKeyCommitments.Load(from)
		if !exists {
			// This can happen if we receive round3 messages before all round2 messages
			// The protocol handler will retry this message later
			return round.ErrNotReady
		}
		commitment, _ := commitmentValue.([]byte)

		// Use session-based hash for verification - using the SENDER's ID
		// The Helper should be the same as the one used in round1 for commitment creation
		if !r.Helper.HashForID(from).Decommit(commitment, body.Decommitment, body.CL) {
			return fmt.Errorf("failed to verify chain key commitment from party %s (hash mismatch)", from)
		}
		r.ChainKeys.Store(from, body.CL)
	} else {
		// During refresh, chain key should be empty
		if body.CL == nil || len(body.CL) == 0 {
			r.ChainKeys.Store(from, types.EmptyRID())
		} else {
			r.ChainKeys.Store(from, body.CL)
		}
	}
	return nil
}

// VerifyMessage implements round.Round.
func (r *round3) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*message3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.FLi == nil {
		return round.ErrNilFields
	}

	return nil
}

// StoreMessage implements round.Round.
//
// Verify the VSS condition here since we will not be sending this message to other parties for verification.
func (r *round3) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message3)

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 2. "Each Pᵢ verifies their shares by calculating
	//
	//   fₗ(i) * G =? ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕₗₖ
	//
	// aborting if the check fails."
	expected := body.FLi.ActOnBase()

	// Load phi from sync.Map
	phiValue, ok := r.Phi.Load(from)
	if !ok {
		// This can happen if we receive p2p messages before broadcast messages
		// The protocol handler will retry this message later
		return round.ErrNotReady
	}
	phi, _ := phiValue.(*polynomial.Exponent)
	if phi == nil {
		return round.ErrNotReady
	}

	actual := phi.Evaluate(r.SelfID().Scalar(r.Group()))
	if !expected.Equal(actual) {
		// Debug: log the mismatch
		return fmt.Errorf("VSS failed to validate from party %s (expected != actual)", from)
	}

	// Store share using sync.Map
	r.shareFrom.Store(from, body.FLi)

	return nil
}

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	// All messages should have been received before Finalize is called
	// The protocol handler ensures all expected messages are received

	// Verify we have all chain keys (can be empty during refresh)
	for _, j := range r.PartyIDs() {
		if _, ok := r.ChainKeys.Load(j); !ok {
			// During refresh, set empty chain key if missing
			if r.refresh {
				r.ChainKeys.Store(j, types.EmptyRID())
			} else {
				return nil, fmt.Errorf("missing chain key from party %s", j)
			}
		}
	}

	// Now we have all chain keys, XOR them together
	// During refresh, chain keys are empty, so ChainKey remains empty
	ChainKey := types.EmptyRID()
	if !r.refresh {
		for _, j := range r.PartyIDs() {
			ckValue, _ := r.ChainKeys.Load(j)
			ck, _ := ckValue.(types.RID)
			if ck == nil || len(ck) == 0 {
				return nil, fmt.Errorf("invalid chain key from party %s", j)
			}
			ChainKey.XOR(ck)
		}
	}

	// These steps come from Figure 1, Round 2 of the Frost paper

	// 3. "Each P_i calculates their long-lived private signing share by computing
	// sᵢ = ∑ₗ₌₁ⁿ fₗ(i), stores s_i securely, and deletes each fₗ(i)"

	// Iterate over shares in sync.Map
	// Debug: count shares
	shareCount := 0
	r.shareFrom.Range(func(key, value interface{}) bool {
		fLi := value.(curve.Scalar)
		r.privateShare.Add(fLi)
		shareCount++
		// Delete from sync.Map after processing
		r.shareFrom.Delete(key)
		return true
	})

	// We should have exactly n shares (including our own)
	if shareCount != r.PartyIDs().Len() {
		return r.AbortRound(fmt.Errorf("expected %d shares, got %d", r.PartyIDs().Len(), shareCount)), nil
	}

	// 4. "Each Pᵢ calculates their public verification share Yᵢ = sᵢ • G,
	// and the group's public key Y = ∑ⱼ₌₁ⁿ ϕⱼ₀. Any participant
	// can compute the verification share of any other participant by calculating
	//
	// Yᵢ = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ."

	// Iterate over Phi in sync.Map to calculate public key
	r.Phi.Range(func(key, value interface{}) bool {
		phiJ := value.(*polynomial.Exponent)
		r.publicKey = r.publicKey.Add(phiJ.Constant())
		return true
	})

	// This accomplishes the same sum as in the paper, by first summing
	// together the exponent coefficients, and then evaluating.
	exponents := make([]*polynomial.Exponent, 0, r.PartyIDs().Len())
	r.Phi.Range(func(key, value interface{}) bool {
		phiJ := value.(*polynomial.Exponent)
		exponents = append(exponents, phiJ)
		return true
	})
	verificationExponent, err := polynomial.Sum(exponents)
	if err != nil {
		panic(err)
	}
	if r.refresh {
		// For refresh, add to existing verification shares
		for k, v := range r.verificationShares {
			r.verificationShares[k] = v.Add(verificationExponent.Evaluate(k.Scalar(r.Group())))
		}
	} else {
		// For fresh keygen, set verification shares directly
		// Debug: log that we're in fresh keygen mode
		for k := range r.verificationShares {
			evaluated := verificationExponent.Evaluate(k.Scalar(r.Group()))
			r.verificationShares[k] = evaluated
		}
	}

	if r.taproot {
		// BIP-340 adjustment: If our public key is odd, then the underlying secret
		// needs to be negated. Since this secret is ∑ᵢ aᵢ₀, we can negated each
		// of these. Had we generated the polynomials -fᵢ instead, we would have
		// ended up with the correct sharing of the secret. So, this means that
		// we can correct by simply negating our share.
		//
		// We assume that everyone else does the same, so we negate all the verification
		// shares.
		YSecp := r.publicKey.(*curve.Secp256k1Point)
		if !YSecp.HasEvenY() {
			r.privateShare.Negate()
			for i, yI := range r.verificationShares {
				r.verificationShares[i] = yI.Negate()
			}
		}
		secpVerificationShares := make(map[party.ID]*curve.Secp256k1Point)
		for k, v := range r.verificationShares {
			secpVerificationShares[k] = v.(*curve.Secp256k1Point)
		}
		return r.ResultRound(&TaprootConfig{
			ID:                 r.SelfID(),
			Threshold:          r.threshold,
			PrivateShare:       r.privateShare.(*curve.Secp256k1Scalar),
			PublicKey:          YSecp.XBytes()[:],
			ChainKey:           ChainKey,
			VerificationShares: secpVerificationShares,
		}), nil
	}

	return r.ResultRound(&Config{
		ID:                 r.SelfID(),
		Threshold:          r.threshold,
		PrivateShare:       r.privateShare,
		PublicKey:          r.publicKey,
		ChainKey:           ChainKey,
		VerificationShares: party.NewPointMap(r.verificationShares),
	}), nil
}

// RoundNumber implements round.Content.
func (message3) RoundNumber() round.Number { return 3 }

// MessageContent implements round.Round.
func (r *round3) MessageContent() round.Content {
	return &message3{
		FLi: r.Group().NewScalar(),
	}
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent { return &broadcast3{} }

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
