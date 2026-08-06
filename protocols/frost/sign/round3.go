package sign

import (
	"fmt"
	"sync"

	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/taproot"
)

// This corresponds with step 7 of Figure 3 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The big difference, once again, stems from their being no signing authority.
// Instead, each participant calculates the signature on their own.
type round3 struct {
	*round2
	// R is the group commitment, and the first part of the consortium signature
	R curve.Point
	// RShares is the fraction each participant contributes to the group commitment
	//
	// This corresponds to R_i in the Frost paper
	RShares map[party.ID]curve.Point
	// c is the challenge, computed as H(R, Y, m).
	c curve.Scalar
	// z contains the response from each participant
	//
	// z[i] corresponds to zᵢ in the Frost paper
	z   map[party.ID]curve.Scalar
	zMu *sync.Mutex

	// Lambda contains all Lagrange coefficients of the parties participating in this session.
	// Lambda[l] = λₗ
	Lambda map[party.ID]curve.Scalar
}

type broadcast3 struct {
	round.NormalBroadcastContent
	// ZI is the response scalar computed by the sender of this message.
	ZI curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.ZI == nil {
		return round.ErrNilFields
	}

	// These steps come from Figure 3 of the Frost paper.

	// 7.b "Verify the validity of each response by checking
	//
	//    zᵢ • G = Rᵢ + c * λᵢ * Yᵢ
	//
	// for each share zᵢ, i in S. If the equality does not hold, identify and report the
	// misbehaving participant, and then abort. Otherwise, continue."
	//
	// Note that step 7.a is an artifact of having a signing authority. In our case,
	// we've already computed everything that step computes.

	// Verify: zᵢ • G = Rᵢ + c * λᵢ * Yᵢ
	expected := r.c.Act(r.Lambda[from].Act(r.YShares[from])).Add(r.RShares[from])

	actual := body.ZI.ActOnBase()

	if !actual.Equal(expected) {
		return fmt.Errorf("failed to verify response from %v", from)
	}

	r.zMu.Lock()
	r.z[from] = body.ZI
	r.zMu.Unlock()

	return nil
}

// VerifyMessage implements round.Round.
func (*round3) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (*round3) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round3) Finalize(chan<- *round.Message) (round.Session, error) {
	// These steps come from Figure 3 of the Frost paper.

	// 7.c "Compute the group's response z = ∑ᵢ zᵢ"
	r.zMu.Lock()
	zMap := make(map[party.ID]curve.Scalar, len(r.z))
	for k, v := range r.z {
		zMap[k] = v
	}
	r.zMu.Unlock()

	z := r.Group().NewScalar()
	for _, z_l := range zMap {
		z.Add(z_l)
	}

	// The format of our signature depends on the signature scheme
	if r.sr25519 {
		// sr25519 signature: R (32 bytes) || s (32 bytes), with high bit of s set
		// R is the ristretto255 canonical encoding of the group commitment
		RBytes, err := r.R.MarshalBinary()
		if err != nil {
			return r, fmt.Errorf("failed to marshal R: %w", err)
		}
		// z is the response scalar; for ristretto255 MarshalBinary returns big-endian,
		// but go-schnorrkel expects little-endian encoding. Convert.
		zBE, err := z.MarshalBinary()
		if err != nil {
			return r, fmt.Errorf("failed to marshal z: %w", err)
		}
		zLE := make([]byte, 32)
		for i := 0; i < 32; i++ {
			zLE[i] = zBE[31-i]
		}

		var sigBytes [64]byte
		copy(sigBytes[:32], RBytes)
		copy(sigBytes[32:], zLE)
		// Set the schnorrkel marker bit (high bit of byte 63)
		sigBytes[63] |= 128

		sig := SR25519Signature{
			Data:           sigBytes,
			SigningContext: r.signingContext,
		}

		// Verify using the Merlin transcript path
		if !sig.Verify(r.Y, r.M) {
			return r.AbortRound(fmt.Errorf("sr25519 signature verification failed")), nil
		}

		return r.ResultRound(sig), nil
	} else if r.ed25519 {
		// R is already the compressed Edwards encoding RFC 8032 wants, and z is
		// reduced mod L by edwards25519's scalar arithmetic, so it is canonical
		// and its top three bits are clear. Ed25519Signature owns the one
		// remaining detail: S goes on the wire little-endian.
		sig := Ed25519Signature{R: r.R, S: z}

		// Checked against crypto/ed25519 itself, so a signature can only leave
		// this protocol if the verifier Solana and TON run accepts it.
		if !sig.Verify(r.Y, r.M) {
			return r.AbortRound(fmt.Errorf("ed25519 signature failed RFC 8032 verification")), nil
		}

		return r.ResultRound(sig), nil
	} else if r.taproot {
		sig := taproot.Signature(make([]byte, 0, taproot.SignatureLen))
		sig = append(sig, r.R.(*curve.Secp256k1Point).XBytes()...)
		zBytes, err := z.MarshalBinary()
		if err != nil {
			return r, err
		}
		sig = append(sig, zBytes...)

		taprootPub := taproot.PublicKey(r.Y.(*curve.Secp256k1Point).XBytes())

		if !taprootPub.Verify(sig, r.M) {
			return r.AbortRound(fmt.Errorf("generated signature failed to verify")), nil
		}

		return r.ResultRound(sig), nil
	} else {
		sig := Signature{
			R: r.R,
			z: z,
		}

		// Check if signature verifies
		if !sig.Verify(r.Y, r.M) {
			return r.AbortRound(fmt.Errorf("signature verification failed")), nil
		}

		return r.ResultRound(sig), nil
	}
}

// MessageContent implements round.Round.
func (*round3) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		ZI: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (*round3) Number() round.Number { return 3 }
