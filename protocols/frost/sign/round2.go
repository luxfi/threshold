package sign

import (
	"fmt"
	"sort"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/taproot"
)

// This round roughly corresponds with steps 3-6 of Figure 3 in the Frost paper:
//
//	https://eprint.iacr.org/2020/852.pdf
//
// The main differences stem from the lack of a signature authority.
//
// This means that instead of receiving a bundle of all the commitments, instead
// each participant sends us their commitment directly.
//
// Then, instead of sending our scalar response to the authority, we broadcast it
// to everyone instead.
type round2 struct {
	*round1
	// d_i = dᵢ is the first nonce we've created.
	d_i curve.Scalar
	// e_i = eᵢ is the second nonce we've created.
	e_i curve.Scalar
	// D[i] = Dᵢ will contain all of the commitments created by each party, ourself included.
	D map[party.ID]curve.Point
	// E[i] = Eᵢ will contain all of the commitments created by each party, ourself included.
	E map[party.ID]curve.Point
}

type broadcast2 struct {
	round.ReliableBroadcastContent
	// D_i is the first commitment produced by the sender of this message.
	D_i curve.Point
	// E_i is the second commitment produced by the sender of this message.
	E_i curve.Point
}

// StoreBroadcastMessage implements round.BroadcastRound.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// This section roughly follows Figure 3.

	// 3. "After receiving (m, B), each Pᵢ first validates the message m,
	// and then checks Dₗ, Eₗ in Gˣ for each commitment in B, aborting if
	// either check fails."
	//
	// We make a few departures.
	//
	// We implicitly assume that the message validation has happened before
	// calling this protocol.
	//
	// We also receive each Dₗ, Eₗ from the participant l directly, instead of
	// an entire bundle from a signing authority.
	if body.D_i.IsIdentity() || body.E_i.IsIdentity() {
		return fmt.Errorf("nonce commitment is the identity point")
	}

	// Only skip if we already have BOTH; otherwise we could drop one
	if r.D[msg.From] != nil && r.E[msg.From] != nil {
		// Already have both values for this party, skip
		return nil
	}

	// Deep copy points to avoid aliasing issues - use marshal/unmarshal for clean copy
	dBytes, err := body.D_i.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal D_i: %w", err)
	}
	eBytes, err := body.E_i.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal E_i: %w", err)
	}

	dCopy := r.Group().NewPoint()
	if err := dCopy.UnmarshalBinary(dBytes); err != nil {
		return fmt.Errorf("failed to unmarshal D_i: %w", err)
	}
	eCopy := r.Group().NewPoint()
	if err := eCopy.UnmarshalBinary(eBytes); err != nil {
		return fmt.Errorf("failed to unmarshal E_i: %w", err)
	}

	r.D[msg.From] = dCopy
	r.E[msg.From] = eCopy
	return nil
}

// VerifyMessage implements round.Round.
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round2) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	// Check if we have all D and E values from ALL signers
	// This is critical - we MUST have D,E from every signer before proceeding
	signers := r.PartyIDs()
	missingCount := 0
	for _, l := range signers {
		if r.D[l] == nil || r.E[l] == nil {
			missingCount++
		}
		// Also verify they're not identity points (shouldn't happen but double-check)
		if r.D[l] != nil && r.D[l].IsIdentity() {
			return r, fmt.Errorf("party %s has identity point for D", l)
		}
		if r.E[l] != nil && r.E[l].IsIdentity() {
			return r, fmt.Errorf("party %s has identity point for E", l)
		}
	}

	if missingCount > 0 {
		// Not ready yet, return self to continue waiting for broadcasts
		return r, nil
	}

	// This essentially follows parts of Figure 3.

	// 4. "Each Pᵢ then computes the set of binding values ρₗ = H₁(l, m, B).
	// Each Pᵢ then derives the group commitment R = ∑ₗ Dₗ + ρₗ * Eₗ and
	// the challenge c = H₂(R, Y, m)."
	//
	// It's easier to calculate H(m, B, l), that way we can simply clone the hash
	// state after H(m, B), instead of rehashing them each time.
	//
	// We also use a hash of the message, instead of the message directly.

	rho := make(map[party.ID]curve.Scalar)
	// This calculates H(m, B), allowing us to avoid re-hashing this data for
	// each extra party l.
	// IMPORTANT: We must hash CANONICAL BYTES of D and E values to ensure
	// all parties compute identical binding values
	rhoPreHash := hash.New()
	_ = rhoPreHash.WriteAny(messageHash(r.M)) // Use the messageHash wrapper
	// Sort signer IDs to ensure consistent ordering (use only signers in this session)
	sortedSigners := make([]party.ID, 0, len(signers))
	for _, id := range signers {
		sortedSigners = append(sortedSigners, id)
	}
	sort.Slice(sortedSigners, func(i, j int) bool {
		return sortedSigners[i] < sortedSigners[j]
	})

	// Hash canonical bytes of points, not the points themselves
	for _, l := range sortedSigners {
		// Write party ID as canonical bytes
		_ = rhoPreHash.WriteAny(&hash.BytesWithDomain{
			TheDomain: "PartyID",
			Bytes:     []byte(l),
		})
		// Write canonical encoding of D[l]
		dBytes, _ := r.D[l].MarshalBinary()
		_ = rhoPreHash.WriteAny(&hash.BytesWithDomain{
			TheDomain: "D",
			Bytes:     dBytes,
		})
		// Write canonical encoding of E[l]
		eBytes, _ := r.E[l].MarshalBinary()
		_ = rhoPreHash.WriteAny(&hash.BytesWithDomain{
			TheDomain: "E",
			Bytes:     eBytes,
		})
	}
	for _, l := range sortedSigners {
		rhoHash := rhoPreHash.Clone()
		_ = rhoHash.WriteAny(&hash.BytesWithDomain{
			TheDomain: "PartyID",
			Bytes:     []byte(l),
		})
		rho[l] = sample.Scalar(rhoHash.Digest(), r.Group())
	}

	R := r.Group().NewPoint()
	RShares := make(map[party.ID]curve.Point)
	// Use sorted order to ensure consistent R computation
	for _, l := range sortedSigners {
		RShares[l] = rho[l].Act(r.E[l])
		RShares[l] = RShares[l].Add(r.D[l])
		R = R.Add(RShares[l])
	}
	var c curve.Scalar
	if r.taproot {
		// BIP-340 adjustment: We need R to have an even y coordinate. This means
		// conditionally negating k = ∑ᵢ (dᵢ + (eᵢ ρᵢ)), which we can accomplish
		// by negating our dᵢ, eᵢ, if necessary. This entails negating the RShares
		// as well.
		RSecp := R.(*curve.Secp256k1Point)
		if !RSecp.HasEvenY() {
			r.d_i.Negate()
			r.e_i.Negate()
			for _, l := range r.PartyIDs() {
				RShares[l] = RShares[l].Negate()
			}
		}

		// BIP-340 adjustment: we need to calculate our hash as specified in:
		// https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing
		RBytes := RSecp.XBytes()
		PBytes := r.Y.(*curve.Secp256k1Point).XBytes()
		cHash := taproot.TaggedHash("BIP0340/challenge", RBytes, PBytes, r.M)
		c = r.Group().NewScalar().SetNat(new(saferith.Nat).SetBytes(cHash))
	} else {
		// Use canonical bytes for challenge computation
		cHash := hash.New()
		rBytes, _ := R.MarshalBinary()
		_ = cHash.WriteAny(&hash.BytesWithDomain{
			TheDomain: "R",
			Bytes:     rBytes,
		})
		yBytes, _ := r.Y.MarshalBinary()
		_ = cHash.WriteAny(&hash.BytesWithDomain{
			TheDomain: "Y",
			Bytes:     yBytes,
		})
		_ = cHash.WriteAny(messageHash(r.M))
		c = sample.Scalar(cHash.Digest(), r.Group())
	}

	// Lambdas[i] = λᵢ
	// IMPORTANT: Lagrange coefficients must be computed for the set of signers participating in this session
	// r.PartyIDs() returns the signers for this session, not all parties from keygen
	Lambdas := polynomial.Lagrange(r.Group(), r.PartyIDs())
	// 5. "Each Pᵢ computes their response using their long-lived secret share sᵢ
	// by computing zᵢ = dᵢ + (eᵢ ρᵢ) + λᵢ sᵢ c, using S to determine
	// the ith lagrange coefficient λᵢ"

	// Debug: log the computation
	lambda_i := Lambdas[r.SelfID()]
	lambda_s_c := r.Group().NewScalar().Set(lambda_i).Mul(r.sI).Mul(c)
	e_rho := r.Group().NewScalar().Set(rho[r.SelfID()]).Mul(r.e_i)

	zI := r.Group().NewScalar().Set(r.d_i)
	zI.Add(e_rho)
	zI.Add(lambda_s_c)

	// 6. "Each Pᵢ securely deletes ((dᵢ, Dᵢ), (eᵢ, Eᵢ)) from their local storage,
	// and returns zᵢ to SA."
	//
	// Since we don't have a signing authority, we instead broadcast zᵢ.

	// TODO: Securely delete the nonces.

	// Debug: Log what we computed (commented out)
	// fmt.Printf("Party %s round2: R=%v, signers=%v\n", r.SelfID(), R, sortedSigners)

	// Broadcast our response
	err := r.BroadcastMessage(out, &broadcast3{ZI: zI})
	if err != nil {
		return r, err
	}

	return &round3{
		round2:  r,
		R:       R,
		RShares: RShares,
		c:       c,
		z:       map[party.ID]curve.Scalar{r.SelfID(): zI},
		Lambda:  Lambdas,
	}, nil
}

// MessageContent implements round.Round.
func (round2) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		D_i: r.Group().NewPoint(),
		E_i: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
