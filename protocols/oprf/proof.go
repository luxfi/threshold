package oprf

// The proof that makes an evaluation VERIFIABLE.
//
// Without it a party that returns a wrong element is not detected: the client
// derives a wrong key, which it cannot tell from having been given the wrong
// password. That is the whole gap between this file and the plain mode, and it
// matters most exactly where the plain mode is most useful — a committee whose
// members are not all trusted equally.
//
// The statement is a discrete-logarithm equality (Chaum–Pedersen): the same k
// relates the generator to the party's public key AND the blinded element to
// the answer. Proving it reveals nothing about k.
//
//	log_G(K) == log_B(Z),  K = k·G,  Z = k·B
//
// RFC 9497 §2.2.1–2.2.2. The transcript below is byte-for-byte theirs, because
// a proof is only as interoperable as the exact bytes both sides hash: a
// reordered or unprefixed element yields a different challenge and every
// verification fails, or — far worse in a scheme with a batch composite — a
// *shorter* transcript admits two different statements as one.

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// ErrProof is returned when a proof does not verify. It is deliberately one
// error for every reason: a caller learns the party lied, never which step of
// its lie failed, because the difference is only ever useful to the liar.
var ErrProof = errors.New("oprf: evaluation proof does not verify")

// Proof is (c, s) — the challenge and the response.
type Proof struct {
	C curve.Scalar
	S curve.Scalar
}

// Prove shows that `answer` is `k` applied to `blinded`, against the public key
// `pub` = k·G. rand supplies the proof's own blinding scalar.
func Prove(rand io.Reader, k curve.Scalar, pub, blinded, answer curve.Point) (*Proof, error) {
	m, z, err := composites(pub, blinded, answer, k)
	if err != nil {
		return nil, err
	}
	r := sampleNonZero(rand)
	c, err := challenge(pub, m, z, r.Act(group.NewBasePoint()), r.Act(m))
	if err != nil {
		return nil, err
	}
	// s = r - c·k, on a copy: Mul and Sub mutate, and k is the caller's key.
	s := group.NewScalar().Set(c).Mul(k)
	s = group.NewScalar().Set(r).Sub(s)
	return &Proof{C: c, S: s}, nil
}

// Verify checks a proof against the party's public key. It recomputes the
// commitments from (c, s) and re-derives the challenge: t2 = s·G + c·K and
// t3 = s·M + c·Z reproduce the prover's r·G and r·M exactly when the same k
// produced both, and otherwise produce a different challenge.
func Verify(pub, blinded, answer curve.Point, p *Proof) error {
	if p == nil || p.C == nil || p.S == nil {
		return ErrProof
	}
	m, z, err := composites(pub, blinded, answer, nil)
	if err != nil {
		return err
	}
	t2 := p.S.Act(group.NewBasePoint()).Add(p.C.Act(pub))
	t3 := p.S.Act(m).Add(p.C.Act(z))

	expected, err := challenge(pub, m, z, t2, t3)
	if err != nil {
		return err
	}
	if !expected.Equal(p.C) {
		return ErrProof
	}
	return nil
}

// composites folds the (blinded, answer) pair into the single pair the proof is
// about. With one evaluation the fold is still performed rather than skipped:
// the seed binds the pair to THIS public key, so a proof cannot be lifted onto
// another party's answer.
//
// k != nil takes the prover's shortcut, Z = k·M, which is the same point the
// verifier reaches by folding D — and is why the prover never needs D's fold.
func composites(pub, blinded, answer curve.Point, k curve.Scalar) (m, z curve.Point, err error) {
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("oprf: serialize public key: %w", err)
	}
	h := sha512.New()
	writeWithLength(h, pubBytes)
	writeWithLength(h, []byte(vseedDST))
	seed := h.Sum(nil)

	cBytes, err := blinded.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("oprf: serialize blinded element: %w", err)
	}
	dBytes, err := answer.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("oprf: serialize answer: %w", err)
	}

	var idx [2]byte // i = 0; the single evaluation's index
	tr := make([]byte, 0, 2+len(seed)+2+2+len(cBytes)+2+len(dBytes)+len("Composite"))
	tr = appendWithLength(tr, seed)
	tr = append(tr, idx[:]...)
	tr = appendWithLength(tr, cBytes)
	tr = appendWithLength(tr, dBytes)
	tr = append(tr, []byte("Composite")...)

	di, err := group.HashToScalar([]byte(vhashToScalarDST), tr)
	if err != nil {
		return nil, nil, err
	}
	m = di.Act(blinded)
	if k != nil {
		return m, k.Act(m), nil
	}
	return m, di.Act(answer), nil
}

// challenge is the transcript both sides hash, in RFC 9497's order:
// the public key, then M, Z, t2, t3, each length-prefixed, then "Challenge".
func challenge(pub, m, z, t2, t3 curve.Point) (curve.Scalar, error) {
	tr := []byte{}
	for _, pt := range []curve.Point{pub, m, z, t2, t3} {
		b, err := pt.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("oprf: serialize challenge element: %w", err)
		}
		tr = appendWithLength(tr, b)
	}
	tr = append(tr, []byte("Challenge")...)
	return group.HashToScalar([]byte(vhashToScalarDST), tr)
}

func appendWithLength(dst, b []byte) []byte {
	return append(append(dst, byte(len(b)>>8), byte(len(b))), b...)
}

// Answer is one party's evaluation together with the proof that it applied its
// own share. The proof is optional: the plain mode carries none, and a caller
// that combines unproved answers is choosing to trust the committee.
type Answer struct {
	Element curve.Point
	Proof   *Proof
}

// EvaluateVerifiable is Evaluate with a proof. A party runs this instead when
// the client should be able to tell a wrong answer from a wrong password.
func EvaluateVerifiable(rand io.Reader, k Key, blinded curve.Point) (Answer, error) {
	if blinded.IsIdentity() {
		return Answer{}, ErrIdentity
	}
	if k.Public == nil {
		return Answer{}, fmt.Errorf("oprf: party %q has no public share to prove against", k.Party)
	}
	el := k.Share.Act(blinded)
	p, err := Prove(rand, k.Share, k.Public, blinded, el)
	if err != nil {
		return Answer{}, err
	}
	return Answer{Element: el, Proof: p}, nil
}

// CombineVerified checks each party's proof against its own public share before
// interpolating. A party that returns a wrong element is REFUSED BY NAME here,
// where the plain Combine would have folded it in and produced a key that is
// simply wrong — indistinguishable, to the person typing, from a wrong password.
//
// That distinction is the whole reason this exists: "your password is wrong"
// and "one of the five machines lied to you" are different facts, and a scheme
// that cannot separate them makes the second one look like the first forever.
// key is the group public key K = k·G, the one value that says WHICH key this
// evaluation is under. Each proof binds an answer to the share it was made
// with, and nothing in a proof says that share belongs to K — so a client given
// a substituted set of public shares checks every proof against the substituted
// set, finds them all valid, and derives an output under a key someone else
// chose. The shares must therefore be tied back to K, which they are by the
// same interpolation the answers get: Σᵢ λᵢ·pubᵢ over the parties that replied
// is k·G exactly when those shares are shares of k.
func CombineVerified(
	domain []party.ID,
	publics map[party.ID]curve.Point,
	key curve.Point,
	blinded curve.Point,
	answers map[party.ID]Answer,
) (curve.Point, error) {
	if len(answers) == 0 {
		return nil, ErrNoShares
	}
	if key == nil || key.IsIdentity() {
		return nil, fmt.Errorf("%w: no key to check them against", ErrWrongKey)
	}
	elements := make(map[party.ID]curve.Point, len(answers))
	for id, a := range answers {
		pub, ok := publics[id]
		if !ok {
			return nil, fmt.Errorf("%w: %q has no public share", ErrUnknownParty, id)
		}
		if err := Verify(pub, blinded, a.Element, a.Proof); err != nil {
			return nil, fmt.Errorf("oprf: party %q: %w", id, err)
		}
		elements[id] = a.Element
	}

	// The same weights the answers are interpolated with, over the same parties,
	// so the check cannot pass for a set the combination would treat otherwise.
	lambda, err := coefficients(domain, answered(answers))
	if err != nil {
		return nil, err
	}
	sum := group.NewPoint()
	for id := range answers {
		sum = sum.Add(lambda[id].Act(publics[id]))
	}
	if !sum.Equal(key) {
		return nil, ErrWrongKey
	}
	return Combine(domain, elements)
}
