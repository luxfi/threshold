// Package reveal encrypts to a group's public key so that no one party can
// decrypt, and t+1 of them together can.
//
// The share set is the one a DKG already produced. A party's secret share sᵢ is
// never sent, never combined, and never reconstructed: each party answers a
// ciphertext with sᵢ⋅R, one point, and the requester interpolates those points
// rather than the shares behind them. So the secret exists only as the thing the
// shares would sum to, which is the property a threshold is bought for.
//
// The scheme is hashed ElGamal — DHIES — over the group the shares live in:
//
//	encrypt   r ← random; R = r⋅G; Z = r⋅P; key = KDF(Z, R); body = AEAD(key, m)
//	answer    Dᵢ = sᵢ⋅R, with a proof that logG(Vᵢ) = logR(Dᵢ)
//	combine   Z = Σ λᵢ⋅Dᵢ over t+1 answers; key = KDF(Z, R); m = AEAD⁻¹(key, body)
//
// where P = s⋅G is the group key, Vᵢ = sᵢ⋅G is the verification share the DKG
// published, and λᵢ are Lagrange coefficients at zero over the answering set.
//
// EVERY ANSWER CARRIES A PROOF, and combining verifies each one. Without that, a
// single wrong point — a bug, a stale share, a party that lies — yields a Z that
// is merely wrong, and a wrong Z is indistinguishable from a wrong ciphertext:
// the AEAD fails and nothing says which of the answers was at fault. The proof
// is Chaum-Pedersen, the standard statement that two discrete logs agree, and it
// costs one scalar pair per answer.
//
// What this does NOT defend against: a party that simply refuses. Robustness
// here is having more than t+1 parties willing to answer, not cryptography.
package reveal

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/threshold/pkg/hash"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
)

// Errors a caller can act on. A refusal to combine is never a partial answer:
// either every proof holds and the AEAD opens, or nothing is returned.
var (
	ErrNotEnough  = errors.New("reveal: not enough answers")
	ErrBadProof   = errors.New("reveal: an answer does not prove it used the share it claims")
	ErrNoShareFor = errors.New("reveal: no verification share for an answering party")
	ErrOpen       = errors.New("reveal: the combined key does not open this ciphertext")
)

// keyLen is the AEAD key the KDF produces: AES-256.
const keyLen = 32

// Ciphertext is what encryption produces and what the parties answer. R is the
// ephemeral public point; Body is the AEAD envelope over the message.
//
// It carries no identity of its own. What it is FOR is decided by the caller
// storing it, and what may open it is decided by the share set — so the same
// bytes handed to a different group are simply undecryptable, not misread.
type Ciphertext struct {
	R    curve.Point
	Body []byte
}

// Answer is one party's contribution: the point sᵢ⋅R, and the proof that it
// really is that party's share acting on R rather than an arbitrary point.
type Answer struct {
	ID party.ID
	D  curve.Point
	// E and Z are the Chaum-Pedersen challenge and response.
	E curve.Scalar
	Z curve.Scalar
}

// Encrypt seals a message to the group public key. It needs no share and no
// cooperation — anyone holding P can write something only the group can read,
// which is what makes enrolling a secret a different act from reading one.
func Encrypt(rnd io.Reader, public curve.Point, message []byte) (*Ciphertext, error) {
	if public == nil || public.IsIdentity() {
		return nil, errors.New("reveal: encrypting to no public key")
	}
	group := public.Curve()

	r := sample.Scalar(rnd, group)
	R := r.ActOnBase()
	key := kdf(r.Act(public), R)
	defer zero(key)

	body, err := seal(key, R, message)
	if err != nil {
		return nil, err
	}
	return &Ciphertext{R: R, Body: body}, nil
}

// Answer computes this party's contribution to opening ct.
//
// The share is used twice and revealed neither time: once acting on R, and once
// in the proof's response, where it is masked by a fresh random scalar.
func (c *Ciphertext) Answer(rnd io.Reader, id party.ID, share curve.Scalar) (*Answer, error) {
	if c == nil || c.R == nil || c.R.IsIdentity() {
		return nil, errors.New("reveal: answering a ciphertext with no ephemeral point")
	}
	group := share.Curve()

	D := share.Act(c.R)
	V := share.ActOnBase()

	// Chaum-Pedersen over the two bases G and R.
	k := sample.Scalar(rnd, group)
	e := challenge(id, c.R, V, D, k.ActOnBase(), k.Act(c.R))
	z := group.NewScalar().Set(e).Mul(share).Add(k)

	return &Answer{ID: id, D: D, E: e, Z: z}, nil
}

// Open combines answers into the message.
//
// `threshold` is the number of corruptions the share set tolerates, the same
// number the DKG was given, so t+1 answers are required. Passing the count of
// answers instead would let one party's answer decrypt a 1-of-n "threshold",
// which is why this takes the share set's parameter and not the caller's.
func Open(ct *Ciphertext, threshold int, verification *party.PointMap, answers []*Answer) ([]byte, error) {
	if ct == nil || ct.R == nil {
		return nil, errors.New("reveal: opening nothing")
	}
	if verification == nil {
		return nil, errors.New("reveal: opening without the verification shares")
	}

	// One answer per party. A set that counted the same party twice would reach
	// t+1 with a single share, and Lagrange over a repeated point is not the
	// secret — it is a number nobody chose.
	seen := make(map[party.ID]*Answer, len(answers))
	for _, a := range answers {
		if a == nil || a.D == nil || a.E == nil || a.Z == nil {
			return nil, errors.New("reveal: an answer is incomplete")
		}
		seen[a.ID] = a
	}
	if len(seen) <= threshold {
		return nil, fmt.Errorf("%w: have %d from distinct parties, need %d", ErrNotEnough, len(seen), threshold+1)
	}

	ids := make([]party.ID, 0, len(seen))
	for id, a := range seen {
		V, ok := verification.Points[id]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNoShareFor, id)
		}
		if !a.verify(V, ct.R) {
			return nil, fmt.Errorf("%w: %s", ErrBadProof, id)
		}
		ids = append(ids, id)
	}

	// Z = Σ λᵢ⋅Dᵢ. The coefficients are taken over the answering set, so any
	// t+1 of the parties reach the same Z and no smaller set reaches it at all.
	group := ct.R.Curve()
	lambda := polynomial.Lagrange(group, ids)
	Z := group.NewPoint()
	for _, id := range ids {
		Z = Z.Add(lambda[id].Act(seen[id].D))
	}

	key := kdf(Z, ct.R)
	defer zero(key)
	return open(key, ct.R, ct.Body)
}

// verify checks that D is this party's share acting on R, given the share's
// public commitment V from the DKG.
//
// It recomputes the prover's commitments from the response rather than carrying
// them, so an answer is two scalars and a point however large the group is.
func (a *Answer) verify(V, R curve.Point) bool {
	A := a.Z.ActOnBase().Sub(a.E.Act(V))
	B := a.Z.Act(R).Sub(a.E.Act(a.D))
	return challenge(a.ID, R, V, a.D, A, B).Equal(a.E)
}

// challenge binds the proof to the party, the ciphertext's ephemeral point, the
// share's commitment and the answer. Binding the party is what stops one
// party's valid answer being replayed as another's, which would otherwise let
// t+1 answers come from fewer than t+1 parties.
func challenge(id party.ID, R, V, D, A, B curve.Point) curve.Scalar {
	h := hash.New()
	_ = h.WriteAny(&hash.BytesWithDomain{TheDomain: "reveal/id", Bytes: []byte(id)})
	// A fixed order, written as a slice: ranging a map would hash these in a
	// different order each run and no proof would ever verify twice.
	for _, bound := range []struct {
		domain string
		point  curve.Point
	}{{"reveal/R", R}, {"reveal/V", V}, {"reveal/D", D}, {"reveal/A", A}, {"reveal/B", B}} {
		b, _ := bound.point.MarshalBinary()
		_ = h.WriteAny(&hash.BytesWithDomain{TheDomain: bound.domain, Bytes: b})
	}
	return sample.Scalar(h.Digest(), R.Curve())
}

// kdf derives the AEAD key from the agreed point. R is bound in as well, so the
// key belongs to one ciphertext: two messages that happened to agree on Z — a
// reused ephemeral — still get different keys.
func kdf(Z, R curve.Point) []byte {
	zb, _ := Z.MarshalBinary()
	rb, _ := R.MarshalBinary()
	h := hash.New()
	_ = h.WriteAny(&hash.BytesWithDomain{TheDomain: "reveal/kdf/Z", Bytes: zb})
	_ = h.WriteAny(&hash.BytesWithDomain{TheDomain: "reveal/kdf/R", Bytes: rb})
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(h.Digest(), key); err != nil {
		panic(fmt.Sprintf("reveal: kdf: %v", err))
	}
	return key
}

// seal and open are AES-256-GCM with R as additional data, so a body cannot be
// moved onto another ephemeral point.
func seal(key []byte, R curve.Point, message []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	// The key is used once — it comes from a fresh ephemeral — so a fixed nonce
	// is safe here and one that looked random would only suggest otherwise.
	aad, _ := R.MarshalBinary()
	return gcm.Seal(nil, nonce, message, aad), nil
}

func open(key []byte, R curve.Point, body []byte) ([]byte, error) {
	gcm, err := aead(key)
	if err != nil {
		return nil, err
	}
	if len(body) < gcm.Overhead() {
		return nil, ErrOpen
	}
	nonce := make([]byte, gcm.NonceSize())
	aad, _ := R.MarshalBinary()
	out, err := gcm.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}

func aead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("reveal: aes-256: %w", err)
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
