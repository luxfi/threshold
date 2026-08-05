// Package tkem is threshold key encapsulation over ristretto255: a t-of-n
// committee decapsulates a symmetric key WITHOUT ever assembling the private
// key that the key is encapsulated to.
//
// # Why this package exists
//
// A key manager wants a root secret that no machine holds. Secret-sharing a
// root key does not achieve that — reconstructing it at boot puts the whole
// key in one process's heap, which is the property we were trying to avoid.
// Threshold SIGNING does not achieve it either: a signature is unique, so
// hashing one gives a deterministic key, but the derived key is again a value
// living in one process. Both fail for the same reason — a key that is USED by
// one machine must EXIST on one machine.
//
// The way out is to never need the private key in one place. Each party applies
// its own share to the ciphertext and returns a PARTIAL decapsulation; the
// caller combines partials into the encapsulated key. The private key x is a
// number no participant, and no combiner, ever computes.
//
// # Construction
//
// Threshold hashed ElGamal (a KEM in the shape of Shoup and Gennaro's TDH2,
// EUROCRYPT'98). G is the ristretto255 generator, H a second generator with
// unknown discrete logarithm, x the Shamir-shared private key, Y = x·G, and
// V_i = x_i·G the per-party verification shares:
//
//	Encapsulate:   r ←$ Z_q,  R = r·G,  R̄ = r·H
//	               key = KDF(R ‖ r·Y ‖ label)
//	               π_ct = proof that log_G R = log_H R̄   (well-formedness)
//	Partial:       D_i = x_i·R
//	               π_i = proof that log_G V_i = log_R D_i (correct decapsulation)
//	Combine:       S = Σ λ_i·D_i = x·R = r·Y
//	               key = KDF(R ‖ S ‖ label)
//
// Correctness is the interpolation identity Σ λ_i x_i = x evaluated in the
// exponent, so every quorum lands on the same S and the same key.
//
// # Threat model
//
// The adversary controls the network and up to t−1 of the n parties, and may
// submit ciphertexts of its choosing to honest parties. It is a Lux-operated
// committee, so the realistic corruption is a compromised node rather than a
// mutually distrusting stranger; the construction does not depend on that
// assumption holding, and stays correct against a malicious minority.
//
// # Security claims (each names the test that fails if the claim is false)
//
//	Claim 1  Quorum agreement. Every t-subset decapsulates the key the
//	         encapsulator produced. TestClaim1_QuorumAgreement.
//	Claim 2  Threshold secrecy. t−1 parties cannot decapsulate.
//	         TestClaim2_BelowThreshold.
//	Claim 3  Verified partials. A forged partial is rejected and its author
//	         named, never absorbed into a wrong key. TestClaim3_ForgedPartial.
//	Claim 4  No assembly. x exists on no device at any point.
//	         TestClaim4_SecretIsNeverAssembled (+ the structural test).
//	Claim 5  Context binding. A key is bound to its label and its ciphertext.
//	         TestClaim5_LabelBinding, TestClaim5_CiphertextBinding.
//	Claim 6  Sealing is unilateral. Encapsulation needs only the public key,
//	         so no node can poison what is written. TestClaim6_SealNeedsNoQuorum.
//	Claim 7  Chosen-ciphertext refusal. A party releases a partial only for a
//	         ciphertext whose author proved knowledge of r.
//	         TestClaim7_MalleatedCiphertextRefused.
//
// Claim 3 is the one that carries operational weight, and it is the lesson from
// the threshold-BLS aggregator that preceded this package: that aggregator
// interpolated partials WITHOUT checking them, so one dishonest partial yielded
// a well-formed but wrong result. Here every partial carries a Chaum-Pedersen
// proof and Combine refuses the whole operation if any proof fails, naming the
// party. Wrong keys are not a reachable outcome, and the culprit is identified.
//
// Claim 7 is why the ciphertext carries a proof at all. Without it, a party
// that will compute x_i·R for any R handed to it is a Diffie-Hellman oracle:
// an adversary submits R' = a·R and recovers the key for R. Requiring the
// author to prove knowledge of r closes that, because an adversary deriving R'
// from a captured R does not know log_G R'.
//
// # Assumptions
//
// Claim 2 rests on the Decisional Diffie-Hellman assumption in ristretto255.
// Claims 3 and 7 rest on the soundness of Fiat-Shamir applied to the
// Chaum-Pedersen sigma protocol, in the random oracle model, with SHA-512 as
// the oracle. Claim 1 is unconditional (it is an algebraic identity).
//
// # What this does NOT give you
//
// The combiner learns the decapsulated key, and therefore whatever that key
// opens. That is not a defect to be engineered away — the caller asked to
// decrypt something, so the plaintext necessarily exists in its address space
// afterwards. What the construction removes is the LONG-LIVED secret: there is
// no value whose compromise opens everything, and no machine to steal it from.
//
// Nothing here is post-quantum. DDH falls to Shor. This is a classical
// primitive and is labelled as one.
package tkem

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/frost/keygen"
)

// KeyLen is the encapsulated key length in bytes. It is 32 because the key is
// consumed as an AES-256-GCM key; a caller needing a different length should
// derive from this one rather than widening the primitive.
const KeyLen = 32

// Domain separators. Every hash in this package is prefixed with exactly one of
// them, so a digest computed for one purpose can never be replayed as another.
const (
	domainGenerator  = "lux/tkem/ristretto255/v1/generator-h"
	domainWellFormed = "lux/tkem/ristretto255/v1/well-formed"
	domainPartial    = "lux/tkem/ristretto255/v1/partial"
	domainKey        = "lux/tkem/ristretto255/v1/key"
)

// Errors. Every one of them is a refusal to produce a key, never a fallback to
// a weaker one.
var (
	ErrMalformedCiphertext = errors.New("tkem: ciphertext well-formedness proof failed")
	ErrBelowThreshold      = errors.New("tkem: fewer partial decapsulations than the threshold")
	ErrUnknownParty        = errors.New("tkem: partial decapsulation from a party with no verification share")
	ErrDuplicateParty      = errors.New("tkem: two partial decapsulations from the same party")
	ErrGroup               = errors.New("tkem: key material is not on ristretto255")
	ErrShape               = errors.New("tkem: threshold must be at least 1 and at most the number of parties")
)

// ErrBadPartial is a partial decapsulation whose proof does not verify. It names
// the party so a caller can evict it: this is the identifiable abort that the
// surrounding session layer does not otherwise provide.
type ErrBadPartial struct{ Culprit party.ID }

func (e ErrBadPartial) Error() string {
	return fmt.Sprintf("tkem: partial decapsulation from %q failed its correctness proof", e.Culprit)
}

// group is the one group this package works in. ristretto255 is a prime-order
// group with canonical encodings, so there is no cofactor to clear, no small
// subgroup to land in, and no invalid encoding to accept — the whole family of
// point-validation mistakes is absent by construction rather than by checking.
var group = curve.Ristretto255{}

// Curve returns the group this package operates over, so callers driving the
// key generation do not have to name it a second time.
func Curve() curve.Curve { return group }

// generatorH is the second generator. It is the image of a fixed tag under the
// ristretto255 one-way map, so its discrete logarithm base G is unknown to
// everybody including whoever wrote this line. That is the entire point: the
// well-formedness proof means nothing if someone knows log_G H.
var generatorH = func() curve.Point {
	d := sha512.Sum512([]byte(domainGenerator))
	p := group.NewPoint().(*curve.Ristretto255Point)
	return p.FromUniformBytes(d[:])
}()

// GeneratorH exposes the second generator for test vectors and cross-checks.
func GeneratorH() curve.Point { return clonePoint(generatorH) }

// Group is the public description of a committee: what it can do and how to
// check it did it. It contains no secret and is safe to publish.
type Group struct {
	// Threshold is how many parties must cooperate to decapsulate. It counts
	// PARTIES, not polynomial degree; FromKeygen does that conversion so the
	// ambiguity is resolved in exactly one place.
	Threshold int
	// PublicKey is Y = x·G. Encapsulation needs this and nothing else.
	PublicKey curve.Point
	// VerificationShares maps each party to V_i = x_i·G, which is what makes a
	// partial decapsulation checkable.
	VerificationShares map[party.ID]curve.Point
}

// Share is one party's private holding: a scalar that is a point on the sharing
// polynomial, and never the polynomial's value at zero.
type Share struct {
	ID     party.ID
	Secret curve.Scalar
}

// Ciphertext is the public header produced by Encapsulate. It carries no
// plaintext — the key it encapsulates is used by the caller to seal the actual
// payload — so a Ciphertext is safe to store next to what it protects.
type Ciphertext struct {
	// R = r·G and RBar = r·H.
	R, RBar curve.Point
	// E, F are the Fiat-Shamir challenge and response proving that R and RBar
	// share a discrete logarithm, i.e. that whoever produced them knew r.
	E, F curve.Scalar
	// Label binds this ciphertext to its context. Bind whatever must not be
	// interchangeable — the identity of the secret being protected, and ideally
	// the sealed payload itself — because two ciphertexts with the same label
	// are two ciphertexts a caller may confuse.
	Label []byte
}

// Partial is one party's contribution to a decapsulation, with the proof that
// makes it checkable.
type Partial struct {
	ID party.ID
	// D = x_i·R.
	D curve.Point
	// E, F prove log_G V_i = log_R D without revealing x_i.
	E, F curve.Scalar
}

// Encapsulate produces a fresh key and the ciphertext a quorum needs to recover
// it. It takes the group public key and nothing else: no share, no quorum, no
// network. A caller can seal secrets all day while every party is offline, and
// a compromised party cannot influence what gets written.
func Encapsulate(rand io.Reader, publicKey curve.Point, label []byte) (*Ciphertext, []byte, error) {
	if publicKey == nil || publicKey.Curve().Name() != group.Name() {
		return nil, nil, ErrGroup
	}
	r, err := randScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	s, err := randScalar(rand)
	if err != nil {
		return nil, nil, err
	}

	R := r.ActOnBase()
	rBar := r.Act(generatorH)
	shared := r.Act(publicKey) // r·Y = r·x·G

	// Chaum-Pedersen over the pair (G, H): prove one r opens both R and RBar.
	W := s.ActOnBase()
	wBar := s.Act(generatorH)
	e := challenge(domainWellFormed, label, enc(R), enc(rBar), enc(W), enc(wBar))
	f := cloneScalar(r).Mul(e).Add(s) // f = s + r·e

	ct := &Ciphertext{R: R, RBar: rBar, E: e, F: f, Label: cloneBytes(label)}
	key, err := deriveKey(R, shared, label)
	if err != nil {
		return nil, nil, err
	}
	return ct, key, nil
}

// Verify checks that a ciphertext was produced by someone who knew r. Every
// party runs it before releasing a partial decapsulation, which is what keeps
// the decapsulation endpoint from being a Diffie-Hellman oracle.
func (c *Ciphertext) Verify() error {
	if c == nil || c.R == nil || c.RBar == nil || c.E == nil || c.F == nil {
		return ErrMalformedCiphertext
	}
	if c.R.Curve().Name() != group.Name() || c.RBar.Curve().Name() != group.Name() {
		return ErrGroup
	}
	// W = f·G − e·R and WBar = f·H − e·RBar reproduce the prover's commitments
	// exactly when log_G R = log_H RBar.
	W := c.F.ActOnBase().Sub(cloneScalar(c.E).Act(c.R))
	wBar := c.F.Act(generatorH).Sub(cloneScalar(c.E).Act(c.RBar))
	if !challenge(domainWellFormed, c.Label, enc(c.R), enc(c.RBar), enc(W), enc(wBar)).Equal(c.E) {
		return ErrMalformedCiphertext
	}
	return nil
}

// PartialDecapsulate applies one share to a ciphertext. It verifies the
// ciphertext first and refuses an unproven one, so a party never becomes an
// oracle for ciphertexts it did not see created.
//
// The share is read, never written: the returned Partial reveals x_i·R and a
// zero-knowledge proof, and nothing else about x_i.
func PartialDecapsulate(rand io.Reader, sh Share, ct *Ciphertext) (*Partial, error) {
	if sh.Secret == nil || sh.Secret.Curve().Name() != group.Name() {
		return nil, ErrGroup
	}
	if err := ct.Verify(); err != nil {
		return nil, err
	}
	k, err := randScalar(rand)
	if err != nil {
		return nil, err
	}

	x := cloneScalar(sh.Secret) // never mutate the caller's share
	D := x.Act(ct.R)
	V := x.ActOnBase()

	// Chaum-Pedersen over the pair (G, R): prove one x_i opens both V_i and D.
	A := k.ActOnBase()
	B := k.Act(ct.R)
	e := challenge(domainPartial, ct.Label, []byte(sh.ID), enc(ct.R), enc(V), enc(D), enc(A), enc(B))
	f := cloneScalar(x).Mul(e).Add(k) // f = k + x_i·e

	return &Partial{ID: sh.ID, D: D, E: e, F: f}, nil
}

// Verify checks a partial against the party's published verification share.
func (p *Partial) Verify(ct *Ciphertext, verificationShare curve.Point) bool {
	if p == nil || p.D == nil || p.E == nil || p.F == nil || verificationShare == nil {
		return false
	}
	if p.D.Curve().Name() != group.Name() {
		return false
	}
	A := p.F.ActOnBase().Sub(cloneScalar(p.E).Act(verificationShare))
	B := p.F.Act(ct.R).Sub(cloneScalar(p.E).Act(p.D))
	return challenge(domainPartial, ct.Label, []byte(p.ID), enc(ct.R), enc(verificationShare), enc(p.D), enc(A), enc(B)).Equal(p.E)
}

// Combine interpolates verified partials into the encapsulated key.
//
// Every partial supplied is checked, and one bad proof fails the whole call
// with the culprit named. That is deliberate: a caller that silently dropped
// bad partials would keep working while a party quietly malfunctioned, and the
// failure would surface later as data nobody can read.
func Combine(g Group, ct *Ciphertext, partials []*Partial) ([]byte, error) {
	if err := g.validate(); err != nil {
		return nil, err
	}
	if err := ct.Verify(); err != nil {
		return nil, err
	}
	if len(partials) < g.Threshold {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrBelowThreshold, len(partials), g.Threshold)
	}

	seen := make(map[party.ID]struct{}, len(partials))
	ids := make([]party.ID, 0, len(partials))
	for _, p := range partials {
		if p == nil {
			return nil, ErrBadPartial{}
		}
		V, ok := g.VerificationShares[p.ID]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnknownParty, p.ID)
		}
		if _, dup := seen[p.ID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateParty, p.ID)
		}
		if !p.Verify(ct, V) {
			return nil, ErrBadPartial{Culprit: p.ID}
		}
		seen[p.ID] = struct{}{}
		ids = append(ids, p.ID)
	}

	// S = Σ λ_i·D_i over exactly the parties that contributed. The Lagrange
	// coefficients depend on WHICH parties those are, which is why the set is
	// fixed before any of them is applied.
	lambda := polynomial.Lagrange(group, ids)
	S := group.NewPoint()
	for _, p := range partials {
		S = S.Add(lambda[p.ID].Act(p.D))
	}
	return deriveKey(ct.R, S, ct.Label)
}

// FromKeygen adapts a FROST distributed key generation result into this
// package's view of it. The key generation is dealerless and never reconstructs
// the secret, and this package never reconstructs it either, so the secret has
// no point in its life cycle at which it exists.
//
// It is also the one place the two threshold conventions are reconciled: FROST
// counts polynomial DEGREE, so t+1 parties sign; tkem counts PARTIES.
func FromKeygen(cfg *keygen.Config) (Group, Share, error) {
	if cfg == nil || cfg.PublicKey == nil || cfg.PrivateShare == nil || cfg.VerificationShares == nil {
		return Group{}, Share{}, ErrGroup
	}
	if cfg.PublicKey.Curve().Name() != group.Name() {
		return Group{}, Share{}, ErrGroup
	}
	shares := make(map[party.ID]curve.Point, len(cfg.VerificationShares.Points))
	for id, v := range cfg.VerificationShares.Points {
		shares[id] = v
	}
	g := Group{Threshold: cfg.Threshold + 1, PublicKey: cfg.PublicKey, VerificationShares: shares}
	if err := g.validate(); err != nil {
		return Group{}, Share{}, err
	}
	return g, Share{ID: cfg.ID, Secret: cfg.PrivateShare}, nil
}

func (g Group) validate() error {
	if g.PublicKey == nil || g.PublicKey.Curve().Name() != group.Name() {
		return ErrGroup
	}
	if g.Threshold < 1 || g.Threshold > len(g.VerificationShares) {
		return fmt.Errorf("%w: threshold %d, parties %d", ErrShape, g.Threshold, len(g.VerificationShares))
	}
	return nil
}

// deriveKey turns the recovered Diffie-Hellman point into the encapsulated key.
// R goes into the input keying material alongside S so that two ciphertexts
// sharing an S — which a caller reusing r would produce — still cannot share a
// key unless they also share an R.
func deriveKey(R, S curve.Point, label []byte) ([]byte, error) {
	ikm := append(enc(R), enc(S)...)
	info := append([]byte(domainKey), lengthPrefixed(label)...)
	key, err := hkdf.Key(sha256.New, ikm, nil, string(info), KeyLen)
	if err != nil {
		return nil, fmt.Errorf("tkem: key derivation: %w", err)
	}
	return key, nil
}

// challenge is the Fiat-Shamir hash. Every field is length-prefixed, so no two
// distinct transcripts can produce the same byte string, and the digest is 64
// bytes mapped uniformly into the scalar field rather than reduced from 32.
func challenge(domain string, items ...[]byte) curve.Scalar {
	h := sha512.New()
	h.Write(lengthPrefixed([]byte(domain)))
	for _, it := range items {
		h.Write(lengthPrefixed(it))
	}
	s := group.NewScalar().(*curve.Ristretto255Scalar)
	return s.FromUniformBytes(h.Sum(nil))
}

func lengthPrefixed(b []byte) []byte {
	out := make([]byte, 8, 8+len(b))
	binary.BigEndian.PutUint64(out, uint64(len(b)))
	return append(out, b...)
}

func enc(p curve.Point) []byte {
	b, err := p.MarshalBinary()
	if err != nil {
		// A ristretto255 point always encodes; a failure here means the value
		// is not one, which is a programming error rather than a runtime case.
		panic(fmt.Sprintf("tkem: point encoding failed: %v", err))
	}
	return b
}

// cloneScalar exists because scalar arithmetic in pkg/math/curve mutates the
// receiver while point arithmetic does not. Copying before every chain keeps
// that asymmetry from silently corrupting a caller's share.
func cloneScalar(s curve.Scalar) curve.Scalar { return group.NewScalar().Set(s) }

func clonePoint(p curve.Point) curve.Point {
	b := enc(p)
	out := group.NewPoint()
	if err := out.UnmarshalBinary(b); err != nil {
		panic(fmt.Sprintf("tkem: point round-trip failed: %v", err))
	}
	return out
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func randScalar(rand io.Reader) (curve.Scalar, error) {
	var buf [64]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return nil, fmt.Errorf("tkem: randomness: %w", err)
	}
	s := group.NewScalar().(*curve.Ristretto255Scalar)
	return s.FromUniformBytes(buf[:]), nil
}
