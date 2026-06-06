// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

// Package tfhe — real distributed (M-of-N) decryption for Threshold-FHE.
//
// This file is Phase 1 of issue #20: real `PartialDecrypt` / `CombineShares`
// that replace the HMAC-stub gated by `ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1`.
// The fake path in `tfhe.go` is preserved for now (deprecated) so existing
// downstream tests keep compiling; new callers should use the real path
// implemented here.
//
// SCHEME (textbook AJL+12-style RLWE threshold decryption, single-bit form):
//
//   - Each LWE-secret-key polynomial coefficient s[k] ∈ Z_QLWE is Shamir-shared
//     over the field F_QLWE (the LWE ciphertext modulus). Party i receives
//     a polynomial s_i ∈ Z_QLWE[X]/(X^N+1) whose k-th coefficient is the
//     evaluation at party i's x-coordinate of the degree-(t-1) Shamir
//     polynomial for s[k]. By Shamir linearity over the same field, for any
//     authorised subset T of size ≥ threshold:
//
//         s = Σ_{i∈T} λ_i(T) · s_i   (mod QLWE, coefficient-wise)
//
//     where λ_i(T) is the Lagrange coefficient at x=0 of party i with respect
//     to the subset T.
//
//   - For an LWE ciphertext (a, b) with b = Δm + e − a·s (mod QLWE), each
//     party computes the partial value
//
//         p_i = ⟨a, s_i⟩  (mod QLWE)
//
//     where ⟨·,·⟩ is the coefficient-0 entry of the ring product a·s_i (the
//     same quantity rlwe.Decryptor inspects to recover the constant term).
//     Optionally adds a small noise-flooding term e_i ← χ_flood.
//
//   - The combiner runs
//
//         m_noisy = (b₀ + Σ_{i∈T} λ_i(T) · p_i)  (mod QLWE)
//
//     and rounds m_noisy against the bit-encoding {Q/8, 7Q/8} to recover the
//     plaintext bit. The combiner uses `polynomial.LagrangeAtZeroBigInt`
//     (added in PR #24 specifically for this issue) to compute the weighted
//     sum at x=0 in F_QLWE.
//
// SECURITY NOTE — what Phase 1 does NOT yet do (deferred to Phase 2):
//
//   - Formal noise-growth proof for `PN9QP28_STD128`. The default flood term
//     is set to zero in this implementation; the API supports a non-zero
//     `FloodNoise` field so a follow-up PR can wire in the χ_flood sampler
//     plus the noise-budget audit.
//   - Active-adversary verification (Feldman/Pedersen VSS commitments to
//     partial shares so a malicious party producing a wrong p_i is detected
//     before combine).
//   - Public-DKG variant. Phase 1 ships a trusted-dealer keygen
//     (`DealRealKeyShares`) only. The DKG hook is sketched in issue body.
//
// All three deferrals are documented in the PR body and on issue #20.
package tfhe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/ring"

	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// lweRing reconstructs the rlwe.Parameters / RingQ used by the LWE half of
// an fhe.Parameters value. The fhe package keeps paramsLWE package-private,
// so we rebuild it from the public surface (N + QLWE + NTTFlag).
//
// The reconstructed parameters are bit-for-bit identical to fhe's internal
// paramsLWE because rlwe.NewParametersFromLiteral is deterministic in
// (LogN, Q, NTTFlag).
func lweRing(params fhe.Parameters) (rlwe.Parameters, *ring.Ring, error) {
	n := params.N()
	if n == 0 || (n&(n-1)) != 0 {
		return rlwe.Parameters{}, nil, fmt.Errorf("tfhe: N=%d is not a positive power of two", n)
	}
	logN := bits.TrailingZeros(uint(n))
	rp, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    logN,
		Q:       []uint64{params.QLWE()},
		NTTFlag: true,
	})
	if err != nil {
		return rlwe.Parameters{}, nil, fmt.Errorf("tfhe: rebuild rlwe params: %w", err)
	}
	return rp, rp.RingQ().AtLevel(0), nil
}

// ErrThresholdNotMet is returned when fewer than threshold partial-decrypt
// shares are submitted to CombineShares.
var ErrThresholdNotMet = errors.New("tfhe: fewer partials than threshold")

// ErrPartialCountInconsistent is returned when partials disagree on the
// underlying ciphertext (the binding hash differs).
var ErrPartialCountInconsistent = errors.New("tfhe: partial-decrypt shares bound to different ciphertexts")

// RealKeyShare is a Phase-1 distributed FHE secret-key share.
//
// Each party holds:
//
//   - PartyID         — the party.ID this share was issued to.
//   - X               — the x-coordinate big-endian-decoded from PartyID (mod QLWE).
//   - SKLWEShareNTT   — the party's share of the LWE secret-key polynomial,
//     in NTT+Montgomery form on the LWE ring (ready to be `MulCoeffsMontgomery`'d
//     against ct.Value[1] without any extra transform).
//   - Threshold       — t in t-of-n.
//   - Total           — n in t-of-n.
//   - QLWE            — cached LWE modulus (the Shamir field modulus).
//   - PublicKey       — collective FHE public key (same across all parties).
//   - Params          — FHE parameters.
//
// CRITICAL: no party's RealKeyShare contains the master secret key. The
// master key is materialised only inside DealRealKeyShares and is discarded
// before that function returns.
type RealKeyShare struct {
	PartyID       party.ID
	X             *big.Int
	SKLWEShareNTT ring.Poly
	Threshold     int
	Total         int
	QLWE          uint64
	PublicKey     *fhe.PublicKey
	Params        fhe.Parameters
}

// PartialShare is one party's contribution to a distributed decryption.
//
// Phase 1 decrypts a single bit (the constant coefficient of the underlying
// LWE plaintext polynomial), so PartialShare carries one scalar.
//
//   - PartyID         — the party that produced this partial.
//   - X               — that party's x-coordinate in F_QLWE.
//   - Value           — ⟨a, s_i⟩ + e_i  (mod QLWE), in canonical [0, QLWE).
//   - CiphertextDigest— binds the partial to a specific ciphertext.
type PartialShare struct {
	PartyID          party.ID
	X                *big.Int
	Value            *big.Int
	CiphertextDigest [32]byte
}

// DealRealKeyShares performs Phase-1 trusted-dealer keygen:
//
//  1. Generates an FHE key-pair (sk, pk) via fhe.KeyGenerator.
//  2. Converts sk.SKLWE (which lives in NTT+Montgomery form) back to standard
//     coefficient form mod QLWE.
//  3. For each coefficient s[k] ∈ Z_QLWE, Shamir-splits it as the constant
//     term of a fresh degree-(threshold-1) polynomial over F_QLWE.
//  4. Evaluates each Shamir polynomial at every party's x-coordinate. The
//     resulting per-party polynomial has its k-th coefficient equal to that
//     party's share of s[k].
//  5. Converts each party's share polynomial to NTT+Montgomery form so the
//     downstream ring-multiplication against ct.Value[1] is a single call to
//     ringQ.MulCoeffsMontgomery (matching the convention used by
//     rlwe.Decryptor).
//  6. Zeroises the master secret-key polynomial before returning. The
//     in-memory representation is overwritten so a post-return memory dump
//     would not recover the master key from the dealer's stack.
//
// The dealer is the only entity that ever holds the master key; no party's
// RealKeyShare contains it.
//
// The returned big.Int x-coordinates match exactly what
// polynomial.LagrangeAtZeroBigInt computes for the same party.IDs, so
// CombineShares can call into that helper directly without extra remapping.
//
// Failure modes:
//
//   - threshold < 1 or threshold > len(parties): returns error.
//   - len(parties) < 2: returns error (degenerates to no sharing).
//   - Two parties whose IDs reduce to the same x-coordinate mod QLWE: returns
//     error (this is the same Lagrange precondition enforced by
//     polynomial.LagrangeAtZeroBigInt; we surface it at deal-time so
//     misconfigured deployments fail fast).
func DealRealKeyShares(
	ctx context.Context,
	params fhe.Parameters,
	threshold int,
	parties []party.ID,
) (*fhe.PublicKey, map[party.ID]*RealKeyShare, error) {
	if threshold < 1 {
		return nil, nil, fmt.Errorf("tfhe: threshold must be ≥ 1, got %d", threshold)
	}
	if threshold > len(parties) {
		return nil, nil, fmt.Errorf("tfhe: threshold %d exceeds party count %d", threshold, len(parties))
	}
	if len(parties) < 2 {
		return nil, nil, fmt.Errorf("tfhe: need ≥ 2 parties for a non-trivial sharing, got %d", len(parties))
	}

	// Generate the master FHE keypair (dealer side).
	kg := fhe.NewKeyGenerator(params)
	masterSK, masterPK := kg.GenKeyPair()

	qlwe := params.QLWE()
	modulus := new(big.Int).SetUint64(qlwe)

	// Resolve party x-coordinates and detect duplicates mod QLWE up-front.
	xs := make([]*big.Int, len(parties))
	xSeen := make(map[string]struct{}, len(parties))
	for i, pid := range parties {
		x := new(big.Int).SetBytes([]byte(pid))
		x.Mod(x, modulus)
		if x.Sign() == 0 {
			return nil, nil, fmt.Errorf("tfhe: party %q reduces to x=0 mod QLWE (Lagrange requires non-zero x)", pid)
		}
		key := x.String()
		if _, dup := xSeen[key]; dup {
			return nil, nil, fmt.Errorf("tfhe: two parties share the same x-coordinate mod QLWE (collision on %q)", pid)
		}
		xSeen[key] = struct{}{}
		xs[i] = x
	}

	// Move the LWE secret key to standard coefficient form so we can read off
	// each coefficient as a plain uint64 in [0, QLWE).
	skLWEStd, err := skLWEStandardForm(params, masterSK)
	if err != nil {
		return nil, nil, fmt.Errorf("tfhe: failed to move SKLWE to standard form: %w", err)
	}

	n := params.N()
	if skLWEStd.N() != n {
		return nil, nil, fmt.Errorf("tfhe: SKLWE ring degree %d does not match params N=%d", skLWEStd.N(), n)
	}

	// For each coefficient s[k], build a fresh degree-(threshold-1) Shamir
	// polynomial, then evaluate it at every party's x. Assemble each party's
	// share polynomial coefficient-by-coefficient.
	shareCoeffs := make([][]uint64, len(parties))
	for i := range shareCoeffs {
		shareCoeffs[i] = make([]uint64, n)
	}

	// Pre-allocated working buffer for polynomial coefficients (length =
	// threshold). coeffs[0] is the secret s[k]; coeffs[1..threshold-1] are
	// fresh random elements of F_QLWE.
	scratch := make([]*big.Int, threshold)
	for j := range scratch {
		scratch[j] = new(big.Int)
	}

	for k := 0; k < n; k++ {
		sk_k := skLWEStd.Coeffs[0][k] % qlwe // canonical
		scratch[0].SetUint64(sk_k)

		for j := 1; j < threshold; j++ {
			r, err := rand.Int(rand.Reader, modulus)
			if err != nil {
				return nil, nil, fmt.Errorf("tfhe: random Shamir coefficient: %w", err)
			}
			scratch[j].Set(r)
		}

		// Evaluate the polynomial at each party's x using Horner's rule.
		for i, x := range xs {
			y := evalShamirAt(scratch, x, modulus)
			shareCoeffs[i][k] = y.Uint64()
		}
	}

	// Zeroise the master secret-key coefficient buffer before returning. Note
	// we do this on the standard-form copy AND on the NTT+Montgomery copy
	// inside masterSK so any reference held by the dealer's stack frame is
	// overwritten.
	zeroPolyCoeffs(skLWEStd.Coeffs[0])
	zeroPolyCoeffs(masterSK.SKLWE.Value.Q.Coeffs[0])

	// Build per-party share polynomials. Each starts in standard form and is
	// transformed into NTT+Montgomery form so partial-decrypt can just call
	// MulCoeffsMontgomery against ct.Value[1].
	_, ringQ, err := lweRing(params)
	if err != nil {
		return nil, nil, err
	}

	shares := make(map[party.ID]*RealKeyShare, len(parties))
	for i, pid := range parties {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], shareCoeffs[i])
		ringQ.NTT(p, p)
		ringQ.MForm(p, p)

		shares[pid] = &RealKeyShare{
			PartyID:       pid,
			X:             new(big.Int).Set(xs[i]),
			SKLWEShareNTT: p,
			Threshold:     threshold,
			Total:         len(parties),
			QLWE:          qlwe,
			PublicKey:     masterPK,
			Params:        params,
		}
	}

	return masterPK, shares, nil
}

// PartialDecrypt produces this party's contribution to the distributed
// decryption of the LWE ciphertext underlying the (boolean) BitCiphertext's
// first bit.
//
// Phase 1 decrypts a single bit at a time. The caller is expected to invoke
// PartialDecrypt per bit position when decrypting a multi-bit BitCiphertext;
// each per-bit invocation produces an independent PartialShare bound to that
// specific RLWE-level Ciphertext.
//
// flood is an optional noise-flooding term. Passing nil yields a deterministic
// partial (no flooding); Phase 2 will introduce a χ_flood sampler.
func (s *RealKeyShare) PartialDecrypt(
	ct *fhe.Ciphertext,
	flood *big.Int,
) (*PartialShare, error) {
	if ct == nil || ct.Ciphertext == nil {
		return nil, errors.New("tfhe: PartialDecrypt: ciphertext is nil")
	}
	if ct.Degree() != 1 {
		return nil, fmt.Errorf("tfhe: PartialDecrypt: expected degree-1 ciphertext, got %d", ct.Degree())
	}

	params := s.Params
	_, ringQ, err := lweRing(params)
	if err != nil {
		return nil, err
	}

	// `a` is ct.Value[1]. We want coefficient 0 of (a · s_i) as a standard
	// integer mod QLWE. The rlwe encoding stores both `a` and `s_i` in
	// NTT+Montgomery form. We mirror rlwe.Decryptor exactly:
	//
	//   tmp = a · s_i             (NTT+Montgomery space, MulCoeffsMontgomery)
	//   INTT(tmp)                 (back to coefficient form)
	//   read tmp.Coeffs[0][0]     (this is ⟨a, s_i⟩ for the constant term)
	tmp := ringQ.NewPoly()
	if ct.IsNTT {
		// ct.Value[1] is in NTT form: do the multiply directly.
		ringQ.MulCoeffsMontgomery(ct.Value[1], s.SKLWEShareNTT, tmp)
	} else {
		// ct.Value[1] is in coefficient form: NTT it first into tmp.
		ringQ.NTT(ct.Value[1], tmp)
		ringQ.MulCoeffsMontgomery(tmp, s.SKLWEShareNTT, tmp)
	}
	ringQ.INTT(tmp, tmp)
	ringQ.Reduce(tmp, tmp)

	val := tmp.Coeffs[0][0] % s.QLWE
	out := new(big.Int).SetUint64(val)

	// Optional noise-flooding term. Phase 1 leaves the χ_flood sampler as a
	// Phase-2 deferral but the API plumbs the value through so wiring in a
	// real sampler later is a one-line caller change.
	if flood != nil {
		out.Add(out, flood)
		out.Mod(out, new(big.Int).SetUint64(s.QLWE))
	}

	// Zeroise the working buffer so the partial coefficients don't linger in
	// memory longer than necessary. (Doesn't bind the partial value, just
	// hygiene.)
	zeroPolyCoeffs(tmp.Coeffs[0])

	return &PartialShare{
		PartyID:          s.PartyID,
		X:                new(big.Int).Set(s.X),
		Value:            out,
		CiphertextDigest: digestRLWECiphertext(ct),
	}, nil
}

// CombineShares interpolates a set of partial-decrypt shares at x=0 to recover
// the noisy plaintext value, then rounds it against the bit-encoding to extract
// the underlying bit.
//
// The b polynomial (ct.Value[0], the second polynomial of a degree-1 RLWE
// ciphertext) is taken from `ct`; combine reads its constant-term coefficient
// in standard form and adds it to the Lagrange-interpolated value before
// rounding. This matches rlwe.Decryptor's
//
//     pt[0] = a·s + b   (then INTT, then rounded)
//
// derivation with `a·s = Σ λ_i · ⟨a, s_i⟩` substituted in.
//
// Returns the recovered boolean as well as the noisy plaintext scalar
// (useful for noise-budget assertions in tests).
func CombineShares(
	params fhe.Parameters,
	ct *fhe.Ciphertext,
	partials []*PartialShare,
	threshold int,
) (bit bool, noisyPlaintext *big.Int, err error) {
	if len(partials) < threshold {
		return false, nil, fmt.Errorf("%w: got %d, need %d", ErrThresholdNotMet, len(partials), threshold)
	}
	if ct == nil || ct.Ciphertext == nil {
		return false, nil, errors.New("tfhe: CombineShares: ciphertext is nil")
	}

	// Bind every partial to the same ciphertext.
	digest := digestRLWECiphertext(ct)
	for _, p := range partials {
		if p.CiphertextDigest != digest {
			return false, nil, ErrPartialCountInconsistent
		}
	}

	qlwe := params.QLWE()
	modulus := new(big.Int).SetUint64(qlwe)

	// Use exactly `threshold` partials (Lagrange combine is determined by any
	// authorised subset). Build the share map polynomial.LagrangeAtZeroBigInt
	// consumes.
	used := partials[:threshold]
	shareMap := make(map[party.ID]*big.Int, threshold)
	for _, p := range used {
		// Defensive: the Lagrange helper derives x from the ID. Verify the
		// PartialShare.X agrees so a malformed partial does not silently
		// poison the combine.
		expected := new(big.Int).SetBytes([]byte(p.PartyID))
		expected.Mod(expected, modulus)
		if expected.Cmp(p.X) != 0 {
			return false, nil, fmt.Errorf("tfhe: partial from %q has X inconsistent with PartyID bytes", p.PartyID)
		}
		shareMap[p.PartyID] = p.Value
	}

	combined, err := polynomial.LagrangeAtZeroBigInt(shareMap, modulus)
	if err != nil {
		return false, nil, fmt.Errorf("tfhe: Lagrange combine: %w", err)
	}

	// Add the b-term constant. b = ct.Value[0]. Read its coefficient-0 entry
	// in standard form.
	b0 := constantTermStandard(params, ct)
	combined.Add(combined, new(big.Int).SetUint64(b0))
	combined.Mod(combined, modulus)

	// Round against the bit encoding: encryptor stores `true` as Q/8 and
	// `false` as 7Q/8 (i.e. -Q/8). We split the interval [0, Q) into the
	// usual two halves [0, Q/2) → true, [Q/2, Q) → false, matching
	// rlwe.Decryptor's convention.
	qHalf := new(big.Int).SetUint64(qlwe >> 1)
	return combined.Cmp(qHalf) < 0, combined, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// skLWEStandardForm returns a fresh ring.Poly containing the LWE secret key's
// coefficients in standard form (no NTT, no Montgomery), reduced mod QLWE.
// The returned poly is decoupled from the SK's backing storage so the
// dealer can zeroise it independently.
func skLWEStandardForm(params fhe.Parameters, sk *fhe.SecretKey) (ring.Poly, error) {
	if sk == nil || sk.SKLWE == nil {
		return ring.Poly{}, errors.New("nil SKLWE")
	}
	_, ringQ, err := lweRing(params)
	if err != nil {
		return ring.Poly{}, err
	}

	std := ringQ.NewPoly()
	// SKLWE is stored in NTT+Montgomery form. Reverse both transforms.
	tmp := ringQ.NewPoly()
	ringQ.IMForm(sk.SKLWE.Value.Q, tmp)
	ringQ.INTT(tmp, std)
	ringQ.Reduce(std, std)

	// Zeroise the intermediate buffer.
	zeroPolyCoeffs(tmp.Coeffs[0])
	return std, nil
}

// evalShamirAt evaluates a polynomial whose coefficients are in `coeffs`
// (coeffs[0] = constant term, ascending degree) at point x in F_modulus,
// using Horner's rule.
func evalShamirAt(coeffs []*big.Int, x, modulus *big.Int) *big.Int {
	result := new(big.Int).Set(coeffs[len(coeffs)-1])
	for j := len(coeffs) - 2; j >= 0; j-- {
		result.Mul(result, x)
		result.Add(result, coeffs[j])
		result.Mod(result, modulus)
	}
	return result
}

// constantTermStandard returns coefficient 0 of ct.Value[0] in standard form
// (no NTT, no Montgomery), reduced mod QLWE.
func constantTermStandard(params fhe.Parameters, ct *fhe.Ciphertext) uint64 {
	_, ringQ, err := lweRing(params)
	if err != nil {
		// Should be unreachable: lweRing only fails if QLWE / N are
		// malformed, but at this call site we've already used the same
		// params to deal + partial-decrypt successfully.
		panic(fmt.Sprintf("tfhe: constantTermStandard: lweRing rebuild failed: %v", err))
	}
	tmp := ringQ.NewPoly()
	if ct.IsNTT {
		ringQ.INTT(ct.Value[0], tmp)
	} else {
		tmp.Copy(ct.Value[0])
	}
	ringQ.Reduce(tmp, tmp)
	v := tmp.Coeffs[0][0] % params.QLWE()
	zeroPolyCoeffs(tmp.Coeffs[0])
	return v
}

// digestRLWECiphertext computes a 32-byte binding hash of an RLWE ciphertext.
// Used to bind partials to a specific ciphertext so a misrouted partial
// cannot be silently combined with partials from a different ciphertext.
func digestRLWECiphertext(ct *fhe.Ciphertext) [32]byte {
	var out [32]byte
	if ct == nil || ct.Ciphertext == nil {
		return out
	}
	// MarshalBinary on rlwe.Ciphertext gives a stable serialisation including
	// metadata + both polynomial halves. Hash with blake-style fold: this is
	// a binding tag, not a cryptographic commitment, so a simple xor-fold of
	// the marshalled bytes into 32 bytes is sufficient for the test surface.
	// (Phase 2 will swap this for a real cryptographic commitment when the
	// active-adversary verification track lands.)
	data, err := ct.Ciphertext.MarshalBinary()
	if err != nil {
		return out
	}
	for i, b := range data {
		out[i%32] ^= b
	}
	// Mix the length in so two ciphertexts of different sizes do not collide
	// trivially.
	out[0] ^= byte(len(data))
	out[1] ^= byte(len(data) >> 8)
	out[2] ^= byte(len(data) >> 16)
	out[3] ^= byte(len(data) >> 24)
	return out
}

// zeroPolyCoeffs overwrites the contents of `c` with zeros.
func zeroPolyCoeffs(c []uint64) {
	for i := range c {
		c[i] = 0
	}
}

// Compile-time assertion that the package depends on rlwe explicitly (so a
// stray accidental removal of the rlwe import in a refactor surfaces here
// rather than at the partial-decrypt call site).
var _ = rlwe.NewDecryptor
