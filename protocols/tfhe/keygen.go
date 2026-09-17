// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Dealerless key generation: GJKR/Pedersen DKG over the Lattigo multiparty
// collective public key. Each member samples its own contribution s_j and
// publishes -a·s_j + e_j, so the aggregate encrypts to s = Σ s_j, and Shamir-
// splits s_j coefficientwise; summing the points it receives gives a member a
// degree-(t-1) share of s. No member, and nothing in this package, forms s.
//
// It generates the encryption key and its shares, not the FHEW blind-rotation
// key that homomorphic compute needs.
//
// Gennaro et al., EUROCRYPT 1999; Mouchet et al., PETS 2021.

package tfhe

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/luxfi/fhe"
	"github.com/luxfi/lattice/v7/core/rlwe"
	"github.com/luxfi/lattice/v7/multiparty"
	"github.com/luxfi/lattice/v7/utils/sampling"
)

// Public is a member's broadcast contribution to the collective public key,
// the share -a·s_j + e_j. It carries no secret-key material.
type Public struct {
	From  int
	Share multiparty.PublicKeyGenShare
}

// Point is one Shamir evaluation, at x=To, of From's own contribution,
// addressed to a single recipient. Any t-1 of them reveal nothing about it.
type Point struct {
	From   int
	To     int
	Coeffs []uint64 // f^{(From)}_i(To) mod q, for i in [0, N)
}

// Party is one member's private ceremony state: its own contribution, and
// nothing another member sampled. No method returns the collective secret.
type Party struct {
	index            int // 1-based Shamir x-coordinate / party identity
	threshold, total int
	params           fhe.Parameters
	paramsLWE        rlwe.Parameters
	ckg              multiparty.PublicKeyGenProtocol

	// si is this party's OWN secret contribution s_j. Private; never
	// serialized and never leaves the node. Zeroized by Zeroize().
	si *rlwe.SecretKey
}

// NewParty creates the member at the given 1-based index and samples its own
// contribution. Construct it on that member's own node; it performs no I/O.
func NewParty(index, threshold, total int, params fhe.Parameters) (*Party, error) {
	if index < 1 || index > total {
		return nil, fmt.Errorf("tfhe: party index %d out of range [1,%d]", index, total)
	}
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("tfhe: bad threshold %d for total %d", threshold, total)
	}
	paramsLWE := params.ParamsLWE()
	if uint64(total) >= paramsLWE.Q()[0] {
		return nil, fmt.Errorf("tfhe: total %d exceeds LWE modulus %d", total, paramsLWE.Q()[0])
	}
	// Sampled from the library's secret distribution, so the collective key is
	// well-formed for the scheme.
	si := rlwe.NewKeyGenerator(paramsLWE).GenSecretKeyNew()
	return &Party{
		index:     index,
		threshold: threshold,
		total:     total,
		params:    params,
		paramsLWE: paramsLWE,
		ckg:       multiparty.NewPublicKeyGenProtocol(paramsLWE),
		si:        si,
	}, nil
}

// Index returns this member's 1-based position.
func (p *Party) Index() int { return p.index }

// Reference derives the common reference polynomial from a seed, with a
// protocol handle. The same seed gives the same polynomial on every node.
func Reference(params fhe.Parameters, crsSeed []byte) (multiparty.PublicKeyGenCRP, multiparty.PublicKeyGenProtocol, error) {
	if len(crsSeed) == 0 {
		return multiparty.PublicKeyGenCRP{}, multiparty.PublicKeyGenProtocol{}, fmt.Errorf("tfhe: empty CRS seed")
	}
	crs, err := sampling.NewKeyedPRNG(crsSeed)
	if err != nil {
		return multiparty.PublicKeyGenCRP{}, multiparty.PublicKeyGenProtocol{}, fmt.Errorf("tfhe: keyed prng: %w", err)
	}
	ckg := multiparty.NewPublicKeyGenProtocol(params.ParamsLWE())
	crp := ckg.SampleCRP(crs)
	return crp, ckg, nil
}

// Deal returns this member's broadcast contribution to the collective public
// key and one Shamir point per recipient, itself included.
func (p *Party) Deal(crp multiparty.PublicKeyGenCRP) (Public, []Point, error) {
	if p.si == nil {
		return Public{}, nil, fmt.Errorf("tfhe: party %d already finalized (secret zeroized)", p.index)
	}

	// Contribution toward the collective encryption key.
	share := p.ckg.AllocateShare()
	p.ckg.GenShare(p.si, crp, &share)

	// Coefficientwise Shamir dealing of this member's own contribution.
	stdCoeffs := coeffs(p.paramsLWE, p.si)
	sub, err := deal(stdCoeffs, p.paramsLWE.Q()[0], p.threshold, p.total)
	zero(stdCoeffs)
	if err != nil {
		return Public{}, nil, err
	}

	msgs := make([]Point, p.total)
	for r := 0; r < p.total; r++ {
		msgs[r] = Point{From: p.index, To: r + 1, Coeffs: sub[r]}
	}
	return Public{From: p.index, Share: share}, msgs, nil
}

// Aggregate folds the points addressed to this member, one from every member
// including itself, into its share of the collective secret.
func (p *Party) Aggregate(inbound []Point) (Share, error) {
	q := p.paramsLWE.Q()[0]
	N := p.paramsLWE.RingQ().N()
	coeffs := make([]uint64, N)
	seen := make(map[int]struct{}, len(inbound))
	for _, m := range inbound {
		if m.To != p.index {
			return Share{}, fmt.Errorf("tfhe: sub-share addressed to %d delivered to party %d", m.To, p.index)
		}
		if _, dup := seen[m.From]; dup {
			return Share{}, fmt.Errorf("tfhe: duplicate sub-share from dealer %d", m.From)
		}
		seen[m.From] = struct{}{}
		if len(m.Coeffs) != N {
			return Share{}, fmt.Errorf("tfhe: sub-share length %d != ring N %d", len(m.Coeffs), N)
		}
		add(coeffs, m.Coeffs, q)
	}
	if len(seen) != p.total {
		return Share{}, fmt.Errorf("tfhe: party %d expected %d sub-shares, got %d", p.index, p.total, len(seen))
	}
	return Share{Index: p.index, Coeffs: coeffs, Q: q, Total: p.total}, nil
}

// Zeroize erases this member's contribution. Call it once the share is held.
func (p *Party) Zeroize() {
	if p.si != nil {
		// ring.Poly.Zero is a no-op on an empty Coeffs, so scrub both parts.
		p.si.Value.Q.Zero()
		p.si.Value.P.Zero()
		p.si = nil
	}
}

// Assemble aggregates the members' broadcast shares into the collective LWE
// public key, p = Σ_j (-a·s_j + e_j).
func Assemble(
	ckg multiparty.PublicKeyGenProtocol,
	crp multiparty.PublicKeyGenCRP,
	shares []Public,
	params fhe.Parameters,
) (*fhe.PublicKey, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("tfhe: no public-key shares")
	}
	agg := ckg.AllocateShare()
	// Fold each contribution into the zero share.
	for i := range shares {
		ckg.AggregateShares(agg, shares[i].Share, &agg)
	}
	pkLWE := rlwe.NewPublicKey(params.ParamsLWE())
	ckg.GenPublicKey(agg, crp, pkLWE)
	return &fhe.PublicKey{PKLWE: pkLWE}, nil
}

// Keygen runs the whole ceremony in one process and returns the collective
// public key with one share per member. A distributed deployment drives the
// Party methods on separate nodes instead, so that no node holds another
// node's contribution.
func Keygen(params fhe.Parameters, threshold, total int, crsSeed []byte) (*fhe.PublicKey, []Share, error) {
	crp, ckg, err := Reference(params, crsSeed)
	if err != nil {
		return nil, nil, err
	}

	parties := make([]*Party, total)
	for i := 0; i < total; i++ {
		parties[i], err = NewParty(i+1, threshold, total, params)
		if err != nil {
			return nil, nil, err
		}
	}

	// Round 1: collect the broadcast shares, route each point to its
	// recipient.
	pkShares := make([]Public, total)
	inboxes := make([][]Point, total)
	for i, party := range parties {
		pkMsg, subs, derr := party.Deal(crp)
		if derr != nil {
			return nil, nil, derr
		}
		pkShares[i] = pkMsg
		for _, s := range subs {
			inboxes[s.To-1] = append(inboxes[s.To-1], s)
		}
	}

	// The public key comes from the broadcast shares alone.
	pub, err := Assemble(ckg, crp, pkShares, params)
	if err != nil {
		return nil, nil, err
	}

	// Round 2: each member folds its inbox into a share.
	shares := make([]Share, total)
	for i, party := range parties {
		shares[i], err = party.Aggregate(inboxes[i])
		if err != nil {
			return nil, nil, err
		}
		party.Zeroize()
	}

	return pub, shares, nil
}

// coeffs lifts a secret key from NTT+Montgomery form to standard coefficient
// form in [0, q), as a fresh copy. Shared with split.
func coeffs(paramsLWE rlwe.Parameters, sk *rlwe.SecretKey) []uint64 {
	ringQ := paramsLWE.RingQ()
	skStd := ringQ.NewPoly()
	ringQ.IMForm(sk.Value.Q, skStd)
	ringQ.INTT(skStd, skStd)
	out := append([]uint64(nil), skStd.Coeffs[0]...)
	skStd.Zero()
	return out
}

// deal Shamir-splits a secret polynomial in standard coefficient form over
// Z_q, returning for each recipient r a length-N vector whose i-th entry is
// f_i(r) for a fresh degree-(threshold-1) f_i with f_i(0) = stdCoeffs[i].
func deal(stdCoeffs []uint64, q uint64, threshold, total int) ([][]uint64, error) {
	if threshold < 1 || threshold > total {
		return nil, fmt.Errorf("tfhe: bad threshold %d for total %d", threshold, total)
	}
	qBig := new(big.Int).SetUint64(q)
	N := len(stdCoeffs)
	out := make([][]uint64, total)
	for r := 0; r < total; r++ {
		out[r] = make([]uint64, N)
	}
	for i := 0; i < N; i++ {
		coeffs := make([]*big.Int, threshold)
		coeffs[0] = new(big.Int).SetUint64(stdCoeffs[i] % q)
		for k := 1; k < threshold; k++ {
			rnd, err := rand.Int(rand.Reader, qBig)
			if err != nil {
				return nil, fmt.Errorf("tfhe: random coeff: %w", err)
			}
			coeffs[k] = rnd
		}
		for r := 0; r < total; r++ {
			x := new(big.Int).SetInt64(int64(r + 1))
			out[r][i] = eval(coeffs, x, qBig)
		}
	}
	return out, nil
}

// add computes dst[i] = (dst[i] + src[i]) mod q in place.
func add(dst, src []uint64, q uint64) {
	for i := range dst {
		// Both operands are < q, so a single conditional subtraction suffices
		// without overflow for q < 2^63.
		s := dst[i] + src[i]
		if s >= q {
			s -= q
		}
		dst[i] = s
	}
}

// zero scrubs a uint64 slice holding sensitive coefficients.
func zero(b []uint64) {
	for i := range b {
		b[i] = 0
	}
}
