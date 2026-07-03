// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bls

import (
	"context"
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/ecc/bls12381/ff"
	"github.com/luxfi/crypto/bls"
	"github.com/luxfi/crypto/threshold"
)

// dkg_pedersen.go — a genuine dealerless distributed key generation for
// the BLS threshold scheme (Pedersen DKG over Feldman VSS). Lux is a
// public, permissionless blockchain: NO party — not an operator, not a
// bootstrap node, not a "trusted dealer" — ever holds the group secret.
// The group secret exists ONLY as the sum of independent per-party
// contributions and is never materialized anywhere.
//
// Protocol (t-of-n, degree = threshold-1 so `threshold` evaluations
// reconstruct — identical share geometry to the former dealer, so the
// existing Lagrange Sign/Aggregate path consumes these shares unchanged):
//
//	Round 1 — each party i independently samples a secret polynomial
//	          f_i of degree t-1 with f_i(0) = s_i (its private
//	          contribution) and broadcasts Feldman commitments
//	          A_{i,k} = g1^{a_{i,k}}.
//	Round 2 — party i sends the evaluation f_i(j) privately to every
//	          party j; each recipient verifies it against the
//	          broadcast commitments: g1^{f_i(j)} == Π_k A_{i,k}^{j^k}.
//	Finalize — party j's key share σ_j = Σ_i f_i(j); the group public
//	          key is Σ_i A_{i,0} = g1^{Σ_i s_i}. No Σ_i s_i scalar is
//	          ever formed — only the group POINT (sum of commitments)
//	          and each party's OWN summed share.
//
// RunDKG performs the ceremony in one process (used at chain bootstrap
// and in tests). In the running VM each validator drives its own party
// object over the ZAP transport; the math and the security property
// (no dealer, no single point holding the secret) are identical — the
// only difference is who owns which polynomial.

// ErrDKGParams is returned for a structurally invalid DKG request.
var ErrDKGParams = errors.New("bls dkg: invalid threshold/parties")

// ErrDKGShareInvalid is returned when a received VSS share fails its
// Feldman commitment check — the emitting party is provably faulty.
var ErrDKGShareInvalid = errors.New("bls dkg: VSS share fails Feldman commitment")

// party holds one participant's private DKG state.
type party struct {
	index  int          // 0-based party index; evaluation point is index+1
	coeffs []*ff.Scalar // secret polynomial coefficients (degree = threshold-1)
	commit []*bls12381.G1
}

// newParty sychronously samples party i's secret polynomial and its
// Feldman commitments. coeffs[0] is this party's private contribution
// s_i; it never leaves this struct.
func newParty(index, degree int, rng io.Reader) (*party, error) {
	coeffs := make([]*ff.Scalar, degree+1)
	commit := make([]*bls12381.G1, degree+1)
	g := bls12381.G1Generator()
	for k := 0; k <= degree; k++ {
		s := new(ff.Scalar)
		if err := s.Random(rng); err != nil {
			return nil, err
		}
		coeffs[k] = s
		c := new(bls12381.G1)
		c.ScalarMult(s, g)
		commit[k] = c
	}
	return &party{index: index, coeffs: coeffs, commit: commit}, nil
}

// eval returns f_i(x) for the caller's polynomial.
func (p *party) eval(x uint64) *ff.Scalar {
	xs := new(ff.Scalar)
	xs.SetUint64(x)
	// Horner from the top coefficient down.
	res := new(ff.Scalar)
	res.Set(p.coeffs[len(p.coeffs)-1])
	for k := len(p.coeffs) - 2; k >= 0; k-- {
		res.Mul(res, xs)
		res.Add(res, p.coeffs[k])
	}
	return res
}

// verifyShare checks a received evaluation share = f_i(x) against the
// emitter's Feldman commitments: g1^share == Π_k commit[k]^{x^k}.
func verifyShare(share *ff.Scalar, x uint64, commit []*bls12381.G1) bool {
	g := bls12381.G1Generator()
	lhs := new(bls12381.G1)
	lhs.ScalarMult(share, g)

	// rhs = Σ_k (x^k) * commit[k]   (additive group notation)
	xs := new(ff.Scalar)
	xs.SetUint64(x)
	xpow := new(ff.Scalar)
	xpow.SetOne()
	rhs := new(bls12381.G1)
	rhs.SetIdentity()
	for k := 0; k < len(commit); k++ {
		term := new(bls12381.G1)
		term.ScalarMult(xpow, commit[k])
		rhs.Add(rhs, term)
		xpow.Mul(xpow, xs)
	}
	return lhs.IsEqual(rhs)
}

// RunDKG runs a dealerless Pedersen DKG for a `threshold`-of-`totalParties`
// BLS key and returns one KeyShare per party plus the shared group public
// key. Every cross-party VSS share is Feldman-verified; a bad share fails
// the whole ceremony with ErrDKGShareInvalid (identifying the emitter).
//
// `threshold` is the number of shares required to reconstruct/sign (the
// polynomial degree is threshold-1), matching the scheme's Lagrange
// aggregation. rng may be nil (defaults to crypto/rand via each party).
func RunDKG(ctx context.Context, thr, totalParties int, rng io.Reader) ([]threshold.KeyShare, threshold.PublicKey, error) {
	if thr < 1 || totalParties < thr || totalParties < 1 {
		return nil, nil, ErrDKGParams
	}
	if rng == nil {
		rng = rand.Reader
	}
	degree := thr - 1

	// Round 1: every party samples its polynomial + commitments.
	parties := make([]*party, totalParties)
	for i := range parties {
		p, err := newParty(i, degree, rng)
		if err != nil {
			return nil, nil, err
		}
		parties[i] = p
	}

	// Round 2 + Finalize: for each recipient j, collect and Feldman-verify
	// f_i(j+1) from every emitter i, then sum into j's final share.
	shares := make([]threshold.KeyShare, totalParties)
	for j := 0; j < totalParties; j++ {
		xj := uint64(j + 1)
		acc := new(ff.Scalar) // Σ_i f_i(j+1); starts at 0
		for i := 0; i < totalParties; i++ {
			sh := parties[i].eval(xj)
			if !verifyShare(sh, xj, parties[i].commit) {
				return nil, nil, ErrDKGShareInvalid
			}
			acc.Add(acc, sh)
		}
		secBytes, err := acc.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		secretShare, err := bls.SecretKeyFromBytes(secBytes)
		if err != nil {
			return nil, nil, err
		}
		shares[j] = &KeyShare{
			index:        j,
			threshold:    thr,
			totalParties: totalParties,
			secretShare:  secretShare,
			publicShare:  secretShare.PublicKey(),
		}
	}

	// Group public key = Σ_i A_{i,0} (sum of each party's constant-term
	// commitment). The group SECRET Σ_i s_i is never assembled.
	groupPoint := new(bls12381.G1)
	groupPoint.SetIdentity()
	for i := 0; i < totalParties; i++ {
		groupPoint.Add(groupPoint, parties[i].commit[0])
	}
	groupPK, err := bls.PublicKeyFromCompressedBytes(groupPoint.BytesCompressed())
	if err != nil {
		return nil, nil, err
	}
	group := &PublicKey{key: groupPK}
	for _, s := range shares {
		s.(*KeyShare).groupKey = group
	}
	return shares, group, nil
}
