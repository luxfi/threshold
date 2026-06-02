// Copyright (C) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// corona_oracle — pure-Go re-implementation of the C++ Corona body in
// luxcpp/crypto/corona/cpp/corona.{hpp,cpp}, used as a cross-language KAT
// oracle. Same parameters (Q = 998244353, N = 512, L = K = 4, σ = 1.7,
// τ = 30, B_∞ = Q/4), same StreamPRNG (SHA-256 counter mode), same Gaussian
// CDT, same negacyclic schoolbook multiply, same wire format. Run once to
// emit corona_kat.h consumed by corona_kat_test.cpp.
//
// Why a re-implementation rather than the network-protocol Go reference at
// github.com/luxfi/corona (which wraps Lattigo with a different ring
// Q = 0x1000000004A01 / N = 256)? The C++ body is deliberately scoped as a
// single-process oracle with luxcpp's own NTT prime — see corona.hpp lines
// 31-39. The two Go paths cover different surfaces:
//   - github.com/luxfi/corona covers the 2-round network protocol.
//   - This file covers the C++ single-process algebraic shape.
//
// Both are first-party algebraic primitives, neither wraps the other.
//
// Usage:
//
//	cd lux/threshold/cmd/corona_oracle
//	go run . > ../../../../luxcpp/crypto/corona/test/corona_kat.h
//
// Determinism:
//   - StreamPRNG: SHA-256(seed || counter_LE8) → 32-byte block, counter++.
//   - pmf table: math.Exp matches darwin libm to ULPs sufficient for the
//     uint64 CDT entries to be byte-equal (verified empirically; see comment
//     at gaussianCDT).
//   - float-to-int: we mirror the C++ static_cast<uint64_t>(d) which on x86
//     is FCVTZS / VCVTSS2SI semantics — matched here by uint64(d) in Go.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// ============================================================================
// Algebra parameters — keep in sync with luxcpp/crypto/corona/cpp/corona.hpp
// ============================================================================

const (
	Q           uint64  = 998244353
	N           int     = 512
	L           int     = 4
	K           int     = 4
	TAU         int     = 30
	GAUSS_BOUND int     = 12
	SIGMA       float64 = 1.7
	POLY_BYTES  int     = N * 4
	PK_BYTES    int     = (K*L + K) * POLY_BYTES // 40960
	SIG_BYTES   int     = (1 + L) * POLY_BYTES   // 10240
)

var B_INF uint64 = Q / 4

// ============================================================================
// Stream PRNG — SHA-256(seed || counter_LE8) refilling 32-byte blocks.
// ============================================================================

type streamPRNG struct {
	seed    []byte
	counter uint64
	buf     [32]byte
	bufPos  int
}

func newStreamPRNG(seed []byte) *streamPRNG {
	r := &streamPRNG{seed: append([]byte(nil), seed...), bufPos: 32}
	r.refill()
	return r
}

func (r *streamPRNG) refill() {
	in := make([]byte, 0, len(r.seed)+8)
	in = append(in, r.seed...)
	var ctrLE [8]byte
	binary.LittleEndian.PutUint64(ctrLE[:], r.counter)
	in = append(in, ctrLE[:]...)
	r.buf = sha256.Sum256(in)
	r.counter++
	r.bufPos = 0
}

func (r *streamPRNG) fill(out []byte) {
	for len(out) > 0 {
		if r.bufPos >= 32 {
			r.refill()
		}
		take := 32 - r.bufPos
		if take > len(out) {
			take = len(out)
		}
		copy(out, r.buf[r.bufPos:r.bufPos+take])
		out = out[take:]
		r.bufPos += take
	}
}

func (r *streamPRNG) nextU32() uint32 {
	var b [4]byte
	r.fill(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func (r *streamPRNG) nextU64() uint64 {
	var b [8]byte
	r.fill(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// ============================================================================
// Ring helpers
// ============================================================================

type Poly [N]uint64

func addModQ(a, b uint64) uint64 {
	s := a + b
	if s >= Q {
		s -= Q
	}
	return s
}

func subModQ(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + Q - b
}

func mulModQ(a, b uint64) uint64 {
	return (a * b) % Q
}

func powModQ(base, exp uint64) uint64 {
	r := uint64(1)
	b := base % Q
	for exp > 0 {
		if exp&1 == 1 {
			r = mulModQ(r, b)
		}
		b = mulModQ(b, b)
		exp >>= 1
	}
	return r
}

func invModQ(a uint64) uint64 { return powModQ(a, Q-2) }

func polyAdd(out, a, b *Poly) {
	for i := 0; i < N; i++ {
		out[i] = addModQ(a[i], b[i])
	}
}

func polySub(out, a, b *Poly) {
	for i := 0; i < N; i++ {
		out[i] = subModQ(a[i], b[i])
	}
}

func polyScalarMul(out, a *Poly, s uint64) {
	sr := s % Q
	for i := 0; i < N; i++ {
		out[i] = mulModQ(a[i], sr)
	}
}

// polyMulNegacyclic computes a*b in Z_Q[X]/(X^N+1). Schoolbook with two
// per-output-coefficient accumulators (positive + negative), reducing only
// at the end. With Q < 2^30 each product is < 2^60; summing 512 of them
// stays under 2^69 — overflows u64. So we periodically reduce a (mod Q)
// once before the inner loop (it's already reduced) but accumulate
// products as 60-bit values in u64, reducing each accumulator coefficient
// every CHUNK_I=8 outer iterations to keep below 2^64.
//
// The C++ side uses an NTT path but produces the same standard-form output
// (see poly_mul.hpp lines 14-20) so this is mathematically equivalent and
// byte-equal at the wire-format boundary.
func polyMulNegacyclic(out, a, b *Poly) {
	var pos, neg [N]uint64
	const chunkI = 8
	for i := 0; i < N; i += chunkI {
		end := i + chunkI
		if end > N {
			end = N
		}
		for ii := i; ii < end; ii++ {
			ai := a[ii]
			if ai == 0 {
				continue
			}
			for j := 0; j < N; j++ {
				// ai < 2^30, b[j] < 2^30 -> product < 2^60.
				prod := ai * b[j]
				ij := ii + j
				if ij < N {
					pos[ij] += prod
				} else {
					neg[ij-N] += prod
				}
			}
		}
		// After up to 8 outer adds, each acc[k] grew by 8 * 2^60 = 2^63.
		// Reduce to keep below overflow.
		for k := 0; k < N; k++ {
			pos[k] %= Q
			neg[k] %= Q
		}
	}
	for k := 0; k < N; k++ {
		out[k] = subModQ(pos[k], neg[k])
	}
}

// ============================================================================
// Samplers
// ============================================================================

func sampleUniformPoly(p *Poly, rng *streamPRNG) {
	const mask uint64 = uint64(1) << 32
	bound := uint32(mask - (mask % Q))
	for i := 0; i < N; i++ {
		var v uint32
		for {
			v = rng.nextU32()
			if v < bound {
				break
			}
		}
		p[i] = uint64(v) % Q
	}
}

// gaussianCDT mirrors the C++ ctor in corona.cpp lines 187-218. We computed
// the CDT once with both libm (Apple clang) and Go math.Exp on darwin/arm64
// and observed byte-identical uint64 entries — see /tmp/cdt_check.go in the
// authoring transcript. The fp pmf differs by 1-2 ULPs but that's far below
// the rounding boundary of static_cast<uint64_t>(cum * 1.844e+19) so the
// integer table matches bit-for-bit.
type gaussianCDT struct {
	cdt [GAUSS_BOUND + 1]uint64
}

func newGaussianCDT() *gaussianCDT {
	g := &gaussianCDT{}
	pmf := make([]float64, GAUSS_BOUND+1)
	for k := 0; k <= GAUSS_BOUND; k++ {
		pmf[k] = math.Exp(-float64(k) * float64(k) / (2.0 * SIGMA * SIGMA))
	}
	sum := pmf[0]
	for k := 1; k <= GAUSS_BOUND; k++ {
		sum += 2.0 * pmf[k]
	}
	for k := 0; k <= GAUSS_BOUND; k++ {
		pmf[k] /= sum
	}
	cum := 0.0
	cum += pmf[0]
	g.cdt[0] = uint64(cum * 18446744073709551615.0)
	for k := 1; k <= GAUSS_BOUND; k++ {
		cum += 2.0 * pmf[k]
		if cum >= 1.0 {
			g.cdt[k] = ^uint64(0)
		} else {
			g.cdt[k] = uint64(cum * 18446744073709551615.0)
		}
	}
	g.cdt[GAUSS_BOUND] = ^uint64(0)
	return g
}

// sample returns a signed Gaussian in [-GAUSS_BOUND, GAUSS_BOUND] using the
// half-CDT + uniform-sign trick from corona.cpp lines 220-236.
func (g *gaussianCDT) sample(rng *streamPRNG) int32 {
	u := rng.nextU64()
	mag := int32(0)
	for k := 0; k <= GAUSS_BOUND; k++ {
		if u <= g.cdt[k] {
			mag = int32(k)
			break
		}
	}
	if mag == 0 {
		return 0
	}
	s := rng.nextU32()
	if s&1 == 1 {
		return -mag
	}
	return mag
}

var globalCDT = newGaussianCDT()

func sampleGaussianPoly(p *Poly, rng *streamPRNG) {
	for i := 0; i < N; i++ {
		v := globalCDT.sample(rng)
		if v >= 0 {
			p[i] = uint64(v) % Q
		} else {
			p[i] = subModQ(0, uint64(-v)%Q)
		}
	}
}

// challengePoly: Fisher-Yates pick TAU positions, ±1 sign per pick.
// Matches corona.cpp lines 267-287.
func challengePoly(c *Poly, tag []byte) {
	rng := newStreamPRNG(tag)
	for i := range c {
		c[i] = 0
	}
	idx := make([]uint32, N)
	for i := 0; i < N; i++ {
		idx[i] = uint32(i)
	}
	for i := uint32(0); i < uint32(TAU); i++ {
		span := uint32(N) - i
		// Compute bound as u64 to avoid the C++ `static_cast<uint32_t>`
		// wrap-to-zero when span divides 2^32 — see comment in
		// corona.cpp challenge_poly. For span = 512 the largest u32
		// multiple of span is exactly 2^32, which narrows to 0 in u32.
		bound64 := uint64(1) << 32 / uint64(span) * uint64(span)
		var r uint32
		for {
			r = rng.nextU32()
			if uint64(r) < bound64 {
				break
			}
		}
		j := i + (r % span)
		idx[i], idx[j] = idx[j], idx[i]
		s := rng.nextU32() & 1
		if s == 0 {
			c[idx[i]] = 1
		} else {
			c[idx[i]] = Q - 1
		}
	}
}

// ============================================================================
// Wire format
// ============================================================================

func polyToBytes(p *Poly, out []byte) {
	for i := 0; i < N; i++ {
		v := uint32(p[i])
		out[4*i+0] = byte(v)
		out[4*i+1] = byte(v >> 8)
		out[4*i+2] = byte(v >> 16)
		out[4*i+3] = byte(v >> 24)
	}
}

// ============================================================================
// Shamir secret sharing in R_q (per-coefficient over Z_q, evaluated polywise)
// ============================================================================

// shamirSharePolys mirrors corona.cpp lines 324-358.
func shamirSharePolys(s []Poly, t, n int, rng *streamPRNG) [][]Poly {
	shares := make([][]Poly, n)
	for i := range shares {
		shares[i] = make([]Poly, len(s))
	}
	for j := range s {
		// Coefficients of f_j(x): a[0] = s[j], a[d] for d=1..t-1 random uniform.
		a := make([]Poly, t)
		a[0] = s[j]
		for d := 1; d < t; d++ {
			sampleUniformPoly(&a[d], rng)
		}
		for i := 0; i < n; i++ {
			x := uint64(i + 1)
			xPow := uint64(1)
			var out Poly
			for d := 0; d < t; d++ {
				if d == 0 {
					out = a[0]
				} else {
					var term Poly
					polyScalarMul(&term, &a[d], xPow)
					polyAdd(&out, &out, &term)
				}
				xPow = mulModQ(xPow, x)
			}
			shares[i][j] = out
		}
	}
	return shares
}

// lagrangeAtZero — coefficient at x=0 for evaluation point xs[i]
// over the index set xs.
func lagrangeAtZero(i int, xs []uint64) uint64 {
	num := uint64(1)
	den := uint64(1)
	xi := xs[i]
	for j := range xs {
		if j == i {
			continue
		}
		negXj := subModQ(0, xs[j])
		num = mulModQ(num, negXj)
		diff := subModQ(xi, xs[j])
		den = mulModQ(den, diff)
	}
	return mulModQ(num, invModQ(den))
}

func shamirReconstruct(shares [][]Poly, partyIDs []uint64, t, l int) []Poly {
	xs := append([]uint64(nil), partyIDs[:t]...)
	out := make([]Poly, l)
	for i := 0; i < t; i++ {
		lam := lagrangeAtZero(i, xs)
		for j := 0; j < l; j++ {
			var term Poly
			polyScalarMul(&term, &shares[i][j], lam)
			polyAdd(&out[j], &out[j], &term)
		}
	}
	return out
}

// ============================================================================
// L-infinity bound
// ============================================================================

func linfWithin(v []Poly, bound uint64) bool {
	halfQ := Q / 2
	for k := range v {
		for _, c := range v[k] {
			var mag uint64
			if c <= halfQ {
				mag = c
			} else {
				mag = Q - c
			}
			if mag > bound {
				return false
			}
		}
	}
	return true
}

// ============================================================================
// Transcript construction
// ============================================================================

func buildChallengeTag(pk []byte, w []Poly, msg []byte) []byte {
	domain := []byte("CORONA.v1")
	buf := make([]byte, 0, len(domain)+len(pk)+len(w)*POLY_BYTES+len(msg))
	buf = append(buf, domain...)
	buf = append(buf, pk...)
	tmp := make([]byte, POLY_BYTES)
	for i := range w {
		polyToBytes(&w[i], tmp)
		buf = append(buf, tmp...)
	}
	buf = append(buf, msg...)
	h := sha256.Sum256(buf)
	return h[:]
}

// ============================================================================
// Context (shape-compatible with C++ Context)
// ============================================================================

type keyShare struct {
	partyID uint32
	sShare  []Poly
}

type Context struct {
	t           uint32
	n           uint32
	A           [][]Poly // K x L
	b           []Poly   // K
	shares      []keyShare
	seed        []byte
	signCounter uint64
}

// Setup mirrors corona.cpp Setup.
func Setup(t, n uint32, seed []byte) *Context {
	if n < 1 || t < 1 || t > n {
		panic("invalid (t,n)")
	}
	// Domain-separated 32-byte derived seed: SHA-256("RTSETUP.v1" || seed).
	dom := append([]byte("RTSETUP.v1"), seed...)
	derived := sha256.Sum256(dom)
	useSeed := derived[:]

	rng := newStreamPRNG(useSeed)
	ctx := &Context{
		t:    t,
		n:    n,
		seed: append([]byte(nil), useSeed...),
		A:    make([][]Poly, K),
	}
	for i := 0; i < K; i++ {
		ctx.A[i] = make([]Poly, L)
		for j := 0; j < L; j++ {
			sampleUniformPoly(&ctx.A[i][j], rng)
		}
	}
	s := make([]Poly, L)
	for j := 0; j < L; j++ {
		sampleGaussianPoly(&s[j], rng)
	}
	e := make([]Poly, K)
	for i := 0; i < K; i++ {
		sampleGaussianPoly(&e[i], rng)
	}
	ctx.b = make([]Poly, K)
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			var term Poly
			polyMulNegacyclic(&term, &ctx.A[i][j], &s[j])
			polyAdd(&ctx.b[i], &ctx.b[i], &term)
		}
		polyAdd(&ctx.b[i], &ctx.b[i], &e[i])
	}
	sharePolys := shamirSharePolys(s, int(t), int(n), rng)
	ctx.shares = make([]keyShare, n)
	for i := uint32(0); i < n; i++ {
		ctx.shares[i] = keyShare{
			partyID: i + 1,
			sShare:  sharePolys[i],
		}
	}
	return ctx
}

// SerializePK — A || b in row-major, polys as little-endian u32 coefs.
func (ctx *Context) SerializePK() []byte {
	out := make([]byte, PK_BYTES)
	off := 0
	for i := 0; i < K; i++ {
		for j := 0; j < L; j++ {
			polyToBytes(&ctx.A[i][j], out[off:])
			off += POLY_BYTES
		}
	}
	for i := 0; i < K; i++ {
		polyToBytes(&ctx.b[i], out[off:])
		off += POLY_BYTES
	}
	return out
}

// Sign — Schnorr-Lyubashevsky with rejection sampling.
func (ctx *Context) Sign(msg []byte) []byte {
	// Reconstruct s from first t shares (Lagrange at x=0).
	partyIDs := make([]uint64, ctx.t)
	for i := uint32(0); i < ctx.t; i++ {
		partyIDs[i] = uint64(ctx.shares[i].partyID)
	}
	sharesPolys := make([][]Poly, ctx.t)
	for i := uint32(0); i < ctx.t; i++ {
		sharesPolys[i] = ctx.shares[i].sShare
	}
	s := shamirReconstruct(sharesPolys, partyIDs, int(ctx.t), L)

	pkBytes := ctx.SerializePK()

	signSeed := make([]byte, 40)
	copy(signSeed[:32], ctx.seed)
	ctx.signCounter++
	ctr := ctx.signCounter
	binary.LittleEndian.PutUint64(signSeed[32:], ctr)

	const maxReject = 256
	for attempt := 0; attempt < maxReject; attempt++ {
		attemptSeed := make([]byte, 40+4)
		copy(attemptSeed, signSeed)
		binary.LittleEndian.PutUint32(attemptSeed[40:], uint32(attempt))
		signRng := newStreamPRNG(attemptSeed)

		y := make([]Poly, L)
		for j := 0; j < L; j++ {
			sampleGaussianPoly(&y[j], signRng)
		}
		w := make([]Poly, K)
		for i := 0; i < K; i++ {
			for j := 0; j < L; j++ {
				var term Poly
				polyMulNegacyclic(&term, &ctx.A[i][j], &y[j])
				polyAdd(&w[i], &w[i], &term)
			}
		}
		tag := buildChallengeTag(pkBytes, w, msg)
		var c Poly
		challengePoly(&c, tag)

		z := make([]Poly, L)
		for j := 0; j < L; j++ {
			var sc Poly
			polyMulNegacyclic(&sc, &s[j], &c)
			polyAdd(&z[j], &y[j], &sc)
		}
		if !linfWithin(z, B_INF) {
			continue
		}
		out := make([]byte, SIG_BYTES)
		off := 0
		polyToBytes(&c, out[off:])
		off += POLY_BYTES
		for j := 0; j < L; j++ {
			polyToBytes(&z[j], out[off:])
			off += POLY_BYTES
		}
		return out
	}
	panic("rejection budget exhausted")
}

// ============================================================================
// KAT vector schedule + emitter
// ============================================================================

// vectorSpec — one KAT vector. The C++ side will call:
//
//	Setup(t, n, seed=seedASCII, seedLen=len(seedASCII))
//	Sign(msg=msgASCII, msgLen=len(msgASCII))   // single Sign per ctx
//
// and assert that pk_sha256 / sig_sha256 / sig_first64 match.
type vectorSpec struct {
	name string
	t, n uint32
	seed string
	msg  string
}

// Sixteen deterministic vectors covering: t=1,n=1; t=2,n=3; t=3,n=5; t=4,n=7;
// t=5,n=9; threshold edges; varying message lengths from 0 to 96 bytes.
// Identical schedule lives in cpp/corona_kat_test.cpp.
var katVectors = []vectorSpec{
	{"single_party", 1, 1, "RT-KAT-V1-S00", ""},
	{"single_party_short_msg", 1, 1, "RT-KAT-V1-S01", "hi"},
	{"two_of_three", 2, 3, "RT-KAT-V1-S02", "Lux threshold consensus block"},
	{"two_of_three_long", 2, 3, "RT-KAT-V1-S03", strings.Repeat("L", 64)},
	{"three_of_five", 3, 5, "RT-KAT-V1-S04", "block-height=12345 epoch=42"},
	{"three_of_five_alt", 3, 5, "RT-KAT-V1-S05", "validator-rotation"},
	{"four_of_seven", 4, 7, "RT-KAT-V1-S06", strings.Repeat("X", 32)},
	{"four_of_seven_alt", 4, 7, "RT-KAT-V1-S07", "corona post-quantum check"},
	{"five_of_nine", 5, 9, "RT-KAT-V1-S08", strings.Repeat("a", 16)},
	{"five_of_nine_alt", 5, 9, "RT-KAT-V1-S09", "ten-byte-m"},
	{"two_of_two", 2, 2, "RT-KAT-V1-S10", "small group"},
	{"three_of_three", 3, 3, "RT-KAT-V1-S11", "all sign"},
	{"two_of_five", 2, 5, "RT-KAT-V1-S12", "low threshold"},
	{"one_of_three", 1, 3, "RT-KAT-V1-S13", "trivial threshold"},
	{"six_of_eleven", 6, 11, "RT-KAT-V1-S14", strings.Repeat("B", 96)},
	{"seven_of_eleven", 7, 11, "RT-KAT-V1-S15", "\x00\x01\x02\xff\xfe\xfd"},
}

// emitCBytes formats a byte slice as a comma-separated 0x-prefixed C array
// content, wrapping at 12 bytes per line.
func emitCBytes(w io.Writer, b []byte) {
	for i, x := range b {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		if i > 0 && i%12 == 0 {
			fmt.Fprint(w, "\n     ")
		}
		fmt.Fprintf(w, "0x%02x", x)
	}
}

func main() {
	w := os.Stdout
	fmt.Fprint(w, `// SPDX-License-Identifier: BSD-3-Clause-Eco
// corona_kat.h — generated by lux/threshold/cmd/corona_oracle.
//
// Source of truth: this Go reimplementation of the C++ Corona body
// (luxcpp/crypto/corona/cpp/corona.{hpp,cpp}). Same parameters
// (Q = 998244353, N = 512, L = K = 4, σ = 1.7, τ = 30, B_∞ = Q/4),
// same StreamPRNG (SHA-256 counter mode), same Gaussian CDT, same
// negacyclic schoolbook multiply, same wire format.
//
// Each vector pins the exact pk_sha256 / sig_sha256 / sig_first64 produced
// by the algorithm given (t, n, seed_ascii, msg_ascii). The C++ KAT test
// runs Setup(t, n, seed) → SerializePK + Sign(msg) and asserts byte-equal
// pk + byte-equal sig. Sixteen vectors cover 1..7-of-11 thresholds with
// message lengths from 0 to 96 bytes.
//
// To regenerate:
//   cd lux/threshold/cmd/corona_oracle
//   go run . > ../../../../luxcpp/crypto/corona/test/corona_kat.h
//
// DO NOT EDIT.
#pragma once
#include <cstdint>
#include <cstddef>

namespace lux::crypto::corona::kat {

struct CoronaKAT {
    const char*    name;
    std::uint32_t  t;
    std::uint32_t  n;
    const char*    seed;          // null-terminated ASCII; Setup seed_len = strlen(seed).
    const char*    msg;           // raw bytes, may contain NUL.
    std::size_t    msg_len;
    std::uint8_t   pk_sha256[32];
    std::uint8_t   sig_sha256[32];
    std::uint8_t   sig_first64[64];
};

`)
	fmt.Fprintf(w, "constexpr int kCoronaKATCount = %d;\n\n", len(katVectors))
	fmt.Fprint(w, "inline const CoronaKAT kCoronaKAT[] = {\n")

	for vi, v := range katVectors {
		ctx := Setup(v.t, v.n, []byte(v.seed))
		pk := ctx.SerializePK()
		pkSha := sha256.Sum256(pk)
		sig := ctx.Sign([]byte(v.msg))
		sigSha := sha256.Sum256(sig)

		// C string-literal escape for msg (handles bytes, including NUL).
		// We emit the raw bytes via \xHH so we don't accidentally produce
		// trigraphs or other surprises in the generated header.
		var msgEsc strings.Builder
		for i := 0; i < len(v.msg); i++ {
			fmt.Fprintf(&msgEsc, "\\x%02x", v.msg[i])
		}

		fmt.Fprintf(w, "    {\n")
		fmt.Fprintf(w, "      /*name=*/        %q,\n", v.name)
		fmt.Fprintf(w, "      /*t=*/           %d,\n", v.t)
		fmt.Fprintf(w, "      /*n=*/           %d,\n", v.n)
		fmt.Fprintf(w, "      /*seed=*/        %q,\n", v.seed)
		fmt.Fprintf(w, "      /*msg=*/         \"%s\",\n", msgEsc.String())
		fmt.Fprintf(w, "      /*msg_len=*/     %d,\n", len(v.msg))
		fmt.Fprintf(w, "      /*pk_sha256=*/   {")
		emitCBytes(w, pkSha[:])
		fmt.Fprintf(w, "},\n")
		fmt.Fprintf(w, "      /*sig_sha256=*/  {")
		emitCBytes(w, sigSha[:])
		fmt.Fprintf(w, "},\n")
		fmt.Fprintf(w, "      /*sig_first64=*/ {")
		emitCBytes(w, sig[:64])
		fmt.Fprintf(w, "},\n")
		if vi == len(katVectors)-1 {
			fmt.Fprintf(w, "    }\n")
		} else {
			fmt.Fprintf(w, "    },\n")
		}
	}
	fmt.Fprint(w, "};\n\n}  // namespace lux::crypto::corona::kat\n")
}
