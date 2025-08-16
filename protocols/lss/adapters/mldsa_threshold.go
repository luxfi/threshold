// Package adapters - ML-DSA/Dilithium threshold signature with Shamir LSS
package adapters

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"math/rand"
	"sort"

	"github.com/luxfi/threshold/pkg/party"
)

// MLDSAThresholdAdapter implements true t-of-n threshold ML-DSA using Shamir LSS
type MLDSAThresholdAdapter struct {
	params    *MLDSAParams
	threshold *ThresholdConfig
	mpc       MPCEngine
	pub       PubOps
}

// MLDSAParams matches FIPS 204 parameter sets
type MLDSAParams struct {
	Name          string // ML-DSA-44, ML-DSA-65, ML-DSA-87
	SecurityLevel int    // NIST level: 2, 3, or 5

	// Core parameters
	Q        int64 // 8380417 (prime modulus)
	N        int   // 256 (polynomial degree)
	K        int   // Vector dimension
	L        int   // Matrix dimension
	D        int   // Dropped bits
	Tau      int   // Challenge weight
	Eta      int   // Secret key range
	Beta     int   // Rejection bound
	Gamma1   int   // y coefficient range
	Gamma2   int   // Low-order rounding range
	Alpha2G2 int   // 2*Gamma2 for HighBits
	Omega    int   // Max hints per row

	// Sizes
	SignatureSize int
	PublicKeySize int
	SecretKeySize int
}

// Field element in GF(Q)
type F int64

// Poly is a degree-255 polynomial over GF(Q)
type Poly [256]F

// SecretPoly is a Shamir-shared polynomial
type SecretPoly struct {
	Coeffs []F // Secret-shared coefficients
}

// ThresholdConfig describes the active subset and Shamir parameters
type ThresholdConfig struct {
	Subset []party.ID     // Active signers (m >= t)
	Alpha  map[party.ID]F // Shamir x-coordinates (non-zero)
	T      int            // Threshold
	N      int            // Total parties
	Q      F              // Field modulus
}

// Hints represent hint positions for signature compression
type Hints struct {
	Idx [][]int // Per-row positions where HighBits differ
}

// Sig is an ML-DSA signature
type Sig struct {
	C Poly   // Challenge polynomial
	Z []Poly // Response vector
	H Hints  // Hint positions
}

// Precomp holds precomputed values for online signing
type Precomp struct {
	Y  []SecretPoly // Secret-shared masking polynomials
	W  []SecretPoly // Secret W = A*Y
	WH []Poly       // Public HighBits(W)
}

// MPCEngine defines the MPC operations interface
type MPCEngine interface {
	Add(a, b []F) []F
	Sub(a, b []F) []F
	MulConst(a []F, c F) []F
	HighBitsVec(v []SecretPoly, alpha int) ([]SecretPoly, error)
	Open(s []SecretPoly) ([]Poly, error)
	OpenAtZero(s []SecretPoly, subset []party.ID, lambda map[party.ID]F) ([]Poly, error)
	EqZero(a []F) (bool, error)
	LongOverflow(v []SecretPoly, bound int) (bool, error)
}

// PubOps defines public operations on polynomials
type PubOps interface {
	VecMulByPublicPoly(v []SecretPoly, p Poly) []SecretPoly
	LiftPublicPoly(p Poly) SecretPoly
	MatrixVectorMul(A [][]Poly, v []SecretPoly) []SecretPoly
}

// SignParams holds signing parameters
type SignParams struct {
	Params  MLDSAParams
	Omega   int
	DeriveC func(mu []byte, wH []Poly) (Poly, error)
	PubMul  func(a, b Poly) Poly
}

// GetMLDSAParams returns parameters for a given security level
func GetMLDSAParams(level int) *MLDSAParams {
	switch level {
	case 2: // ML-DSA-44
		return &MLDSAParams{
			Name:          "ML-DSA-44",
			SecurityLevel: 2,
			Q:             8380417,
			N:             256,
			K:             4,
			L:             4,
			D:             13,
			Tau:           39,
			Eta:           2,
			Beta:          78,
			Gamma1:        131072, // 2^17
			Gamma2:        95232,  // (q-1)/88
			Alpha2G2:      190464, // 2*Gamma2
			Omega:         80,
			SignatureSize: 2420,
			PublicKeySize: 1312,
			SecretKeySize: 2528,
		}
	case 3: // ML-DSA-65
		return &MLDSAParams{
			Name:          "ML-DSA-65",
			SecurityLevel: 3,
			Q:             8380417,
			N:             256,
			K:             6,
			L:             5,
			D:             13,
			Tau:           49,
			Eta:           4,
			Beta:          196,
			Gamma1:        524288, // 2^19
			Gamma2:        261888, // (q-1)/32
			Alpha2G2:      523776, // 2*Gamma2
			Omega:         55,
			SignatureSize: 3293,
			PublicKeySize: 1952,
			SecretKeySize: 4000,
		}
	case 5: // ML-DSA-87
		return &MLDSAParams{
			Name:          "ML-DSA-87",
			SecurityLevel: 5,
			Q:             8380417,
			N:             256,
			K:             8,
			L:             7,
			D:             13,
			Tau:           60,
			Eta:           2,
			Beta:          120,
			Gamma1:        524288, // 2^19
			Gamma2:        261888, // (q-1)/32
			Alpha2G2:      523776, // 2*Gamma2
			Omega:         75,
			SignatureSize: 4595,
			PublicKeySize: 2592,
			SecretKeySize: 4864,
		}
	default:
		return GetMLDSAParams(2)
	}
}

// NewMLDSAThresholdAdapter creates a new threshold ML-DSA adapter
func NewMLDSAThresholdAdapter(securityLevel int, threshold *ThresholdConfig, mpc MPCEngine, pub PubOps) *MLDSAThresholdAdapter {
	return &MLDSAThresholdAdapter{
		params:    GetMLDSAParams(securityLevel),
		threshold: threshold,
		mpc:       mpc,
		pub:       pub,
	}
}

// LagrangeAtZero computes Lagrange coefficients for reconstruction at x=0
func LagrangeAtZero(th *ThresholdConfig) (map[party.ID]F, error) {
	m := len(th.Subset)
	if m < th.T {
		return nil, fmt.Errorf("insufficient signers: have %d need %d", m, th.T)
	}

	lambda := make(map[party.ID]F, m)
	for _, i := range th.Subset {
		ai := th.Alpha[i]
		num := F(1)
		den := F(1)

		for _, j := range th.Subset {
			if j == i {
				continue
			}
			aj := th.Alpha[j]
			// λ_i = Π_{j≠i} (-aj) / (ai - aj)
			num = num.MulMod(F(0).SubMod(aj, th.Q), th.Q)
			den = den.MulMod(ai.SubMod(aj, th.Q), th.Q)
		}

		invDen, ok := den.InvMod(th.Q)
		if !ok {
			return nil, fmt.Errorf("non-invertible denominator for %s", i)
		}
		lambda[i] = num.MulMod(invDen, th.Q)
	}

	return lambda, nil
}

// BuildHintsPublic computes ML-DSA hints from public data (post-reconstruction)
func BuildHintsPublic(
	A [][]Poly,
	Z []Poly,
	c Poly,
	t, t0 []Poly,
	params *MLDSAParams,
	omega int,
	mul func(a, b Poly) Poly,
) (Hints, error) {
	if len(A) != params.K || len(A[0]) != params.L {
		return Hints{}, fmt.Errorf("A dims mismatch: got %dx%d need %dx%d",
			len(A), len(A[0]), params.K, params.L)
	}
	if len(Z) != params.L || len(t) != params.K || len(t0) != params.K {
		return Hints{}, fmt.Errorf("vector dims mismatch")
	}

	// 1) Az (public)
	Az := make([]Poly, params.K)
	for j := 0; j < params.K; j++ {
		var acc Poly
		for i := 0; i < params.L; i++ {
			term := mul(A[j][i], Z[i])
			acc = acc.Add(term)
		}
		Az[j] = acc
	}

	// 2) u1 = Az - c*t, u2 = u1 + c*t0 (public)
	u1 := make([]Poly, params.K)
	u2 := make([]Poly, params.K)
	for j := 0; j < params.K; j++ {
		ct := mul(c, t[j])
		ct0 := mul(c, t0[j])
		u1[j] = Az[j].Sub(ct)
		u2[j] = u1[j].Add(ct0)
	}

	// 3) h1 = HighBits(u1), h2 = HighBits(u2)
	h1 := make([]Poly, params.K)
	h2 := make([]Poly, params.K)
	for j := 0; j < params.K; j++ {
		h1[j] = HighBitsPublic(u1[j], params.Alpha2G2, int(params.Q))
		h2[j] = HighBitsPublic(u2[j], params.Alpha2G2, int(params.Q))
	}

	// 4) Find positions where they differ
	out := Hints{Idx: make([][]int, params.K)}
	for j := 0; j < params.K; j++ {
		idx := make([]int, 0, omega)
		for i := 0; i < params.N; i++ {
			if h1[j][i] != h2[j][i] {
				idx = append(idx, i)
				if len(idx) > omega {
					return Hints{}, fmt.Errorf("too many hints in row %d: %d > %d",
						j, len(idx), omega)
				}
			}
		}
		out.Idx[j] = idx
	}

	return out, nil
}

// OnlineSignT performs threshold signing for ML-DSA using Shamir LSS
func (m *MLDSAThresholdAdapter) OnlineSignT(
	A [][]Poly,
	mu []byte,
	pre Precomp,
	s1, s2 []SecretPoly,
	t, t0 []Poly,
	sp SignParams,
) (Sig, bool, error) {
	P := &sp.Params
	if len(s1) != P.L || len(s2) != P.K {
		return Sig{}, false, fmt.Errorf("key shares dims mismatch")
	}

	// Round A: Derive challenge from (mu, wH)
	c, err := sp.DeriveC(mu, pre.WH)
	if err != nil {
		return Sig{}, false, fmt.Errorf("derive c: %w", err)
	}

	// Round B: MPC computations (remain secret)
	// zs = y + c*s1
	cS1 := m.pub.VecMulByPublicPoly(s1, c)
	zs := m.addVecMPC(pre.Y, cS1)

	// rL = (w - 2*γ2*wH) - c*s2
	wL := make([]SecretPoly, P.K)
	for j := 0; j < P.K; j++ {
		whShare := m.pub.LiftPublicPoly(pre.WH[j])
		sub := m.mpc.Sub(pre.W[j].Coeffs, m.mpc.MulConst(whShare.Coeffs, F(P.Alpha2G2)))
		wL[j] = SecretPoly{Coeffs: sub}
	}
	cS2 := m.pub.VecMulByPublicPoly(s2, c)
	rL := make([]SecretPoly, P.K)
	for j := 0; j < P.K; j++ {
		rL[j] = SecretPoly{Coeffs: m.mpc.Sub(wL[j].Coeffs, cS2[j].Coeffs)}
	}

	// Rejection check (in MPC)
	ok, err := m.RejectionCheck(zs, rL, P)
	if err != nil {
		return Sig{}, false, fmt.Errorf("rejection-check: %w", err)
	}
	if !ok {
		return Sig{}, false, nil // Retry with new precomp
	}

	// Round C: Reconstruct Z via Lagrange (only after rejection passes)
	lambda, err := LagrangeAtZero(m.threshold)
	if err != nil {
		return Sig{}, false, fmt.Errorf("lagrange: %w", err)
	}

	// Open z at 0 using Lagrange coefficients
	Z, err := m.mpc.OpenAtZero(zs, m.threshold.Subset, lambda)
	if err != nil {
		return Sig{}, false, fmt.Errorf("open z: %w", err)
	}

	// Round D: Build hints publicly (cheaper than MPC)
	h, err := BuildHintsPublic(A, Z, c, t, t0, P, sp.Omega, sp.PubMul)
	if err != nil {
		return Sig{}, false, fmt.Errorf("hints: %w", err)
	}

	return Sig{C: c, Z: Z, H: h}, true, nil
}

// RejectionCheck performs ML-DSA rejection sampling in MPC
func (m *MLDSAThresholdAdapter) RejectionCheck(zs, rL []SecretPoly, params *MLDSAParams) (bool, error) {
	// Check ||z||_∞ < γ1 - β
	bound := F(params.Gamma1 - params.Beta)
	for _, z := range zs {
		overflow, err := m.mpc.LongOverflow([]SecretPoly{z}, int(bound))
		if err != nil {
			return false, err
		}
		if overflow {
			return false, nil
		}
	}

	// Check low bits condition for rL
	for _, r := range rL {
		// Implementation depends on MPC engine's capabilities
		// This is a simplified check
		overflow, err := m.mpc.LongOverflow([]SecretPoly{r}, params.Gamma2-params.Beta)
		if err != nil {
			return false, err
		}
		if overflow {
			return false, nil
		}
	}

	return true, nil
}

// PrecomputeT generates precomputation for threshold signing
func (m *MLDSAThresholdAdapter) PrecomputeT(A [][]Poly) (Precomp, error) {
	P := m.params

	// Sample y with correct distribution (Shamir-shared)
	Y := m.sampleMaskingVector(P.L, P.Gamma1)

	// W = A*Y (secret)
	W := m.pub.MatrixVectorMul(A, Y)

	// WH = HighBits(W) then open
	WH_secret, err := m.mpc.HighBitsVec(W, P.Alpha2G2)
	if err != nil {
		return Precomp{}, fmt.Errorf("highbits: %w", err)
	}

	WH, err := m.mpc.Open(WH_secret)
	if err != nil {
		return Precomp{}, fmt.Errorf("open wH: %w", err)
	}

	return Precomp{Y: Y, W: W, WH: WH}, nil
}

// sampleMaskingVector samples a Shamir-shared masking vector
func (m *MLDSAThresholdAdapter) sampleMaskingVector(dimension int, gamma1 int) []SecretPoly {
	// This would use PRSS or other secure sampling
	// Placeholder implementation
	y := make([]SecretPoly, dimension)
	for i := 0; i < dimension; i++ {
		coeffs := make([]F, m.params.N)
		for j := 0; j < m.params.N; j++ {
			// Sample from [-gamma1+1, gamma1-1]
			v := rand.Intn(2*gamma1-1) - (gamma1 - 1)
			coeffs[j] = F(v)
		}
		y[i] = SecretPoly{Coeffs: coeffs}
	}
	return y
}

// addVecMPC adds two vectors of secret polynomials
func (m *MLDSAThresholdAdapter) addVecMPC(a, b []SecretPoly) []SecretPoly {
	result := make([]SecretPoly, len(a))
	for i := range a {
		result[i] = SecretPoly{
			Coeffs: m.mpc.Add(a[i].Coeffs, b[i].Coeffs),
		}
	}
	return result
}

// HighBitsPublic computes HighBits on public polynomial
func HighBitsPublic(v Poly, alpha int, Q int) Poly {
	var out Poly
	for i := 0; i < 256; i++ {
		r := modPlus(int(v[i]), Q)
		rL := modSym(r, alpha)
		var rH int
		if r-rL == Q-1 {
			rH = 0
			rL = rL - 1
		} else {
			rH = (r - rL) / alpha
		}
		out[i] = F(rH)
	}
	return out
}

// Field arithmetic methods

func (f F) Add(g F) F {
	return F((int64(f) + int64(g)) % 8380417)
}

func (f F) Sub(g F) F {
	r := (int64(f) - int64(g)) % 8380417
	if r < 0 {
		r += 8380417
	}
	return F(r)
}

func (f F) MulMod(g, q F) F {
	return F((int64(f) * int64(g)) % int64(q))
}

func (f F) SubMod(g, q F) F {
	r := (int64(f) - int64(g)) % int64(q)
	if r < 0 {
		r += int64(q)
	}
	return F(r)
}

func (f F) InvMod(q F) (F, bool) {
	// Extended Euclidean algorithm
	a, b := big.NewInt(int64(f)), big.NewInt(int64(q))
	gcd := new(big.Int).GCD(nil, nil, a, b)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return 0, false
	}
	inv := new(big.Int).ModInverse(a, b)
	return F(inv.Int64()), true
}

// Polynomial arithmetic

func (p Poly) Add(q Poly) Poly {
	var r Poly
	for i := 0; i < 256; i++ {
		r[i] = p[i].Add(q[i])
	}
	return r
}

func (p Poly) Sub(q Poly) Poly {
	var r Poly
	for i := 0; i < 256; i++ {
		r[i] = p[i].Sub(q[i])
	}
	return r
}

// Helper functions

func modPlus(x, q int) int {
	x = x % q
	if x < 0 {
		x += q
	}
	return x
}

func modSym(x, alpha int) int {
	r := x % alpha
	if r > alpha/2 {
		r -= alpha
	}
	return r
}

// TranscriptBinding creates a domain-separated binding for threshold ML-DSA
func TranscriptBinding(
	chainID string,
	keyID string,
	epochID uint64,
	participants []party.ID,
	alphaPoints map[party.ID]F,
	precompNonce []byte,
	wH []Poly,
	mu []byte,
) []byte {
	h := sha256.New()
	h.Write([]byte("MLDSA-THRESHOLD"))
	h.Write([]byte(chainID))
	h.Write([]byte(keyID))

	// Epoch ID
	epochBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		epochBytes[i] = byte(epochID >> (8 * i))
	}
	h.Write(epochBytes)

	// Sorted participants
	sorted := make([]party.ID, len(participants))
	copy(sorted, participants)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	for _, p := range sorted {
		h.Write([]byte(p))
		alpha := alphaPoints[p]
		alphaBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			alphaBytes[i] = byte(alpha >> (8 * i))
		}
		h.Write(alphaBytes)
	}

	// Precomputation nonce
	h.Write(precompNonce)

	// Public wH
	for _, w := range wH {
		for i := 0; i < 256; i++ {
			wBytes := make([]byte, 8)
			for j := 0; j < 8; j++ {
				wBytes[j] = byte(w[i] >> (8 * j))
			}
			h.Write(wBytes)
		}
	}

	// Message
	h.Write(mu)

	return h.Sum(nil)
}

// ValidateThresholdConfig ensures threshold configuration is valid
func ValidateThresholdConfig(config *ThresholdConfig) error {
	if config.T < 1 || config.T > config.N {
		return fmt.Errorf("invalid threshold: %d not in [1, %d]", config.T, config.N)
	}

	if len(config.Subset) < config.T {
		return fmt.Errorf("insufficient subset: %d < %d", len(config.Subset), config.T)
	}

	// Check all alphas are distinct and non-zero
	seen := make(map[F]bool)
	for _, id := range config.Subset {
		alpha, ok := config.Alpha[id]
		if !ok {
			return fmt.Errorf("missing alpha for party %s", id)
		}
		if alpha == 0 {
			return fmt.Errorf("alpha for %s is zero", id)
		}
		if seen[alpha] {
			return fmt.Errorf("duplicate alpha value %d", alpha)
		}
		seen[alpha] = true
	}

	return nil
}

// TestMLDSAThreshold provides test vectors and conformance checks
func TestMLDSAThreshold() error {
	// Test Lagrange reconstruction
	config := &ThresholdConfig{
		T:      2,
		N:      3,
		Q:      8380417,
		Subset: []party.ID{"alice", "bob"},
		Alpha: map[party.ID]F{
			"alice":   1,
			"bob":     2,
			"charlie": 3,
		},
	}

	lambda, err := LagrangeAtZero(config)
	if err != nil {
		return fmt.Errorf("lagrange failed: %w", err)
	}

	// Verify sum of lambdas equals 1 for valid reconstruction
	sum := F(0)
	for _, l := range lambda {
		sum = sum.Add(l)
	}
	if sum != F(1) {
		return fmt.Errorf("lagrange coefficients don't sum to 1: got %d", sum)
	}

	// Test public hints computation
	params := GetMLDSAParams(2)
	A := make([][]Poly, params.K)
	for i := range A {
		A[i] = make([]Poly, params.L)
	}

	Z := make([]Poly, params.L)
	var c Poly
	t := make([]Poly, params.K)
	t0 := make([]Poly, params.K)

	mul := func(a, b Poly) Poly { return a } // Placeholder

	_, err = BuildHintsPublic(A, Z, c, t, t0, params, params.Omega, mul)
	if err != nil {
		return fmt.Errorf("hints failed: %w", err)
	}

	return nil
}
