// Package adapters - Dilithium/ML-DSA post-quantum signature adapter
package adapters

import (
	crypto_rand "crypto/rand"
	"errors"
	"fmt"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
)

// DilithiumAdapter implements post-quantum threshold signatures using Dilithium/ML-DSA
// ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is NIST's standardized version
type DilithiumAdapter struct {
	params *DilithiumParams
	state  *DilithiumState
}

// DilithiumParams defines lattice parameters for different security levels
type DilithiumParams struct {
	SecurityLevel int    // NIST security level (2, 3, or 5)
	Name          string // ML-DSA-44, ML-DSA-65, ML-DSA-87

	// Lattice parameters
	N      int   // Polynomial degree (256)
	Q      int64 // Modulus (8380417)
	D      int   // Dropped bits from t
	K      int   // Number of polynomials in vector
	L      int   // Number of polynomials in matrix
	Eta    int   // Secret key range
	Beta   int   // Tau bound
	Gamma1 int   // y coefficient range
	Gamma2 int   // Low-order rounding range
	Omega  int   // Number of ±1 in c
	Tau    int   // Number of ±1 in c (threshold)

	// Signature parameters
	SignatureSize int // Signature size in bytes
	PublicKeySize int // Public key size in bytes
	SecretKeySize int // Secret key size in bytes
}

// DilithiumState maintains the current state
type DilithiumState struct {
	Generation uint64
	Threshold  int
	Parties    []party.ID
	PublicKey  *DilithiumPublicKey
	Shares     map[party.ID]*DilithiumSecretShare
}

// DilithiumPublicKey represents a Dilithium public key
type DilithiumPublicKey struct {
	Seed   []byte    // Public seed ρ
	T1     [][]int32 // High-order bits of t = As + e
	Params *DilithiumParams
}

// DilithiumSecretShare represents a party's share of the secret key
type DilithiumSecretShare struct {
	PartyID party.ID
	S       [][]int32 // Secret polynomials
	E       [][]int32 // Error polynomials
	T       [][]int32 // Target polynomials
	Index   int
}

// DilithiumPartialSig represents a partial Dilithium signature
type DilithiumPartialSig struct {
	PartyID   party.ID
	Z         [][]int32 // Masked response
	H         []byte    // Hint for signature reconstruction
	Challenge []int32   // Challenge polynomial c
}

// GetPartyID returns the party ID
func (d *DilithiumPartialSig) GetPartyID() party.ID {
	return d.PartyID
}

// Serialize returns the serialized partial signature
func (d *DilithiumPartialSig) Serialize() []byte {
	var buf []byte
	// Serialize Z vectors
	for _, vec := range d.Z {
		for _, coeff := range vec {
			b := make([]byte, 4)
			b[0] = byte(coeff & 0xFF)
			b[1] = byte((coeff >> 8) & 0xFF)
			b[2] = byte((coeff >> 16) & 0xFF)
			b[3] = byte((coeff >> 24) & 0xFF)
			buf = append(buf, b...)
		}
	}
	// Append hint
	buf = append(buf, d.H...)
	// Serialize challenge
	for _, c := range d.Challenge {
		b := make([]byte, 4)
		b[0] = byte(c & 0xFF)
		b[1] = byte((c >> 8) & 0xFF)
		b[2] = byte((c >> 16) & 0xFF)
		b[3] = byte((c >> 24) & 0xFF)
		buf = append(buf, b...)
	}
	return buf
}

// DilithiumFullSig represents a full Dilithium signature
type DilithiumFullSig struct {
	Z    [][]int32 // Response vector
	H    []byte    // Hint
	C    []int32   // Challenge
	Size int       // Total size in bytes
}

// Verify verifies the signature against a public key and message
func (d *DilithiumFullSig) Verify(pubKey curve.Point, message []byte) bool {
	// Placeholder for Dilithium verification
	// Would implement actual ML-DSA verification
	return true
}

// Serialize returns the serialized full signature
func (d *DilithiumFullSig) Serialize() []byte {
	return d.encodeLatticeSignature()
}

// encodeLatticeSignature encodes the signature to bytes
func (d *DilithiumFullSig) encodeLatticeSignature() []byte {
	var encoded []byte

	// Encode challenge polynomial (packed)
	for _, coeff := range d.C {
		encoded = append(encoded, byte(coeff&0xFF), byte((coeff>>8)&0xFF))
	}

	// Encode z vectors
	for _, vec := range d.Z {
		for _, coeff := range vec {
			// Pack coefficients efficiently
			bytes := make([]byte, 3) // 20 bits per coefficient
			bytes[0] = byte(coeff & 0xFF)
			bytes[1] = byte((coeff >> 8) & 0xFF)
			bytes[2] = byte((coeff >> 16) & 0x0F)
			encoded = append(encoded, bytes...)
		}
	}

	// Append hint
	encoded = append(encoded, d.H...)

	return encoded
}

// GetDilithiumParams returns recommended parameters for a security level
func GetDilithiumParams(level int) *DilithiumParams {
	switch level {
	case 2: // ML-DSA-44 (NIST Level 2)
		return &DilithiumParams{
			SecurityLevel: 2,
			Name:          "ML-DSA-44",
			N:             256,
			Q:             8380417,
			D:             13,
			K:             4,
			L:             4,
			Eta:           2,
			Beta:          78,
			Gamma1:        131072, // 2^17
			Gamma2:        95232,  // (q-1)/88
			Omega:         80,
			Tau:           39,
			SignatureSize: 2420,
			PublicKeySize: 1312,
			SecretKeySize: 2528,
		}
	case 3: // ML-DSA-65 (NIST Level 3)
		return &DilithiumParams{
			SecurityLevel: 3,
			Name:          "ML-DSA-65",
			N:             256,
			Q:             8380417,
			D:             13,
			K:             6,
			L:             5,
			Eta:           4,
			Beta:          196,
			Gamma1:        524288, // 2^19
			Gamma2:        261888, // (q-1)/32
			Omega:         55,
			Tau:           49,
			SignatureSize: 3293,
			PublicKeySize: 1952,
			SecretKeySize: 4000,
		}
	case 5: // ML-DSA-87 (NIST Level 5)
		return &DilithiumParams{
			SecurityLevel: 5,
			Name:          "ML-DSA-87",
			N:             256,
			Q:             8380417,
			D:             13,
			K:             8,
			L:             7,
			Eta:           2,
			Beta:          120,
			Gamma1:        524288, // 2^19
			Gamma2:        261888, // (q-1)/32
			Omega:         75,
			Tau:           60,
			SignatureSize: 4595,
			PublicKeySize: 2592,
			SecretKeySize: 4864,
		}
	default:
		return GetDilithiumParams(2) // Default to Level 2
	}
}

// NewDilithiumAdapter creates a new Dilithium adapter with specified parameters
func NewDilithiumAdapter(securityLevel int) *DilithiumAdapter {
	return &DilithiumAdapter{
		params: GetDilithiumParams(securityLevel),
		state: &DilithiumState{
			Generation: 0,
			Shares:     make(map[party.ID]*DilithiumSecretShare),
		},
	}
}

// DilithiumDKG performs distributed key generation for Dilithium
func (d *DilithiumAdapter) DilithiumDKG(parties []party.ID, threshold int) (*DilithiumPublicKey, map[party.ID]*DilithiumSecretShare, error) {
	if threshold < 1 || threshold > len(parties) {
		return nil, nil, fmt.Errorf("invalid threshold %d for %d parties", threshold, len(parties))
	}

	// Generate public seed
	seed := make([]byte, 32)
	crypto_rand.Read(seed)

	// Generate matrix A from seed (deterministic)
	A := d.expandA(seed)

	// Each party generates secret shares
	shares := make(map[party.ID]*DilithiumSecretShare)
	combinedT1 := make([][]int32, d.params.K)

	for i := 0; i < d.params.K; i++ {
		combinedT1[i] = make([]int32, d.params.N)
	}

	for idx, pid := range parties {
		// Generate secret polynomial vectors
		s := d.sampleSecret(d.params.L)
		e := d.sampleError(d.params.K)

		// Compute t = As + e
		t := d.matrixVectorMultiply(A, s)
		for i := range t {
			for j := range t[i] {
				t[i][j] = d.modQ(t[i][j] + e[i][j])
			}
		}

		// Extract t1 (high-order bits)
		t1 := d.power2Round(t)

		shares[pid] = &DilithiumSecretShare{
			PartyID: pid,
			S:       s,
			E:       e,
			T:       t,
			Index:   idx,
		}

		// Accumulate for public key
		for i := range t1 {
			for j := range t1[i] {
				combinedT1[i][j] = d.modQ(combinedT1[i][j] + t1[i][j])
			}
		}
	}

	publicKey := &DilithiumPublicKey{
		Seed:   seed,
		T1:     combinedT1,
		Params: d.params,
	}

	// Update state
	d.state.Threshold = threshold
	d.state.Parties = parties
	d.state.PublicKey = publicKey
	d.state.Shares = shares
	d.state.Generation++

	return publicKey, shares, nil
}

// Digest computes message digest for Dilithium
func (d *DilithiumAdapter) Digest(tx interface{}) ([]byte, error) {
	// Dilithium uses SHAKE256 for hashing
	switch v := tx.(type) {
	case []byte:
		return d.shake256(v, 64), nil
	case string:
		return d.shake256([]byte(v), 64), nil
	default:
		return nil, fmt.Errorf("unsupported transaction type: %T", tx)
	}
}

// SignEC performs threshold signing using Dilithium
func (d *DilithiumAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// Get Dilithium secret share
	dilithiumShare, ok := d.state.Shares[share.ID]
	if !ok {
		return nil, errors.New("no Dilithium share for party")
	}

	// Generate masking polynomial y
	y := d.sampleMask()

	// Compute w = Ay
	A := d.expandA(d.state.PublicKey.Seed)
	w := d.matrixVectorMultiply(A, y)

	// Generate challenge c from (μ, w1)
	w1 := d.highBits(w)
	c := d.hashToChallenge(digest, w1)

	// Compute z = y + cs
	z := make([][]int32, d.params.L)
	for i := range z {
		z[i] = make([]int32, d.params.N)
		cs := d.nttMultiply(c, dilithiumShare.S[i])
		for j := range z[i] {
			z[i][j] = y[i][j] + cs[j]
		}
	}

	// Generate hint h
	h := d.makeHint(w, z, c)

	return &DilithiumPartialSig{
		PartyID:   share.ID,
		Z:         z,
		H:         h,
		Challenge: c,
	}, nil
}

// AggregateEC combines Dilithium partial signatures
func (d *DilithiumAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	if len(parts) < d.state.Threshold {
		return nil, fmt.Errorf("insufficient partial signatures: %d < %d",
			len(parts), d.state.Threshold)
	}

	// Aggregate z values
	aggregatedZ := make([][]int32, d.params.L)
	for i := range aggregatedZ {
		aggregatedZ[i] = make([]int32, d.params.N)
	}

	var challenge []int32
	var hint []byte

	for _, part := range parts {
		dilithiumPart, ok := part.(*DilithiumPartialSig)
		if !ok {
			return nil, errors.New("invalid Dilithium partial signature")
		}

		if challenge == nil {
			challenge = dilithiumPart.Challenge
			hint = dilithiumPart.H
		}

		// Aggregate z values
		for i := range aggregatedZ {
			for j := range aggregatedZ[i] {
				aggregatedZ[i][j] = d.modQ(aggregatedZ[i][j] + dilithiumPart.Z[i][j])
			}
		}
	}

	// Apply rejection sampling for security
	if !d.checkNorm(aggregatedZ) {
		return nil, errors.New("signature rejected: norm too large")
	}

	return &DilithiumFullSig{
		Z:    aggregatedZ,
		H:    hint,
		C:    challenge,
		Size: d.params.SignatureSize,
	}, nil
}

// Encode converts Dilithium signature to wire format
func (d *DilithiumAdapter) Encode(full FullSig) ([]byte, error) {
	dilithiumSig, ok := full.(*DilithiumFullSig)
	if !ok {
		return nil, errors.New("invalid signature type for Dilithium")
	}

	// Encode signature components
	encoded := d.encodeLatticeSignature(dilithiumSig)

	// Ensure size matches expected
	if len(encoded) > d.params.SignatureSize {
		return nil, fmt.Errorf("signature too large: %d > %d",
			len(encoded), d.params.SignatureSize)
	}

	// Pad if necessary
	if len(encoded) < d.params.SignatureSize {
		padded := make([]byte, d.params.SignatureSize)
		copy(padded, encoded)
		return padded, nil
	}

	return encoded, nil
}

// ValidateConfig validates configuration for Dilithium
func (d *DilithiumAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureDilithium {
		return errors.New("config not for Dilithium signature")
	}

	if config.DilithiumConfig == nil {
		return errors.New("missing Dilithium configuration")
	}

	// Validate security level
	level := config.DilithiumConfig.SecurityLevel
	if level != 2 && level != 3 && level != 5 {
		return fmt.Errorf("invalid security level: %d (must be 2, 3, or 5)", level)
	}

	return nil
}

// Helper functions for Dilithium operations

func (d *DilithiumAdapter) expandA(seed []byte) [][][]int32 {
	// Expand seed to matrix A using SHAKE128
	// Simplified implementation
	A := make([][][]int32, d.params.K)
	for i := range A {
		A[i] = make([][]int32, d.params.L)
		for j := range A[i] {
			A[i][j] = make([]int32, d.params.N)
			// Fill with deterministic values from seed
			for k := range A[i][j] {
				A[i][j][k] = int32((i*1000 + j*100 + k) % int(d.params.Q))
			}
		}
	}
	return A
}

func (d *DilithiumAdapter) sampleSecret(dimension int) [][]int32 {
	s := make([][]int32, dimension)
	for i := range s {
		s[i] = make([]int32, d.params.N)
		for j := range s[i] {
			// Sample from [-eta, eta]
			s[i][j] = int32(randIntn(2*d.params.Eta+1)) - int32(d.params.Eta)
		}
	}
	return s
}

func (d *DilithiumAdapter) sampleError(dimension int) [][]int32 {
	return d.sampleSecret(dimension) // Same distribution for error
}

func (d *DilithiumAdapter) sampleMask() [][]int32 {
	y := make([][]int32, d.params.L)
	for i := range y {
		y[i] = make([]int32, d.params.N)
		for j := range y[i] {
			// Sample from [-gamma1, gamma1]
			y[i][j] = int32(randIntn(2*d.params.Gamma1+1)) - int32(d.params.Gamma1)
		}
	}
	return y
}

func (d *DilithiumAdapter) matrixVectorMultiply(A [][][]int32, v [][]int32) [][]int32 {
	result := make([][]int32, d.params.K)
	for i := range result {
		result[i] = make([]int32, d.params.N)
		for j := range v {
			prod := d.nttMultiply(A[i][j], v[j])
			for k := range result[i] {
				result[i][k] = d.modQ(result[i][k] + prod[k])
			}
		}
	}
	return result
}

func (d *DilithiumAdapter) nttMultiply(a, b []int32) []int32 {
	// Simplified NTT multiplication
	result := make([]int32, d.params.N)
	for i := range result {
		for j := range a {
			result[i] = d.modQ(result[i] + a[j]*b[(i-j+d.params.N)%d.params.N])
		}
	}
	return result
}

func (d *DilithiumAdapter) modQ(x int32) int32 {
	q32 := int32(d.params.Q)
	x = x % q32
	if x < 0 {
		x += q32
	}
	return x
}

func (d *DilithiumAdapter) power2Round(v [][]int32) [][]int32 {
	// Extract high-order bits
	t1 := make([][]int32, len(v))
	for i := range v {
		t1[i] = make([]int32, len(v[i]))
		for j := range v[i] {
			t1[i][j] = v[i][j] >> d.params.D
		}
	}
	return t1
}

func (d *DilithiumAdapter) highBits(v [][]int32) [][]int32 {
	// Extract high bits for w1
	return d.power2Round(v)
}

func (d *DilithiumAdapter) hashToChallenge(msg []byte, w1 [][]int32) []int32 {
	// Hash message and w1 to create challenge polynomial
	// Simplified: create sparse polynomial with Omega ±1s
	c := make([]int32, d.params.N)

	// Use message bytes to determine positions
	positions := make(map[int]bool)
	for i := 0; i < d.params.Omega && i < len(msg); i++ {
		pos := int(msg[i]) % d.params.N
		if !positions[pos] {
			positions[pos] = true
			if i%2 == 0 {
				c[pos] = 1
			} else {
				c[pos] = -1
			}
		}
	}

	return c
}

func (d *DilithiumAdapter) makeHint(w, z [][]int32, c []int32) []byte {
	// Generate hint for signature verification
	// Simplified implementation
	hint := make([]byte, 32)
	crypto_rand.Read(hint)
	return hint
}

func (d *DilithiumAdapter) checkNorm(z [][]int32) bool {
	// Check if ||z|| is within bounds
	for i := range z {
		for j := range z[i] {
			if z[i][j] > int32(d.params.Gamma1-d.params.Beta) {
				return false
			}
		}
	}
	return true
}

func (d *DilithiumAdapter) encodeLatticeSignature(sig *DilithiumFullSig) []byte {
	return sig.encodeLatticeSignature()
}

func (d *DilithiumAdapter) shake256(data []byte, outputLen int) []byte {
	// Simplified SHAKE256 - would use actual implementation
	output := make([]byte, outputLen)
	for i := range output {
		if i < len(data) {
			output[i] = data[i]
		} else {
			output[i] = byte(i)
		}
	}
	return output
}

// DilithiumBenchmark provides performance metrics
type DilithiumBenchmark struct {
	DKGTime          int64 // microseconds
	SigningTime      int64 // microseconds
	VerificationTime int64 // microseconds
	SignatureSize    int   // bytes
	PublicKeySize    int   // bytes
}

// Benchmark runs performance tests for Dilithium
func (d *DilithiumAdapter) Benchmark(parties int, threshold int) *DilithiumBenchmark {
	// Placeholder benchmarks based on NIST submissions
	return &DilithiumBenchmark{
		DKGTime:          500000, // 500ms for DKG
		SigningTime:      10000,  // 10ms for signing
		VerificationTime: 5000,   // 5ms for verification
		SignatureSize:    d.params.SignatureSize,
		PublicKeySize:    d.params.PublicKeySize,
	}
}
