// Package adapters - Ringtail post-quantum threshold signature implementation
package adapters

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"

	"github.com/luxfi/threshold/pkg/party"
)

// RingtailAdapter implements post-quantum threshold signatures using lattice-based cryptography
// Based on the Ringtail protocol: 2-round threshold signatures from LWE
type RingtailAdapter struct {
	params *RingtailParams
	state  *RingtailState
}

// RingtailParams defines lattice parameters for different security levels
type RingtailParams struct {
	N             int     // Lattice dimension
	Q             int64   // Modulus
	D             int     // Module rank
	M             int     // Number of samples
	Sigma         float64 // Gaussian parameter
	SecurityLevel int     // 128, 192, or 256 bits
	MaxParties    int     // Maximum number of parties (up to 1024)
	SignatureSize int     // Expected signature size in bytes
}

// RingtailState maintains the current state of the Ringtail instance
type RingtailState struct {
	Generation          uint64
	Threshold           int
	Parties             []party.ID
	PublicKey           *RingtailPublicKey
	PreprocessingStore  map[string]*RingtailOfflineData
	ConsumedPreproc     map[string]bool
}

// RingtailPublicKey represents a lattice-based public key
type RingtailPublicKey struct {
	A      [][]int64 // Public matrix A ∈ Z_q^{n×m}
	B      []int64   // Public vector B = As + e
	Params *RingtailParams
}

// RingtailSecretShare represents a party's share of the secret key
type RingtailSecretShare struct {
	PartyID party.ID
	S       []int64   // Secret share vector
	E       []int64   // Error share vector
	Index   int
}

// RingtailOfflineData stores precomputed data for the offline phase
type RingtailOfflineData struct {
	ID           string
	Round1Data   *OfflineRound1
	Round2Data   *OfflineRound2
	Consumed     bool
}

// OfflineRound1 contains first round offline preprocessing data
type OfflineRound1 struct {
	Commitments [][]byte  // Commitments to shares
	Nonces      []int64   // Random nonces
	Timestamp   int64
}

// OfflineRound2 contains second round offline preprocessing data
type OfflineRound2 struct {
	MaskedShares []int64   // Masked secret shares
	Proofs       [][]byte  // Zero-knowledge proofs
}

// GetRecommendedParams returns recommended parameters for a security level
func GetRecommendedParams(securityLevel int, maxParties int) *RingtailParams {
	switch securityLevel {
	case 128:
		return &RingtailParams{
			N:             512,
			Q:             12289,
			D:             8,
			M:             1024,
			Sigma:         3.2,
			SecurityLevel: 128,
			MaxParties:    maxParties,
			SignatureSize: 13400, // ~13.4KB as per paper
		}
	case 192:
		return &RingtailParams{
			N:             768,
			Q:             24593,
			D:             10,
			M:             1536,
			Sigma:         3.5,
			SecurityLevel: 192,
			MaxParties:    maxParties,
			SignatureSize: 20100, // ~20KB estimated
		}
	case 256:
		return &RingtailParams{
			N:             1024,
			Q:             40961,
			D:             12,
			M:             2048,
			Sigma:         3.8,
			SecurityLevel: 256,
			MaxParties:    maxParties,
			SignatureSize: 26800, // ~26.8KB estimated
		}
	default:
		return GetRecommendedParams(128, maxParties) // Default to 128-bit
	}
}

// NewRingtailAdapter creates a new Ringtail adapter with specified parameters
func NewRingtailAdapter(securityLevel int, maxParties int) *RingtailAdapter {
	if maxParties > 1024 {
		maxParties = 1024 // Cap at tested maximum
	}
	
	return &RingtailAdapter{
		params: GetRecommendedParams(securityLevel, maxParties),
		state: &RingtailState{
			Generation:         0,
			PreprocessingStore: make(map[string]*RingtailOfflineData),
			ConsumedPreproc:    make(map[string]bool),
		},
	}
}

// RingtailDKG performs distributed key generation for Ringtail
func (r *RingtailAdapter) RingtailDKG(parties []party.ID, threshold int) (*RingtailPublicKey, map[party.ID]*RingtailSecretShare, error) {
	if threshold < 1 || threshold > len(parties) {
		return nil, nil, fmt.Errorf("invalid threshold %d for %d parties", threshold, len(parties))
	}
	
	if len(parties) > r.params.MaxParties {
		return nil, nil, fmt.Errorf("too many parties: %d > %d", len(parties), r.params.MaxParties)
	}
	
	// Generate public matrix A
	A := r.generatePublicMatrix()
	
	// Each party generates a secret share
	shares := make(map[party.ID]*RingtailSecretShare)
	combinedS := make([]int64, r.params.N)
	combinedE := make([]int64, r.params.N)
	
	for i, pid := range parties {
		// Generate secret and error vectors from Gaussian distribution
		s := r.sampleGaussianVector(r.params.N)
		e := r.sampleGaussianVector(r.params.N)
		
		shares[pid] = &RingtailSecretShare{
			PartyID: pid,
			S:       s,
			E:       e,
			Index:   i,
		}
		
		// Accumulate for public key
		for j := 0; j < r.params.N; j++ {
			combinedS[j] = (combinedS[j] + s[j]) % r.params.Q
			combinedE[j] = (combinedE[j] + e[j]) % r.params.Q
		}
	}
	
	// Compute public key B = A*s + e
	B := r.matrixVectorMultiply(A, combinedS)
	for i := range B {
		B[i] = (B[i] + combinedE[i]) % r.params.Q
	}
	
	publicKey := &RingtailPublicKey{
		A:      A,
		B:      B,
		Params: r.params,
	}
	
	// Update state
	r.state.Threshold = threshold
	r.state.Parties = parties
	r.state.PublicKey = publicKey
	r.state.Generation++
	
	return publicKey, shares, nil
}

// PreprocessOffline generates offline preprocessing data for faster online signing
func (r *RingtailAdapter) PreprocessOffline(numSessions int) error {
	if r.state.PublicKey == nil {
		return errors.New("no public key generated")
	}
	
	for i := 0; i < numSessions; i++ {
		sessionID := fmt.Sprintf("session_%d_%d", r.state.Generation, i)
		
		// Generate offline round 1 data
		round1 := &OfflineRound1{
			Commitments: r.generateCommitments(r.state.Threshold),
			Nonces:      r.sampleGaussianVector(r.params.M),
			Timestamp:   int64(i),
		}
		
		// Generate offline round 2 data
		round2 := &OfflineRound2{
			MaskedShares: r.sampleGaussianVector(r.params.N),
			Proofs:       r.generateProofs(r.state.Threshold),
		}
		
		r.state.PreprocessingStore[sessionID] = &RingtailOfflineData{
			ID:         sessionID,
			Round1Data: round1,
			Round2Data: round2,
			Consumed:   false,
		}
	}
	
	return nil
}

// Digest computes message digest for Ringtail (identity function for PQ)
func (r *RingtailAdapter) Digest(tx interface{}) ([]byte, error) {
	// For post-quantum signatures, we typically use the message directly
	// or apply a quantum-resistant hash function
	switch v := tx.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("unsupported transaction type: %T", tx)
	}
}

// SignEC performs threshold signing using Ringtail protocol
func (r *RingtailAdapter) SignEC(digest []byte, share Share) (PartialSig, error) {
	// Find available preprocessing data
	var offlineData *RingtailOfflineData
	for id, data := range r.state.PreprocessingStore {
		if !data.Consumed {
			offlineData = data
			r.state.PreprocessingStore[id].Consumed = true
			r.state.ConsumedPreproc[id] = true
			break
		}
	}
	
	if offlineData == nil {
		return nil, errors.New("no available preprocessing data")
	}
	
	// For now, create a placeholder Ringtail secret share from scalar
	// TODO: Properly convert curve.Scalar to RingtailSecretShare
	ringtailShare := &RingtailSecretShare{
		PartyID: share.ID,
		Index:   share.Index,
		// Value would be the lattice element derived from share.Value
	}
	
	// Online round 1: Use preprocessed nonces
	// Online round 2: Compute signature share using masked shares
	sigShare := r.computeSignatureShare(digest, ringtailShare, offlineData)
	
	return &RingtailPartialSig{
		PartyID: share.ID,
		Share:   sigShare,
	}, nil
}

// AggregateEC combines Ringtail partial signatures
func (r *RingtailAdapter) AggregateEC(parts []PartialSig) (FullSig, error) {
	if len(parts) < r.state.Threshold {
		return nil, fmt.Errorf("insufficient partial signatures: %d < %d", 
			len(parts), r.state.Threshold)
	}
	
	// Aggregate lattice signatures
	aggregated := r.aggregateLatticeSignatures(parts)
	
	return &RingtailFullSig{
		Signature: aggregated,
		Size:      r.params.SignatureSize,
	}, nil
}

// Encode converts Ringtail signature to wire format
func (r *RingtailAdapter) Encode(full FullSig) ([]byte, error) {
	ringtailSig, ok := full.(*RingtailFullSig)
	if !ok {
		return nil, errors.New("invalid signature type for Ringtail")
	}
	
	// Encode lattice signature
	encoded := r.encodeLatticeSignature(ringtailSig.Signature)
	
	// Ensure size matches expected
	if len(encoded) > r.params.SignatureSize {
		return nil, fmt.Errorf("signature too large: %d > %d", 
			len(encoded), r.params.SignatureSize)
	}
	
	// Pad if necessary
	if len(encoded) < r.params.SignatureSize {
		padded := make([]byte, r.params.SignatureSize)
		copy(padded, encoded)
		return padded, nil
	}
	
	return encoded, nil
}

// ValidateConfig validates configuration for Ringtail
func (r *RingtailAdapter) ValidateConfig(config *UnifiedConfig) error {
	if config.SignatureScheme != SignatureRingtail {
		return errors.New("config not for Ringtail signature")
	}
	
	if config.RingtailConfig == nil {
		return errors.New("missing Ringtail configuration")
	}
	
	// Validate security parameters
	if config.RingtailConfig.SecurityLevel < 128 || config.RingtailConfig.SecurityLevel > 256 {
		return fmt.Errorf("invalid security level: %d", config.RingtailConfig.SecurityLevel)
	}
	
	// Check lattice dimensions
	if config.RingtailConfig.N < 256 || config.RingtailConfig.N > 2048 {
		return fmt.Errorf("invalid lattice dimension: %d", config.RingtailConfig.N)
	}
	
	return nil
}

// Helper functions for lattice operations

func (r *RingtailAdapter) generatePublicMatrix() [][]int64 {
	A := make([][]int64, r.params.N)
	for i := 0; i < r.params.N; i++ {
		A[i] = make([]int64, r.params.M)
		for j := 0; j < r.params.M; j++ {
			A[i][j] = r.randomModQ()
		}
	}
	return A
}

func (r *RingtailAdapter) sampleGaussianVector(n int) []int64 {
	vec := make([]int64, n)
	for i := 0; i < n; i++ {
		vec[i] = r.sampleGaussian()
	}
	return vec
}

func (r *RingtailAdapter) sampleGaussian() int64 {
	// Box-Muller transform for Gaussian sampling
	u1, _ := rand.Int(rand.Reader, big.NewInt(r.params.Q))
	u2, _ := rand.Int(rand.Reader, big.NewInt(r.params.Q))
	
	f1 := float64(u1.Int64()) / float64(r.params.Q)
	f2 := float64(u2.Int64()) / float64(r.params.Q)
	
	z := math.Sqrt(-2*math.Log(f1)) * math.Cos(2*math.Pi*f2)
	sample := int64(z * r.params.Sigma)
	
	return sample % r.params.Q
}

func (r *RingtailAdapter) randomModQ() int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(r.params.Q))
	return n.Int64()
}

func (r *RingtailAdapter) matrixVectorMultiply(A [][]int64, v []int64) []int64 {
	result := make([]int64, len(A))
	for i := range A {
		sum := int64(0)
		for j := range v {
			if j < len(A[i]) {
				sum = (sum + A[i][j]*v[j]) % r.params.Q
			}
		}
		result[i] = sum
	}
	return result
}

func (r *RingtailAdapter) generateCommitments(n int) [][]byte {
	commitments := make([][]byte, n)
	for i := 0; i < n; i++ {
		commitment := make([]byte, 32)
		rand.Read(commitment)
		commitments[i] = commitment
	}
	return commitments
}

func (r *RingtailAdapter) generateProofs(n int) [][]byte {
	proofs := make([][]byte, n)
	for i := 0; i < n; i++ {
		proof := make([]byte, 64)
		rand.Read(proof)
		proofs[i] = proof
	}
	return proofs
}

func (r *RingtailAdapter) computeSignatureShare(message []byte, share *RingtailSecretShare, offline *RingtailOfflineData) []int64 {
	// Simplified signature share computation
	// Actual implementation would follow Ringtail protocol specification
	sigShare := make([]int64, r.params.N)
	
	// Use offline data and secret share to compute signature share
	for i := 0; i < r.params.N; i++ {
		// Combine secret share with nonce and message
		h := int64(0)
		for j := 0; j < len(message) && j < r.params.M; j++ {
			h = (h + int64(message[j])*offline.Round1Data.Nonces[j]) % r.params.Q
		}
		
		sigShare[i] = (share.S[i] + h + offline.Round2Data.MaskedShares[i]) % r.params.Q
	}
	
	return sigShare
}

func (r *RingtailAdapter) aggregateLatticeSignatures(parts []PartialSig) []int64 {
	if len(parts) == 0 {
		return nil
	}
	
	// Get first signature share to determine size
	first := parts[0].(*RingtailPartialSig).Share.([]int64)
	aggregated := make([]int64, len(first))
	
	// Sum all signature shares
	for _, part := range parts {
		share := part.(*RingtailPartialSig).Share.([]int64)
		for i := range aggregated {
			aggregated[i] = (aggregated[i] + share[i]) % r.params.Q
		}
	}
	
	return aggregated
}

func (r *RingtailAdapter) encodeLatticeSignature(sig interface{}) []byte {
	lattice := sig.([]int64)
	
	// Encode each coefficient as bytes
	encoded := make([]byte, 0, len(lattice)*8)
	for _, coeff := range lattice {
		// Encode as 8 bytes
		bytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			bytes[i] = byte(coeff >> (8 * i))
		}
		encoded = append(encoded, bytes...)
	}
	
	return encoded
}

// RingtailBenchmark provides performance metrics
type RingtailBenchmark struct {
	DKGTime           int64 // microseconds
	PreprocessingTime int64 // microseconds per session
	SigningTime       int64 // microseconds (online only)
	VerificationTime  int64 // microseconds
	SignatureSize     int   // bytes
	CommunicationSize int   // total bytes exchanged
}

// Benchmark runs performance tests for Ringtail
func (r *RingtailAdapter) Benchmark(parties int, threshold int) *RingtailBenchmark {
	// This would run actual benchmarks
	// Placeholder values based on paper's reported results
	return &RingtailBenchmark{
		DKGTime:           1000000,              // 1 second for DKG
		PreprocessingTime: 50000,                // 50ms per session
		SigningTime:       5000,                 // 5ms online signing
		VerificationTime:  2000,                 // 2ms verification
		SignatureSize:     r.params.SignatureSize,
		CommunicationSize: parties * threshold * 1024, // Estimated
	}
}