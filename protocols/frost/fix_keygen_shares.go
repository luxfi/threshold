package frost

// The issue with verification shares in FROST keygen:
//
// Current implementation computes Y_i = F(i)*G where F = sum of all n polynomials.
// This creates shares from a degree n*t polynomial, which cannot reconstruct
// the public key using only t shares.
//
// The FROST paper says:
// - Each party computes Y_i = s_i * G (their verification share)
// - s_i = sum of shares received from all parties
// - Any party can compute Y_i for another party using the public polynomials
//
// The problem is that the paper's formula for computing Y_i from public polynomials
// (Y_i = ∑ⱼ₌₁ⁿ ∑ₖ₌₀ᵗ (iᵏ mod q) * ϕⱼₖ) produces shares from a high-degree polynomial.
//
// For threshold signing to work, we need Y_i such that:
// - Y = ∑ᵢ λᵢ * Y_i (for any threshold subset)
// - This requires Y_i to be shares of a degree-t polynomial
//
// The solution is to ensure verification shares Y_i = s_i * G where s_i are
// proper Shamir shares of the secret key. This means the secret polynomial
// must have degree t, not n*t.
//
// In the current implementation, each party generates a degree-t polynomial,
// and the final shares are sums of evaluations from all n polynomials.
// This creates shares from a polynomial of degree n*t.
//
// To fix this, we need to ensure that the combined polynomial has degree t.
// This can be done by having only one party generate the main polynomial,
// or by carefully coordinating the polynomial generation.
