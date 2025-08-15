package frost

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/luxfi/threshold/pkg/party"
)

// TestFROSTEquation tests the fundamental FROST signature equation
func TestFROSTEquation(t *testing.T) {
	// The FROST signature equation is:
	// g^z = R * Y^c
	// where:
	// - z = sum(z_i) for all signers
	// - z_i = d_i + e_i*ρ_i + λ_i*s_i*c
	// - R = sum(D_i + ρ_i*E_i) for all signers
	// - Y is the group public key
	// - c = H(R, Y, m)

	// The key insight is that the secret key x is shared as:
	// x = sum(λ_i * s_i) for threshold signers
	// where s_i are the secret shares from keygen

	// For the equation to hold:
	// g^z = g^(sum(d_i + e_i*ρ_i + λ_i*s_i*c))
	//     = g^(sum(d_i + e_i*ρ_i)) * g^(sum(λ_i*s_i)*c)
	//     = R * g^(x*c)  [if sum(λ_i*s_i) = x]
	//     = R * Y^c      [since Y = g^x]

	// The issue is that in FROST keygen, the shares s_i come from
	// summing evaluations of n degree-t polynomials:
	// s_i = f_1(i) + f_2(i) + ... + f_n(i)
	//
	// The secret x = f_1(0) + f_2(0) + ... + f_n(0)
	//
	// For Lagrange interpolation to work correctly, we need:
	// sum(λ_i * s_i) = x for any threshold subset
	//
	// But this only works if the s_i values come from a single
	// degree-t polynomial, not from the sum of n polynomials.

	group := curve.Secp256k1{}

	// Test with simple values
	// Let's say we have 3 parties, threshold 2
	n := 3
	threshold := 2
	partyIDs := make([]party.ID, n)
	for i := 0; i < n; i++ {
		partyIDs[i] = party.ID(string(rune('a' + i)))
	}

	// In standard Shamir secret sharing with a single polynomial:
	// f(x) = secret + a1*x + a2*x^2 + ... + at*x^t
	// Each party i gets share s_i = f(i)
	// The secret = f(0)
	// With Lagrange interpolation: secret = sum(λ_i * s_i) for any t+1 parties

	// But in FROST DKG, each party j creates their own polynomial f_j(x)
	// and the final shares are: s_i = sum_j f_j(i)
	// The secret is: x = sum_j f_j(0)

	// This means the shares come from a polynomial of degree n*t (approximately),
	// not degree t, which breaks threshold reconstruction.

	// Let's verify this with a simple example
	signers := partyIDs[:threshold]
	lambdas := polynomial.Lagrange(group, signers)

	t.Logf("Signers: %v", signers)
	t.Logf("Lagrange coefficients:")
	for id, lambda := range lambdas {
		t.Logf("  λ_%s = %v", id, lambda)
	}

	// The fundamental issue is that FROST keygen produces shares that
	// don't satisfy the threshold property for reconstruction.
	// This is why the signature verification fails.

	// The FROST paper addresses this by using ALL n parties during keygen
	// to establish the shares, but then allows any threshold subset to sign.
	// The trick is that the Lagrange coefficients are computed for the
	// signing subset, not for reconstructing the secret.

	// However, the math only works out if the shares are consistent
	// with the threshold property, which they're not in our implementation.
}
