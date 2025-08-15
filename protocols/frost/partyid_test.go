package frost_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/polynomial"
	"github.com/stretchr/testify/require"
)

// TestPartyIDScalars tests how party IDs are converted to scalars
func TestPartyIDScalars(t *testing.T) {
	group := curve.Secp256k1{}
	n := 5
	partyIDs := test.PartyIDs(n)

	t.Logf("Party IDs: %v", partyIDs)

	// Check the scalar values for each party ID
	for _, id := range partyIDs {
		scalar := id.Scalar(group)
		t.Logf("ID %s -> scalar: %v", id, scalar)
	}

	// Test Lagrange coefficients for subset
	subset := partyIDs[:3] // [a, b, c]
	t.Logf("\nComputing Lagrange coefficients for subset: %v", subset)

	lambdas := polynomial.Lagrange(group, subset)
	for _, id := range subset {
		t.Logf("Lambda[%s] = %v", id, lambdas[id])
	}

	// Manual computation of Lagrange coefficients for verification
	// For parties with IDs a=0x61, b=0x62, c=0x63
	// The Lagrange coefficient for party i at x=0 is:
	// λᵢ = ∏(j≠i) (0 - xⱼ) / (xᵢ - xⱼ)

	t.Logf("\nManual verification:")
	a := partyIDs[0].Scalar(group) // 'a' = 0x61 = 97
	b := partyIDs[1].Scalar(group) // 'b' = 0x62 = 98
	c := partyIDs[2].Scalar(group) // 'c' = 0x63 = 99

	// Lambda for 'a': (0-b)*(0-c) / ((a-b)*(a-c))
	// = b*c / ((a-b)*(a-c))
	// = 98*99 / ((-1)*(-2)) = 9702 / 2 = 4851
	numerA := group.NewScalar().Set(b).Mul(c)
	denomA := group.NewScalar().Set(a).Sub(b)
	temp := group.NewScalar().Set(a).Sub(c)
	denomA.Mul(temp)
	lambdaA := group.NewScalar().Set(numerA).Mul(denomA.Invert())
	t.Logf("Manual λ[a] = %v", lambdaA)
	require.True(t, lambdaA.Equal(lambdas[partyIDs[0]]), "Lambda[a] mismatch")

	// Lambda for 'b': (0-a)*(0-c) / ((b-a)*(b-c))
	// = a*c / ((b-a)*(b-c))
	// = 97*99 / (1*(-1)) = 9603 / (-1) = -9603
	numerB := group.NewScalar().Set(a).Mul(c)
	denomB := group.NewScalar().Set(b).Sub(a)
	temp = group.NewScalar().Set(b).Sub(c)
	denomB.Mul(temp)
	lambdaB := group.NewScalar().Set(numerB).Mul(denomB.Invert())
	t.Logf("Manual λ[b] = %v", lambdaB)
	require.True(t, lambdaB.Equal(lambdas[partyIDs[1]]), "Lambda[b] mismatch")

	// Lambda for 'c': (0-a)*(0-b) / ((c-a)*(c-b))
	// = a*b / ((c-a)*(c-b))
	// = 97*98 / (2*1) = 9506 / 2 = 4753
	numerC := group.NewScalar().Set(a).Mul(b)
	denomC := group.NewScalar().Set(c).Sub(a)
	temp = group.NewScalar().Set(c).Sub(b)
	denomC.Mul(temp)
	lambdaC := group.NewScalar().Set(numerC).Mul(denomC.Invert())
	t.Logf("Manual λ[c] = %v", lambdaC)
	require.True(t, lambdaC.Equal(lambdas[partyIDs[2]]), "Lambda[c] mismatch")

	// Verify that sum of lambdas equals 1 (at x=0)
	sum := group.NewScalar()
	for _, id := range subset {
		sum.Add(lambdas[id])
	}
	one := group.NewScalar()
	one.SetNat(new(saferith.Nat).SetUint64(1))
	t.Logf("\nSum of lambdas = %v (should be 1)", sum)
	require.True(t, sum.Equal(one), "Sum of Lagrange coefficients should be 1")
}
