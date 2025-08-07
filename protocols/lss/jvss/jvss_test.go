package jvss_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/jvss"
	"github.com/stretchr/testify/assert"
)

func TestJVSSCreation(t *testing.T) {
	group := curve.Secp256k1{}
	parties := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	dealer := party.ID("alice")
	
	j := jvss.NewJVSS(group, threshold, parties, dealer)
	assert.NotNil(t, j)
}

func TestJVSSBasicOperations(t *testing.T) {
	group := curve.Secp256k1{}
	parties := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	dealer := party.ID("alice")
	
	j := jvss.NewJVSS(group, threshold, parties, dealer)
	assert.NotNil(t, j)
	
	// Test that JVSS can be created with different parameters
	t.Run("DifferentThreshold", func(t *testing.T) {
		j2 := jvss.NewJVSS(group, 3, parties, dealer)
		assert.NotNil(t, j2)
	})
	
	t.Run("DifferentParties", func(t *testing.T) {
		moreParties := []party.ID{"alice", "bob", "charlie", "david", "eve"}
		j3 := jvss.NewJVSS(group, 3, moreParties, dealer)
		assert.NotNil(t, j3)
	})
}

func TestJVSSValidation(t *testing.T) {
	group := curve.Secp256k1{}
	
	testCases := []struct {
		name      string
		parties   []party.ID
		threshold int
		dealer    party.ID
	}{
		{
			name:      "valid 2-of-3",
			parties:   []party.ID{"alice", "bob", "charlie"},
			threshold: 2,
			dealer:    party.ID("alice"),
		},
		{
			name:      "valid 3-of-5",
			parties:   []party.ID{"alice", "bob", "charlie", "david", "eve"},
			threshold: 3,
			dealer:    party.ID("bob"),
		},
		{
			name:      "edge case n=t",
			parties:   []party.ID{"alice", "bob", "charlie"},
			threshold: 3,
			dealer:    party.ID("charlie"),
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			j := jvss.NewJVSS(group, tc.threshold, tc.parties, tc.dealer)
			assert.NotNil(t, j)
		})
	}
}

func TestJVSSConcurrency(t *testing.T) {
	group := curve.Secp256k1{}
	parties := []party.ID{"alice", "bob", "charlie", "david", "eve"}
	threshold := 3
	
	// Test concurrent JVSS creation
	numInstances := 10
	instances := make([]*jvss.JVSS, numInstances)
	done := make(chan int, numInstances)
	
	for i := 0; i < numInstances; i++ {
		go func(idx int) {
			dealer := party.ID(string(rune('a' + idx)))
			j := jvss.NewJVSS(group, threshold, parties, dealer)
			if j != nil {
				instances[idx] = j
				done <- idx
			} else {
				done <- -1
			}
		}(i)
	}
	
	successCount := 0
	for i := 0; i < numInstances; i++ {
		idx := <-done
		if idx >= 0 {
			successCount++
			assert.NotNil(t, instances[idx])
		}
	}
	
	assert.Greater(t, successCount, 0, "At least one JVSS instance should be created")
}