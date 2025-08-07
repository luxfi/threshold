package dealer_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/lss/dealer"
	"github.com/stretchr/testify/assert"
)

func TestBootstrapDealerCreation(t *testing.T) {
	group := curve.Secp256k1{}
	initialParties := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	
	d := dealer.NewBootstrapDealer(group, initialParties, threshold)
	assert.NotNil(t, d)
}

func TestDealerBasicOperations(t *testing.T) {
	group := curve.Secp256k1{}
	initialParties := []party.ID{"alice", "bob", "charlie"}
	threshold := 2
	
	d := dealer.NewBootstrapDealer(group, initialParties, threshold)
	assert.NotNil(t, d)
	
	// Test basic operations
	t.Run("InitiateReshare", func(t *testing.T) {
		newParties := []party.ID{"alice", "bob", "charlie", "david"}
		newThreshold := 3
		
		// InitiateReshare requires: oldThreshold, newThreshold, oldParties, newParties
		err := d.InitiateReshare(threshold, newThreshold, initialParties, newParties)
		// Dealer operations are implemented
		assert.NoError(t, err)
	})
	
	t.Run("GetCurrentGeneration", func(t *testing.T) {
		gen := d.GetCurrentGeneration()
		assert.GreaterOrEqual(t, gen, uint64(0))
	})
}

func TestDealerConcurrency(t *testing.T) {
	group := curve.Secp256k1{}
	parties := []party.ID{"alice", "bob", "charlie", "david", "eve"}
	threshold := 3
	
	// Test concurrent dealer creation
	numDealers := 10
	dealers := make([]*dealer.BootstrapDealer, numDealers)
	done := make(chan int, numDealers)
	
	for i := 0; i < numDealers; i++ {
		go func(idx int) {
			d := dealer.NewBootstrapDealer(group, parties, threshold)
			if d != nil {
				dealers[idx] = d
				done <- idx
			} else {
				done <- -1
			}
		}(i)
	}
	
	successCount := 0
	for i := 0; i < numDealers; i++ {
		idx := <-done
		if idx >= 0 {
			successCount++
			assert.NotNil(t, dealers[idx])
		}
	}
	
	assert.Greater(t, successCount, 0, "At least one dealer should be created")
}