package lss_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/lss"
)

func ExampleSuite() {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Auto-select protocol based on signature needs
	factory := lss.NewFactory(pl)
	
	// Need ECDSA? Automatically uses CMP
	ecdsaSuite := factory.Auto(protocol.ECDSA)
	_ = ecdsaSuite
	
	// Need Schnorr? Automatically uses FROST  
	schnorrSuite := factory.Auto(protocol.Schnorr)
	_ = schnorrSuite
	
	// Or explicitly choose
	cmpSuite := lss.WithCMP(pl)
	frostSuite := lss.WithFROST(pl)
	
	// All suites have the same interface
	_ = cmpSuite
	_ = frostSuite
}

func TestSuiteSimple(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	
	// Create a suite with CMP backend
	suite := lss.WithCMP(pl)
	
	// Generate keys (would need proper network in real usage)
	group := curve.Secp256k1{}
	parties := []party.ID{"alice", "bob", "charlie"}
	keygen := suite.Keygen(group, "alice", parties, 2)
	
	// The keygen function is ready to use with protocol handlers
	_ = keygen
	
	// No ugly conversions needed!
}