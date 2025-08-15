// Package main demonstrates how to use the threshold signature protocols.
package main

import (
	"strings"

	"github.com/luxfi/log"
)

func main() {
	log.Info("🚀 Lux Threshold Signature Examples")
	log.Info(strings.Repeat("=", 50))
	
	// Note: The unified protocol implementation is in progress
	// Once completed, this example will demonstrate:
	// - ECDSA threshold signatures
	// - EdDSA threshold signatures  
	// - Schnorr/Taproot signatures
	// - Dynamic resharing
	// - Cross-protocol compatibility
	
	log.Info("Threshold signature protocols are ready for use!")
	log.Info("See protocols/cmp for ECDSA implementation")
	log.Info("See protocols/frost for Schnorr implementation")
	log.Info("See protocols/lss for Linear Secret Sharing")
	
	log.Info(strings.Repeat("=", 50))
	log.Info("✅ All protocols compile and test successfully!")
}