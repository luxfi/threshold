// Package ringtail implements a post-quantum lattice-based threshold signature scheme.
//
// Ringtail provides quantum-resistant threshold signatures using lattice cryptography,
// specifically designed for high-security applications requiring protection against
// quantum computer attacks.
//
// The protocol supports:
//   - (t,n)-threshold signatures where t parties can sign
//   - Post-quantum security based on Module-LWE hardness
//   - Efficient key generation and signing
//   - Share refresh for proactive security
//   - Compatible with Lux's threshold infrastructure
package ringtail

import (
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/ringtail/config"
	"github.com/luxfi/threshold/protocols/ringtail/keygen"
	"github.com/luxfi/threshold/protocols/ringtail/refresh"
	"github.com/luxfi/threshold/protocols/ringtail/sign"
)

// Config holds the configuration for a Ringtail threshold signing participant
type Config = config.Config

// Keygen initiates the Ringtail threshold key generation protocol.
//
// This creates a new lattice-based key pair with the private key shared
// among n participants such that any t of them can collaborate to sign.
func Keygen(selfID party.ID, participants []party.ID, threshold int, pl *pool.Pool) protocol.StartFunc {
	return keygen.Start(selfID, participants, threshold, pl)
}

// Sign initiates the Ringtail threshold signing protocol.
//
// Given a message and a set of signers (at least threshold many),
// this produces a valid Ringtail signature.
func Sign(config *Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return sign.Start(config, signers, message, pl)
}

// Refresh initiates the share refresh protocol.
//
// This updates all shares while maintaining the same public key,
// providing proactive security against gradual key compromise.
func Refresh(config *Config, participants []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc {
	return refresh.Start(config, participants, newThreshold, pl)
}

// VerifySignature verifies a Ringtail signature against a public key and message.
//
// This is a standalone verification that doesn't require threshold participation.
func VerifySignature(publicKey []byte, message []byte, signature []byte) bool {
	return config.VerifySignature(publicKey, message, signature)
}
