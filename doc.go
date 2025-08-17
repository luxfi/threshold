// Package threshold provides a threshold signature library implementation
// supporting multiple signature schemes including ECDSA, EdDSA, and Schnorr.
//
// The library implements several threshold signature protocols:
//   - CMP: Canetti-Makriyannis-Pagourtzis protocol for ECDSA
//   - FROST: Flexible Round-Optimized Schnorr Threshold signatures
//   - Doerner: Doerner-Shelat protocol for EdDSA
//   - LSS: Linear Secret Sharing based threshold signatures
//
// This is the root package documentation. The actual implementation
// is organized in subpackages under pkg/ and protocols/.
package threshold
