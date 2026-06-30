// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package pulsar re-exports github.com/luxfi/pulsar/pkg/pulsar
// through the threshold/protocols alias surface. Downstream consumers
// (luxfi/consensus) target this import path so the consensus engine
// does not depend directly on the pulsar reference-implementation
// module.
//
// The Pulsar headline claim: a signature produced by an n-of-t
// threshold ceremony verifies under unmodified FIPS 204 ML-DSA.Verify
// (NIST MPTC Category N1). See the upstream package's spec for the
// formal claim and the byte-equality reductions.
//
// Layering shape:
//
//	consensus → threshold/protocols/pulsar  ← stable alias surface
//	              ↓
//	         luxfi/pulsar/pkg/pulsar  ← reference math kernel
//
// The re-exports here are type aliases and thin function forwards; no
// behaviour change. The set of re-exports covers identity, DKG,
// single-party sign/verify, and parameter surfaces.
//
// H-1 (reconstruct-then-sign rip): the v0.1 threshold-signing re-exports
// — ThresholdSigner / NewThresholdSigner / Combine and the Round1Message
// / Round2Message wire types — were REMOVED. That path reconstructed the
// full ML-DSA signing key in aggregator memory; its only consumer was
// consensus's quasar wave-signer, which is deleted. Threshold signing on
// the live consensus path runs through the corona dealerless kernel
// (protocols/corona), not this alias. Do NOT re-add a reconstruct-then-
// sign forward here. Adding non-reconstruct symbols is allowed when a new
// consumer needs them; removing or renaming is a breaking change.
package pulsar

import (
	"io"

	"github.com/luxfi/pulsar/pkg/pulsar"
)

// ---------------------------------------------------------------------
// Parameter set: NIST FIPS 204 ML-DSA modes.
// ---------------------------------------------------------------------

// Mode is the ML-DSA parameter set identifier (FIPS 204 §4 Table 1).
// Aliased to the kernel type so constants below retain their typed
// identity across the alias boundary.
type Mode = pulsar.Mode

const (
	// ModeUnspecified rejects every operation; included so the zero
	// value of Mode does not silently map to a real parameter set.
	ModeUnspecified = pulsar.ModeUnspecified

	// ModeP44 targets FIPS 204 ML-DSA-44 (NIST PQ Category 2).
	ModeP44 = pulsar.ModeP44

	// ModeP65 targets FIPS 204 ML-DSA-65 (NIST PQ Category 3).
	// This is the Lux-default identity / threshold mode.
	ModeP65 = pulsar.ModeP65

	// ModeP87 targets FIPS 204 ML-DSA-87 (NIST PQ Category 5).
	ModeP87 = pulsar.ModeP87
)

// Params bundles the lattice / sampler / wire parameters for one
// FIPS 204 mode. Aliased to the kernel type.
type Params = pulsar.Params

// ParamsP44 / P65 / P87 are the pre-built parameter blocks. Aliased
// to the kernel singletons so they retain pointer identity across the
// alias boundary (downstream callers that compare *Params by pointer
// for cache-keying see the same pointer either way).
var (
	ParamsP44 = pulsar.ParamsP44
	ParamsP65 = pulsar.ParamsP65
	ParamsP87 = pulsar.ParamsP87
)

// ParamsFor returns the parameter block for a Mode. Returns an error
// for ModeUnspecified or an unrecognised mode.
func ParamsFor(mode Mode) (*Params, error) {
	return pulsar.ParamsFor(mode)
}

// MustParamsFor panics on an unrecognised mode; for test code only.
func MustParamsFor(mode Mode) *Params {
	return pulsar.MustParamsFor(mode)
}

// ---------------------------------------------------------------------
// Keys, shares, signatures, transcript types.
// ---------------------------------------------------------------------

// NodeID is the 32-byte party identifier the kernel uses across
// identity / DKG / signing protocols.
type NodeID = pulsar.NodeID

// PublicKey, PrivateKey, KeyShare, Signature are the wire types
// for FIPS-204-byte-equal signing under a Pulsar group key.
type (
	PublicKey  = pulsar.PublicKey
	PrivateKey = pulsar.PrivateKey
	KeyShare   = pulsar.KeyShare
	Signature  = pulsar.Signature
)

// ---------------------------------------------------------------------
// Identity layer: long-term keys, directory, session derivation.
// ---------------------------------------------------------------------

// IdentityKey and IdentityPublicKey are the long-term keypair types
// each party holds across DKG / signing sessions.
type (
	IdentityKey       = pulsar.IdentityKey
	IdentityPublicKey = pulsar.IdentityPublicKey
)

// IdentityDirectory maps NodeID to the long-term public identity key
// of that party. Returned by NewIdentityDirectory.
type IdentityDirectory = pulsar.IdentityDirectory

// GenerateIdentity samples a fresh long-term identity keypair.
func GenerateIdentity(rng io.Reader) (*IdentityKey, error) {
	return pulsar.GenerateIdentity(rng)
}

// NewIdentityDirectory wraps a NodeID → IdentityPublicKey map in the
// kernel's IdentityDirectory type (with the canonical ordering
// invariants the kernel relies on).
func NewIdentityDirectory(entries map[NodeID]*IdentityPublicKey) (IdentityDirectory, error) {
	return pulsar.NewIdentityDirectory(entries)
}

// SymmetricSession derives the pairwise 32-byte symmetric session key
// that the two-round threshold protocol uses for envelope MACing.
func SymmetricSession(
	a NodeID, ikA *IdentityKey,
	b NodeID, ikB *IdentityKey,
	sessionID [16]byte, transcript []byte,
) ([32]byte, error) {
	return pulsar.SymmetricSession(a, ikA, b, ikB, sessionID, transcript)
}

// ---------------------------------------------------------------------
// DKG: Pedersen DKG over R_q^k, three-round protocol.
// ---------------------------------------------------------------------

// DKGSession drives one party's role in the three-round DKG protocol.
type DKGSession = pulsar.DKGSession

// DKGRound1Msg / DKGRound2Msg / DKGOutput are the wire and result
// types of the DKG protocol.
type (
	DKGRound1Msg = pulsar.DKGRound1Msg
	DKGRound2Msg = pulsar.DKGRound2Msg
	DKGOutput    = pulsar.DKGOutput
)

// NewDKGSession constructs a DKGSession pinned to a committee and
// threshold, with the calling party's NodeID and long-term identity
// key. The IdentityDirectory must contain a public key for every
// member of the committee.
func NewDKGSession(
	params *Params,
	committee []NodeID,
	threshold int,
	self NodeID,
	identity *IdentityKey,
	directory IdentityDirectory,
	rng io.Reader,
) (*DKGSession, error) {
	return pulsar.NewDKGSession(params, committee, threshold, self, identity, directory, rng)
}

// ---------------------------------------------------------------------
// Single-party signing and verification (FIPS 204 baseline path).
// ---------------------------------------------------------------------

// GenerateKey samples a single-party FIPS 204 keypair for the given
// parameter block.
func GenerateKey(params *Params, rng io.Reader) (*PrivateKey, error) {
	return pulsar.GenerateKey(params, rng)
}

// Sign produces a single-party FIPS 204 signature under sk over
// message with optional context ctx.
func Sign(params *Params, sk *PrivateKey, message, ctx []byte, randomized bool, rng io.Reader) (*Signature, error) {
	return pulsar.Sign(params, sk, message, ctx, randomized, rng)
}

// VerifyCtx verifies a signature under groupPubkey over message with
// context ctx. The Pulsar Class N1 claim: output is byte-equal to a
// single-party FIPS 204 signature, so this verifier is the canonical
// FIPS 204 ML-DSA.Verify.
func VerifyCtx(params *Params, groupPubkey *PublicKey, message, ctx []byte, sig *Signature) error {
	return pulsar.VerifyCtx(params, groupPubkey, message, ctx, sig)
}
