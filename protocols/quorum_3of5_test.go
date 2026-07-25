// SPDX-License-Identifier: BSD-3-Clause

package protocols_test

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"

	decredsecp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/math/sample"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/quorum"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
)

// policy is the custody policy under test: three of five shareholders must
// cooperate to sign, and any two must not be able to.
//
// It is stated once, as a quorum.Policy, and every protocol call below takes
// its degree from policy.Degree(). Writing the degree as a bare literal is
// exactly the mistake this file exists to catch: a "3-of-5" key created at
// degree 3 is a 4-of-5 key, and nothing about it looks wrong until three
// custodians try to sign and cannot.
var policy = quorum.MustNew(3, 5)

// cggmpTimeout bounds the CGGMP21 sessions below. A five-party key
// generation builds a Paillier modulus and its ring-mod proof per party; with
// the race detector on, that runs well past the harness default of five
// minutes. The deadline exists to stop a hung test, not to assert
// performance, so it is set generously.
const cggmpTimeout = 45 * time.Minute

// evmAddress derives the 20-byte EVM account address of a threshold group
// key, the way the EVM itself does: Keccak256 over the 64-byte uncompressed
// public key (X‖Y, no format prefix), low 20 bytes.
//
// curve.Point.MarshalBinary returns the 33-byte COMPRESSED encoding, so the
// point must be decompressed first. Hashing the compressed bytes — or the
// 32-byte X alone — yields a well-formed but entirely wrong address, and
// value sent to it is unspendable. That failure is silent at derivation time,
// which is why the tests below never trust a derived address on its own: each
// one is confirmed by ecrecover on a real signature.
func evmAddress(t testing.TB, pub curve.Point) [20]byte {
	t.Helper()

	compressed, err := pub.MarshalBinary()
	require.NoError(t, err, "marshal group public key")
	require.Len(t, compressed, 33, "curve.Point.MarshalBinary must be the compressed encoding")

	parsed, err := decredsecp.ParsePubKey(compressed)
	require.NoError(t, err, "group public key must be a valid secp256k1 point")

	uncompressed := parsed.SerializeUncompressed() // 0x04 ‖ X(32) ‖ Y(32)
	require.Len(t, uncompressed, 65)

	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:]) // drop the 0x04 prefix: hash X‖Y
	sum := h.Sum(nil)

	var addr [20]byte
	copy(addr[:], sum[12:])
	return addr
}

// recoverAddress performs the operation an EVM node performs on a signature:
// ecrecover to a public key, then Keccak to an address. A signature that
// recovers to the group's address is a signature the Safe contract's
// checkNSignatures will accept for an owner at that address.
func recoverAddress(t testing.TB, digest []byte, sig *ecdsa.Signature) [20]byte {
	t.Helper()

	eth, err := sig.SigEthereum()
	require.NoError(t, err, "SigEthereum")
	require.Len(t, eth, 65, "EVM signature must be R‖S‖V")
	require.LessOrEqual(t, eth[64], byte(1), "recovery id must be 0 or 1")

	compact := make([]byte, 65)
	compact[0] = 27 + eth[64] // decred compact header, uncompressed key
	copy(compact[1:], eth[:64])

	pub, _, err := decredecdsa.RecoverCompact(compact, digest)
	require.NoError(t, err, "ecrecover must succeed on a canonical signature")

	h := sha3.NewLegacyKeccak256()
	h.Write(pub.SerializeUncompressed()[1:])
	sum := h.Sum(nil)

	var addr [20]byte
	copy(addr[:], sum[12:])
	return addr
}

// keygen3of5 runs a real CGGMP21 distributed key generation across all five
// parties at the policy's degree and returns each party's private config plus
// the group public key they all agree on. There is no dealer: no party, and
// no point in this function, ever holds the full secret key.
func keygen3of5(t testing.TB, ids party.IDSlice, pools map[party.ID]*pool.Pool, sessionID string) (map[party.ID]*cmp.Config, curve.Point) {
	t.Helper()

	results, err := test.RunProtocolWithTimeout(t, ids, []byte(sessionID), cggmpTimeout,
		func(id party.ID) protocol.StartFunc {
			return cmp.Keygen(curve.Secp256k1{}, id, ids, policy.Degree(), pools[id])
		})
	require.NoError(t, err, "CGGMP21 DKG at degree %d must complete", policy.Degree())
	require.Len(t, results, policy.N, "every one of the %d parties must receive a share", policy.N)

	configs := make(map[party.ID]*cmp.Config, policy.N)
	var groupKey curve.Point
	for id, r := range results {
		cfg, ok := r.(*cmp.Config)
		require.True(t, ok, "party %s: keygen result is %T, want *cmp.Config", id, r)

		// The stored degree is what a later signing session reads to decide
		// how many signers it needs. If it is not policy.Degree(), the key on
		// disk is not the policy that was requested.
		require.Equal(t, policy.Degree(), cfg.Threshold,
			"party %s: stored degree must be %d for a %s key", id, policy.Degree(), policy)

		readBack, err := quorum.FromDegree(cfg.Threshold, policy.N)
		require.NoError(t, err)
		require.Equal(t, policy, readBack, "party %s: stored key reads back as %s, want %s", id, readBack, policy)

		configs[id] = cfg
		if groupKey == nil {
			groupKey = cfg.PublicPoint()
		} else {
			require.True(t, groupKey.Equal(cfg.PublicPoint()),
				"party %s disagrees on the group public key — the shares are not for one key", id)
		}
	}
	require.NotNil(t, groupKey)
	require.False(t, groupKey.IsIdentity(), "group public key must not be the identity point")
	return configs, groupKey
}

func newPools(t testing.TB, ids party.IDSlice) map[party.ID]*pool.Pool {
	t.Helper()
	pools := make(map[party.ID]*pool.Pool, len(ids))
	for _, id := range ids {
		pools[id] = pool.NewPool(0)
	}
	t.Cleanup(func() {
		for _, pl := range pools {
			pl.TearDown()
		}
	})
	return pools
}

// TestQuorum3of5_CGGMP21_RecoversToGroupAddress is the end-to-end custody
// proof: five parties run a real distributed key generation, three of them
// sign, and the resulting signature ecrecovers to the group's EVM address.
//
// The ecrecover step is the one that matters for a Safe. Verifying the
// signature against the group public key proves the threshold maths is
// right; recovering it to the group ADDRESS proves the EVM will attribute
// that signature to the account the Safe has as an owner. A key can pass the
// first check and fail the second — that is precisely what a mis-derived
// address (compressed point, dropped Y parity, unpadded coordinate) looks
// like, and it is unrecoverable once the Safe is live.
func TestQuorum3of5_CGGMP21_RecoversToGroupAddress(t *testing.T) {
	ids := test.PartyIDs(policy.N)
	pools := newPools(t, ids)

	configs, groupKey := keygen3of5(t, ids, pools, "quorum/3of5/cggmp21/keygen")
	groupAddr := evmAddress(t, groupKey)
	t.Logf("%s CGGMP21 group address: 0x%x", policy, groupAddr)

	digest := make([]byte, 32)
	copy(digest, "lux 3-of-5 cggmp21 custody proof")

	signers := ids[:policy.K]
	sigResults, err := test.RunProtocolWithTimeout(t, signers, []byte("quorum/3of5/cggmp21/sign"), cggmpTimeout,
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(configs[id], signers, digest, pools[id])
		})
	require.NoError(t, err, "%d signers must be able to sign a %s key", len(signers), policy)
	require.Len(t, sigResults, policy.K)

	// Every signer must output the same signature, and it must both verify
	// under the group key and recover to the group address.
	var canonical []byte
	for id, r := range sigResults {
		sig, ok := r.(*ecdsa.Signature)
		require.True(t, ok, "party %s: sign result is %T, want *ecdsa.Signature", id, r)

		require.True(t, sig.Verify(groupKey, digest),
			"party %s: signature must verify under the group public key", id)

		gotAddr := recoverAddress(t, digest, sig)
		require.Equal(t, groupAddr, gotAddr,
			"party %s: signature recovers to 0x%x, want the group address 0x%x", id, gotAddr, groupAddr)

		eth, err := sig.SigEthereum()
		require.NoError(t, err)
		if canonical == nil {
			canonical = eth
		} else {
			require.True(t, bytes.Equal(canonical, eth),
				"party %s produced a different signature — signers must agree byte for byte", id)
		}
	}
}

// TestQuorum3of5_CGGMP21_EverySubsetSignsForOneAddress proves the key is a
// single threshold key rather than a collection of per-subset keys: several
// different 3-party subsets each produce a signature, and all of them recover
// to the same address.
//
// This is the property a Safe owner rotation depends on. The Safe stores one
// owner address; whichever three custodians happen to be available must all
// produce signatures that resolve to that one address.
func TestQuorum3of5_CGGMP21_EverySubsetSignsForOneAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("multiple CGGMP21 signing sessions; skipped under -short")
	}

	ids := test.PartyIDs(policy.N)
	pools := newPools(t, ids)

	configs, groupKey := keygen3of5(t, ids, pools, "quorum/3of5/cggmp21/subsets/keygen")
	groupAddr := evmAddress(t, groupKey)

	digest := make([]byte, 32)
	copy(digest, "one address, any three signers--")

	// Disjoint-as-possible subsets, so no single party is in all of them:
	// every share gets exercised and no party is load-bearing.
	subsets := [][]party.ID{
		{ids[0], ids[1], ids[2]},
		{ids[2], ids[3], ids[4]},
		{ids[0], ids[2], ids[4]},
		{ids[1], ids[3], ids[4]},
	}

	for i, signers := range subsets {
		signers := signers
		name := ""
		for _, id := range signers {
			name += string(id)
		}
		t.Run(name, func(t *testing.T) {
			results, err := test.RunProtocolWithTimeout(t, signers,
				[]byte("quorum/3of5/cggmp21/subsets/sign/"+name), cggmpTimeout,
				func(id party.ID) protocol.StartFunc {
					return cmp.Sign(configs[id], signers, digest, pools[id])
				})
			require.NoError(t, err, "subset %d %v must be able to sign", i, signers)

			for _, r := range results {
				sig := r.(*ecdsa.Signature)
				require.True(t, sig.Verify(groupKey, digest), "subset %v: signature must verify", signers)
				require.Equal(t, groupAddr, recoverAddress(t, digest, sig),
					"subset %v: every 3-of-5 subset must sign for the same address", signers)
			}
		})
	}
}

// TestQuorum3of5_CGGMP21_TwoSignersCannotSign is the negative that gives the
// policy meaning. Two of five must not be able to produce a signature.
//
// The refusal happens before any round runs: cmp.Sign -> sign.StartSign ->
// config.CanSign -> ValidThreshold(t=2, n=2) is false. No partial signature
// is ever emitted, so there is nothing for an attacker holding two shares to
// aggregate offline.
func TestQuorum3of5_CGGMP21_TwoSignersCannotSign(t *testing.T) {
	ids := test.PartyIDs(policy.N)
	pools := newPools(t, ids)

	configs, groupKey := keygen3of5(t, ids, pools, "quorum/3of5/cggmp21/insufficient/keygen")

	digest := make([]byte, 32)
	copy(digest, "two shares must not be enough---")

	// Every 2-party subset, not just the first: a policy that holds for
	// {a,b} but not {d,e} is not a policy.
	for i := 0; i < policy.N; i++ {
		for j := i + 1; j < policy.N; j++ {
			signers := []party.ID{ids[i], ids[j]}
			name := string(ids[i]) + string(ids[j])
			t.Run(name, func(t *testing.T) {
				results, err := test.RunProtocolWithTimeout(t, signers,
					[]byte("quorum/3of5/cggmp21/insufficient/sign/"+name), cggmpTimeout,
					func(id party.ID) protocol.StartFunc {
						return cmp.Sign(configs[id], signers, digest, pools[id])
					})
				require.Error(t, err,
					"%d signers MUST be refused for a %s key", len(signers), policy)

				// Belt and braces: even if some result leaked through, it must
				// not be a signature that verifies.
				for _, r := range results {
					if sig, ok := r.(*ecdsa.Signature); ok && sig != nil {
						require.False(t, sig.Verify(groupKey, digest),
							"subset %v produced a VERIFYING signature below the quorum", signers)
					}
				}
			})
		}
	}
}

// TestQuorum3of5_CGGMP21_ForgedShareCannotSign covers the other way a quorum
// can be faked: the right NUMBER of signers, but one of them holding a share
// it did not receive from the DKG.
//
// Three parties attempt to sign, but one substitutes a random secret share
// for its real one. The session must not yield a signature that verifies
// under the group key. This is what stops an attacker who has compromised two
// genuine shares from making up a third.
func TestQuorum3of5_CGGMP21_ForgedShareCannotSign(t *testing.T) {
	ids := test.PartyIDs(policy.N)
	pools := newPools(t, ids)

	configs, groupKey := keygen3of5(t, ids, pools, "quorum/3of5/cggmp21/forged/keygen")

	digest := make([]byte, 32)
	copy(digest, "a forged third share must fail--")

	signers := ids[:policy.K]

	// Deep-copy the victim's config through its own serialisation, then
	// replace the secret share. Copying is essential: cmp.Config holds
	// pointer-backed curve values, so mutating in place would corrupt the
	// config the honest tests share.
	forger := signers[len(signers)-1]
	raw, err := configs[forger].MarshalBinary()
	require.NoError(t, err)

	tampered := cmp.EmptyConfig(curve.Secp256k1{})
	require.NoError(t, tampered.UnmarshalBinary(raw))
	tampered.ECDSA = sample.Scalar(rand.Reader, curve.Secp256k1{})

	signConfigs := make(map[party.ID]*cmp.Config, len(signers))
	for _, id := range signers {
		signConfigs[id] = configs[id]
	}
	signConfigs[forger] = tampered

	results, err := test.RunProtocolWithTimeout(t, signers, []byte("quorum/3of5/cggmp21/forged/sign"), cggmpTimeout,
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(signConfigs[id], signers, digest, pools[id])
		})

	// CGGMP21 is an identifiable-abort protocol: the expected outcome is that
	// the session errors out. What is NOT acceptable under any circumstance is
	// a signature that verifies under the real group key.
	for id, r := range results {
		sig, ok := r.(*ecdsa.Signature)
		if !ok || sig == nil {
			continue
		}
		require.False(t, sig.Verify(groupKey, digest),
			"party %s accepted a signature built on a forged share — threshold security is broken", id)
	}
	require.Error(t, err, "a signing session containing a forged share must abort")
}

// TestQuorum3of5_FROST_VerifiesUnderGroupKey is the Schnorr/EdDSA half of the
// same claim: a real FROST distributed key generation at the same policy,
// signed by three of five, verifying under the group key — and refused at two.
//
// FROST uses the same degree convention as CGGMP21 (threshold = tolerated
// corruptions, threshold+1 signers required), so policy.Degree() is correct
// for both and there is one place in the codebase that knows why.
func TestQuorum3of5_FROST_VerifiesUnderGroupKey(t *testing.T) {
	ids := test.PartyIDs(policy.N)

	kgResults, err := test.RunProtocol(t, ids, []byte("quorum/3of5/frost/keygen"),
		func(id party.ID) protocol.StartFunc {
			return frost.Keygen(curve.Secp256k1{}, id, ids, policy.Degree())
		})
	require.NoError(t, err, "FROST DKG at degree %d must complete", policy.Degree())
	require.Len(t, kgResults, policy.N)

	configs := make(map[party.ID]*frost.Config, policy.N)
	var groupKey curve.Point
	for id, r := range kgResults {
		cfg, ok := r.(*frost.Config)
		require.True(t, ok, "party %s: keygen result is %T, want *frost.Config", id, r)
		require.Equal(t, policy.Degree(), cfg.Threshold,
			"party %s: stored degree must be %d for a %s key", id, policy.Degree(), policy)
		configs[id] = cfg
		if groupKey == nil {
			groupKey = cfg.PublicKey
		} else {
			require.True(t, groupKey.Equal(cfg.PublicKey),
				"party %s disagrees on the group public key", id)
		}
	}
	require.NotNil(t, groupKey)

	message := []byte("lux 3-of-5 frost custody proof")

	// POSITIVE: three signers produce a signature that verifies.
	signers := ids[:policy.K]
	sigResults, err := test.RunProtocol(t, signers, []byte("quorum/3of5/frost/sign"),
		func(id party.ID) protocol.StartFunc {
			return frost.Sign(configs[id], signers, message)
		})
	require.NoError(t, err, "%d signers must be able to sign a %s FROST key", len(signers), policy)
	for id, r := range sigResults {
		// frost.Sign yields the signature by value, unlike cmp.Sign.
		sig, ok := r.(frost.Signature)
		require.True(t, ok, "party %s: sign result is %T, want frost.Signature", id, r)
		require.True(t, sig.Verify(groupKey, message),
			"party %s: FROST signature must verify under the group public key", id)
	}

	// NEGATIVE: two signers must not.
	twoSigners := ids[:policy.K-1]
	negResults, negErr := test.RunProtocol(t, twoSigners, []byte("quorum/3of5/frost/sign-2"),
		func(id party.ID) protocol.StartFunc {
			return frost.Sign(configs[id], twoSigners, message)
		})
	for _, r := range negResults {
		if sig, ok := r.(frost.Signature); ok {
			require.False(t, sig.Verify(groupKey, message),
				"a %d-signer FROST session produced a VERIFYING signature below the quorum", len(twoSigners))
		}
	}
	require.Error(t, negErr, "%d signers MUST be refused for a %s FROST key", len(twoSigners), policy)
}
