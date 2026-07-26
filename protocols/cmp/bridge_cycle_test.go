// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cmp_test

// bridge_cycle_test.go — end-to-end proof of the native B/M-chain bridge seam.
//
// This test proves the ONE cycle the universal on-chain bridge turns on, using
// the SAME luxfi/threshold primitive that both native VMs consume:
//
//	user → B.lock(source) → M.attest(threshold-sig) → B.mint(dest)
//
// Roles (decomplected — "one way, on-chain, decentralized by consensus"):
//   - M-Chain (mpcvm) OWNS the key + the signature. A threshold committee runs
//     DKG once; no single node ever holds the group secret. To authorise a
//     transfer, a T+1 quorum threshold-signs the transfer's domain-bound digest.
//     That signature IS the attestation.
//   - B-Chain (bridgevm) OWNS what a bridge message MEANS. It commits to a
//     transfer on lock, and mints/releases on the destination ONLY when M's
//     attestation verifies against the published group key. B calls no signer
//     and holds no share — it verifies inline (the threshold ECDSA signature is
//     indistinguishable from a single-key secp256k1 sig, so any holder of the
//     group key verifies it with zero interaction).
//   - threshold is the shared LIBRARY (this package) — a value, not a chain.
//
// What this proves with REAL crypto (not a mock): a real 3-of-5 CGGMP21 DKG +
// threshold signature authorises exactly one mint of exactly one amount to
// exactly one recipient, conservation holds (locked == minted), and any
// tampering (inflated amount, redirected recipient, replayed nonce) fails the
// gate so B refuses to mint. This is the seam bridgevm.Block.Verify already
// implements (sig.Verify(groupKey, requestHash)) and mpcvm.RequestSignature
// already produces — exercised here through the library's in-process transport.

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/ecdsa"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/stretchr/testify/require"
)

// bridgeTransfer is the domain-bound message B commits to on lock and M signs
// as its attestation. Binding both chain IDs, the asset, the amount, the
// recipient and a nonce means one signature authorises one mint — of that
// amount, to that recipient, on that route — and nothing else. This mirrors the
// preimage bridgevm hashes (chains/bridgevm/block.go computeRequestHash) and the
// message mpcvm signs (chains/mpcvm RequestSignature).
type bridgeTransfer struct {
	SrcChainID uint32   // source network (e.g. Lux C-Chain 96369)
	DstChainID uint32   // destination network (e.g. Zoo EVM 200200)
	Asset      [32]byte // canonical asset id
	Amount     uint64   // units locked on source == units minted on dest
	Recipient  [20]byte // dest recipient (20-byte account/EVM address)
	Nonce      uint64   // per-route monotonic nonce → replay protection
}

// digest is the canonical, domain-separated signing preimage. The domain tag
// ensures a bridge-transfer attestation can never be replayed as any other
// message M signs (oracle writes, session-complete, epoch beacons, ...).
func (t bridgeTransfer) digest() []byte {
	h := sha256.New()
	h.Write([]byte("LUX_BRIDGE_TRANSFER_v1")) // domain separation
	var b [8]byte
	binary.BigEndian.PutUint32(b[:4], t.SrcChainID)
	h.Write(b[:4])
	binary.BigEndian.PutUint32(b[:4], t.DstChainID)
	h.Write(b[:4])
	h.Write(t.Asset[:])
	binary.BigEndian.PutUint64(b[:], t.Amount)
	h.Write(b[:])
	h.Write(t.Recipient[:])
	binary.BigEndian.PutUint64(b[:], t.Nonce)
	h.Write(b[:])
	return h.Sum(nil)
}

// mChain models the M-Chain (mpcvm) threshold committee: it holds a per-party
// key share from one DKG and can produce a threshold attestation over a digest.
type mChain struct {
	partyIDs party.IDSlice
	configs  map[party.ID]*cmp.Config
	pools    map[party.ID]*pool.Pool
	groupKey curve.Point // the published bridge signing key
	T        int         // threshold: any T+1 parties can attest
}

// dkg runs a real CGGMP21 distributed key generation across n parties. The
// returned mChain holds each party's share; the group key is published for B to
// verify against. No single party ever holds the secret.
func dkg(t *testing.T, n, threshold int) *mChain {
	t.Helper()
	ids := test.PartyIDs(n)
	pools := make(map[party.ID]*pool.Pool, n)
	for _, id := range ids {
		pools[id] = pool.NewPool(0)
	}
	results, err := test.RunProtocol(t, ids, []byte("mchain/bridge/keygen"),
		func(id party.ID) protocol.StartFunc {
			return cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pools[id])
		})
	require.NoError(t, err, "M-Chain DKG must complete")
	require.Len(t, results, n, "every party gets a share")

	configs := make(map[party.ID]*cmp.Config, n)
	var groupKey curve.Point
	for id, r := range results {
		cfg, ok := r.(*cmp.Config)
		require.True(t, ok, "DKG result is a cmp.Config")
		configs[id] = cfg
		if groupKey == nil {
			groupKey = cfg.PublicPoint()
		} else {
			require.True(t, groupKey.Equal(cfg.PublicPoint()),
				"all parties agree on one group key")
		}
	}
	require.NotNil(t, groupKey)
	return &mChain{partyIDs: ids, configs: configs, pools: pools, groupKey: groupKey, T: threshold}
}

func (m *mChain) teardown() {
	for _, pl := range m.pools {
		pl.TearDown()
	}
}

// attest is the M-Chain operation: a T+1 quorum threshold-signs the transfer's
// digest. The result is a standard secp256k1 ECDSA signature over the domain-
// bound message — the bridge attestation.
func (m *mChain) attest(t *testing.T, xfer bridgeTransfer) *ecdsa.Signature {
	t.Helper()
	signers := m.partyIDs[:m.T+1] // a real threshold quorum (T+1 of N)
	digest := xfer.digest()
	results, err := test.RunProtocol(t, signers, []byte("mchain/bridge/sign"),
		func(id party.ID) protocol.StartFunc {
			return cmp.Sign(m.configs[id], signers, digest, m.pools[id])
		})
	require.NoError(t, err, "M-Chain threshold sign must complete")
	for _, r := range results {
		sig, ok := r.(*ecdsa.Signature)
		require.True(t, ok, "sign result is an ecdsa.Signature")
		return sig // all signers converge on the same signature
	}
	t.Fatal("no attestation produced")
	return nil
}

// bChain models the B-Chain (bridgevm) settlement side: a locked ledger, a
// minted ledger, and a spent-nonce set. It holds M's published group key and
// verifies attestations inline — it never calls M and never holds a share.
type bChain struct {
	groupKey curve.Point
	locked   map[[32]byte]uint64 // asset -> units custodied on source
	minted   map[[32]byte]uint64 // asset -> units released on dest
	spent    map[uint64]bool     // nonce -> already settled (replay guard)
}

func newBChain(groupKey curve.Point) *bChain {
	return &bChain{
		groupKey: groupKey,
		locked:   map[[32]byte]uint64{},
		minted:   map[[32]byte]uint64{},
		spent:    map[uint64]bool{},
	}
}

// lock records custody of the source asset (the deposit leg). Returns the
// transfer that M must attest before B will mint.
func (b *bChain) lock(xfer bridgeTransfer) {
	b.locked[xfer.Asset] += xfer.Amount
}

// mintOnAttestation is B's gate: it mints on the destination ONLY if M's
// attestation verifies against the group key over THIS exact transfer, and the
// nonce has not been settled before. Returns whether the mint was authorised.
func (b *bChain) mintOnAttestation(xfer bridgeTransfer, att *ecdsa.Signature) bool {
	if b.spent[xfer.Nonce] {
		return false // replay: this route+nonce already settled
	}
	if !att.Verify(b.groupKey, xfer.digest()) {
		return false // attestation does not authorise THIS message → refuse
	}
	b.minted[xfer.Asset] += xfer.Amount
	b.spent[xfer.Nonce] = true
	return true
}

// TestNativeBridgeLockAttestMintCycle proves the full native cycle end-to-end
// with real threshold crypto: 3-of-5 DKG, a threshold attestation over a
// domain-bound transfer, B's inline-verify mint gate, conservation, and the
// gate rejecting every tampering / replay.
func TestNativeBridgeLockAttestMintCycle(t *testing.T) {
	if testing.Short() {
		t.Skip("threshold DKG is slow; skipped in -short")
	}
	const N, T = 5, 2 // 5 M-Chain signer nodes; any T+1 = 3 form a quorum

	// --- M-Chain: one DKG produces the decentralised bridge key ---
	m := dkg(t, N, T)
	defer m.teardown()

	// --- B-Chain: holds only M's published group key ---
	b := newBChain(m.groupKey)

	// The transfer: 1,000,000 units of LUX, Lux C-Chain -> Zoo EVM, to treasury.
	xfer := bridgeTransfer{
		SrcChainID: 96369,
		DstChainID: 200200,
		Asset:      sha256.Sum256([]byte("LUX")),
		Amount:     1_000_000,
		Recipient: [20]byte{0x90, 0x11, 0xE8, 0x88, 0x25, 0x1A, 0xB0, 0x53, 0xB7, 0xBD,
			0x1C, 0xDB, 0x59, 0x8D, 0xB4, 0xF9, 0xDE, 0xD9, 0x47, 0x14},
		Nonce: 1,
	}

	// --- 1) LOCK on source ---
	b.lock(xfer)
	require.Equal(t, uint64(1_000_000), b.locked[xfer.Asset], "source custody recorded")
	require.Zero(t, b.minted[xfer.Asset], "nothing minted before attestation")

	// --- 2) ATTEST: M threshold-signs the transfer digest ---
	att := m.attest(t, xfer)
	require.NotNil(t, att)
	// The attestation is inline-verifiable by anyone holding the group key —
	// this is the "B calls no signer" property that makes the seam minimal.
	require.True(t, att.Verify(m.groupKey, xfer.digest()),
		"M's attestation verifies against the published group key")

	// --- 3) MINT on dest, gated on the attestation ---
	require.True(t, b.mintOnAttestation(xfer, att), "valid attestation authorises the mint")

	// --- 4) CONSERVATION: exactly what was locked was minted, once ---
	require.Equal(t, b.locked[xfer.Asset], b.minted[xfer.Asset],
		"conservation: locked == minted")
	require.Equal(t, uint64(1_000_000), b.minted[xfer.Asset])

	// --- 5) The gate actually gates: tampering fails, no mint ---
	// 5a) attacker inflates the amount under the same attestation
	inflated := xfer
	inflated.Amount = 1_000_000_000
	inflated.Nonce = 2
	require.False(t, b.mintOnAttestation(inflated, att),
		"inflated amount does not verify → B refuses to mint")

	// 5b) attacker redirects the recipient
	redirected := xfer
	redirected.Recipient = [20]byte{0xba, 0xd0}
	redirected.Nonce = 3
	require.False(t, b.mintOnAttestation(redirected, att),
		"redirected recipient does not verify → B refuses to mint")

	// 5c) replay of the original (settled) transfer is refused
	require.False(t, b.mintOnAttestation(xfer, att),
		"replayed nonce is refused → no double-mint")

	// Ledger is unchanged by all rejected attempts — still conserved.
	require.Equal(t, uint64(1_000_000), b.minted[xfer.Asset],
		"no phantom mint from any rejected transfer")
}
