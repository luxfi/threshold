// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// distributed.go — GATE C: the per-node distributed v0.3 algebraic
// threshold signer.
//
// THE PROBLEM THIS CLOSES (red HIGH finding):
//
//	"no-reconstruct" ≠ "no all-shares custody". The v0.3 algebraic
//	sign path provably never materialises the master ML-DSA secret
//	key (AlgebraicAggregate has no sk-bearing parameter), BUT the
//	in-process driver OrchestrateV03Sign{,Ctx} constructs all t
//	AlgebraicThresholdSigners — i.e. all t AlgebraicKeyShares — in
//	ONE OS process. A single coredump of that process is one Lagrange
//	combine away from the full key. The same goes for QuorumSessionKeys,
//	which takes every party's PRIVATE *IdentityKey in one map.
//
// THE FIX (this file):
//
//	DistributedSigner is one validator's local state. It holds EXACTLY
//	ONE *AlgebraicKeyShare and ONE long-term *IdentityKey (private);
//	every other party is known only by its PUBLIC *IdentityPublicKey.
//	The per-node rounds emit plain serialisable messages; any node can
//	carry them over the consensus / MPC message bus. The designated
//	aggregator (quorum[0]) combines the collected messages into a FIPS
//	204 signature via AlgebraicAggregateCtx — whose call signature has
//	NO *PrivateKey, NO SkBytes, NO []*AlgebraicKeyShare. No process is
//	ever one Lagrange combine from the key.
//
//	This is a CUSTODY-BOUNDARY decomposition, not a new scheme. Every
//	message a DistributedSigner emits is byte-identical to the message
//	the in-process orchestrator's party would emit on the same inputs;
//	the aggregator runs the same AlgebraicAggregateCtx. So the
//	unforgeability / (t-1)-privacy reduction is inherited verbatim from
//	threshold_v03.go: an adversary against the distributed protocol sees
//	a strict subset of what the orchestrator's adversary sees and holds
//	strictly fewer shares per process.
//
// RELATION TO orchestrate.go:
//
//	OrchestrateV03Sign{,Ctx} stays as the SINGLE-PROCESS driver for the
//	off-chain JSON-RPC dispatcher (dev/test harness, MPC-bus fixtures,
//	SDK tooling) and the explicit-opt-in TEE custody path. The chain
//	finality path drives DistributedSigner — one per validator process.
//	Same kernel, different custody boundary.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Errors specific to the distributed driver.
var (
	// ErrDistNilShare is returned when NewDistributedSigner is given a
	// nil AlgebraicKeyShare. A DistributedSigner is meaningless without
	// exactly one share.
	ErrDistNilShare = errors.New("pulsar: distributed signer requires exactly one AlgebraicKeyShare")

	// ErrDistNotAggregator is returned when Aggregate is called on a node
	// that is not the designated aggregator (quorum[0]). Only quorum[0]
	// holds the pairwise session-key row needed to verify the Round-2
	// MACs, which every party computes toward quorum[0].
	ErrDistNotAggregator = errors.New("pulsar: only the designated aggregator (quorum[0]) can Aggregate")

	// ErrDistSessionIncomplete is returned when a round is attempted
	// before IngestSessions has produced a pairwise key for every peer
	// in the quorum.
	ErrDistSessionIncomplete = errors.New("pulsar: distributed session keys incomplete (call SessionRound + IngestSessions for the full quorum first)")

	// ErrDistNoAttempt is returned when a sign round is attempted before
	// BeginAttempt has constructed the per-attempt inner signer.
	ErrDistNoAttempt = errors.New("pulsar: distributed signer has no active attempt (call BeginAttempt first)")
)

// SessionEncap is one node's authenticated ML-KEM-768 encapsulation
// toward a single recipient: the FIPS 203 ciphertext plus the sender's
// FIPS 204 ML-DSA-65 signature over it. The recipient verifies the
// signature against the sender's published IdentityPublicKey before
// decapsulating (VerifyPeerEncapsulation).
type SessionEncap struct {
	Ct  []byte
	Sig []byte
}

// SessionMsg is the Round-0 broadcast of one node. Encaps is keyed by
// RECIPIENT NodeID: Encaps[r] is From's authenticated encapsulation
// toward party r. Every quorum member (other than From) finds its own
// encapsulation under Encaps[self].
//
// This replaces QuorumSessionKeys' all-private-identities-in-one-map
// co-location: a node derives ONLY its own pairwise key row from peers'
// SessionMsgs, using its own *IdentityKey and peers' *IdentityPublicKeys.
type SessionMsg struct {
	From   NodeID
	Encaps map[NodeID]SessionEncap
}

// DistributedSigner is one validator's local state machine for a
// distributed v0.3 algebraic threshold signature.
//
// CUSTODY INVARIANT: the struct holds ONE *AlgebraicKeyShare (field
// `share`, a single pointer — never a slice) and ONE private
// *IdentityKey. There is no field, constructor, or method by which a
// DistributedSigner comes to hold a second party's share or private
// identity. ShareCount() is the runtime witness; the type is the
// compile-time witness.
type DistributedSigner struct {
	params *Params
	setup  *AlgebraicSetup

	// share is THE single key share this validator holds. Never a slice.
	share *AlgebraicKeyShare

	// identity is this validator's long-term private identity. Peers are
	// known only via the public `directory`.
	identity  *IdentityKey
	directory IdentityDirectory

	quorum     []NodeID // sorted committee for this signature
	evalPoints []uint32 // Shamir x-coords, parallel to quorum
	sid        [16]byte
	ctx        []byte
	msg        []byte

	rng io.Reader // per-attempt y_i entropy; nil ⇒ crypto/rand

	// mySS[peer] is this node's own EstablishSession contributory secret
	// toward peer, retained from SessionRound until the peer's
	// encapsulation arrives in IngestSessions.
	mySS map[NodeID][]byte

	// myRow[peer] is the derived pairwise session key between this node
	// and peer — this node's row of the pairwise matrix, and ONLY this
	// node's row.
	myRow map[NodeID][32]byte

	// inner is the current attempt's single-share party state machine.
	// Re-created by BeginAttempt on every rejection-restart.
	inner   *AlgebraicThresholdSigner
	attempt uint32
}

// NewDistributedSigner constructs one validator's distributed signer
// over exactly one AlgebraicKeyShare.
//
//   - setup is the public AlgebraicSetup (group pubkey + ρ + tr + A; no
//     sk). Shared by the whole committee.
//   - share is THIS validator's AlgebraicKeyShare (the one and only).
//   - identity is THIS validator's long-term *IdentityKey (private).
//   - directory must carry a published *IdentityPublicKey for every
//     quorum member (peers' public halves only).
//   - quorum is the t-element signing committee, sorted ascending by
//     NodeID; it MUST contain share.NodeID.
//   - evalPoints are the Shamir x-coordinates parallel to quorum
//     (V03QuorumEvalPoints output).
//   - sid is a fresh per-signature session id; ctx is the FIPS 204 §5.4
//     octet string (0..255 bytes, nil for empty); msg is the message.
func NewDistributedSigner(
	params *Params,
	setup *AlgebraicSetup,
	share *AlgebraicKeyShare,
	identity *IdentityKey,
	directory IdentityDirectory,
	quorum []NodeID,
	evalPoints []uint32,
	sid [16]byte,
	ctx []byte,
	msg []byte,
) (*DistributedSigner, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if setup == nil {
		return nil, ErrAlgebraicNoSetup
	}
	if share == nil {
		return nil, ErrDistNilShare
	}
	if identity == nil {
		return nil, ErrIdentityKeyMissing
	}
	if directory == nil {
		return nil, ErrDirectoryIncomplete
	}
	if share.Mode != params.Mode || setup.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(ctx) > 255 {
		return nil, ErrCtxTooLarge
	}
	if len(quorum) == 0 {
		return nil, ErrEmptyQuorum
	}
	if len(evalPoints) != len(quorum) {
		return nil, fmt.Errorf("pulsar: distributed evalPoints length %d != quorum length %d", len(evalPoints), len(quorum))
	}
	// Quorum must be sorted ascending and duplicate-free (the inner
	// signer + aggregator both assume canonical order).
	for i := 1; i < len(quorum); i++ {
		if !nodeIDLess(quorum[i-1], quorum[i]) {
			return nil, ErrCommitteeDuplicate
		}
	}
	// This node must be in the quorum and the directory must cover every
	// peer (so we can seal/verify pairwise encapsulations).
	inQuorum := false
	for _, q := range quorum {
		if q == share.NodeID {
			inQuorum = true
		}
		if directory[q] == nil {
			return nil, ErrDirectoryIncomplete
		}
	}
	if !inQuorum {
		return nil, ErrNotInQuorum
	}

	var ctxCopy []byte
	if len(ctx) > 0 {
		ctxCopy = append([]byte{}, ctx...)
	}

	return &DistributedSigner{
		params:     params,
		setup:      setup,
		share:      share,
		identity:   identity,
		directory:  directory,
		quorum:     append([]NodeID{}, quorum...),
		evalPoints: append([]uint32{}, evalPoints...),
		sid:        sid,
		ctx:        ctxCopy,
		msg:        append([]byte{}, msg...),
		mySS:       make(map[NodeID][]byte, len(quorum)-1),
		myRow:      make(map[NodeID][32]byte, len(quorum)-1),
	}, nil
}

// SetRand overrides the per-attempt entropy source (default crypto/rand).
// Used by KAT/deterministic tests; production leaves it nil.
func (d *DistributedSigner) SetRand(r io.Reader) { d.rng = r }

// NodeID returns this validator's identity within the quorum.
func (d *DistributedSigner) NodeID() NodeID { return d.share.NodeID }

// ShareCount is the runtime witness of the GATE C custody invariant: a
// DistributedSigner holds exactly one AlgebraicKeyShare. It returns 1
// for a constructed signer (and 0 only for the zero value).
func (d *DistributedSigner) ShareCount() int {
	if d.share == nil {
		return 0
	}
	return 1
}

// Aggregator returns the NodeID of the designated aggregator for this
// quorum: quorum[0] (the lowest-sorted member). This is deterministic
// per (quorum) and rotates with the committee — it is not a fixed leader.
func (d *DistributedSigner) Aggregator() NodeID { return d.quorum[0] }

// IsAggregator reports whether this node is the designated aggregator.
func (d *DistributedSigner) IsAggregator() bool { return d.share.NodeID == d.quorum[0] }

// SessionRound emits this node's Round-0 broadcast: an authenticated
// ML-KEM-768 encapsulation toward every other quorum member, bound to
// (sid, msg). The caller broadcasts the returned SessionMsg and feeds
// every peer's SessionMsg to IngestSessions.
//
// Transcript binding matches QuorumSessionKeys (transcript == msg) so a
// DistributedSigner and an in-process orchestrator derive byte-identical
// session keys on the same inputs.
func (d *DistributedSigner) SessionRound() (*SessionMsg, error) {
	encaps := make(map[NodeID]SessionEncap, len(d.quorum)-1)
	for _, peer := range d.quorum {
		if peer == d.share.NodeID {
			continue
		}
		mySS, ct, sig, err := EstablishSession(d.share.NodeID, d.identity, peer, d.directory[peer], d.sid, d.msg)
		if err != nil {
			return nil, fmt.Errorf("pulsar: distributed SessionRound toward %x: %w", peer[:4], err)
		}
		d.mySS[peer] = mySS
		encaps[peer] = SessionEncap{Ct: ct, Sig: sig}
	}
	return &SessionMsg{From: d.share.NodeID, Encaps: encaps}, nil
}

// IngestSessions consumes peers' Round-0 broadcasts and derives THIS
// node's pairwise session-key row (and only this node's row). Each
// peer's encapsulation addressed to us is authenticated against the
// peer's published IdentityPublicKey, decapsulated with our own KEM
// secret, and mixed with our own contributory secret into the canonical
// session key (DeriveSessionKey).
//
// Must be called after SessionRound and before any sign round. Returns
// ErrDistSessionIncomplete if any quorum peer's key is missing.
func (d *DistributedSigner) IngestSessions(peers []*SessionMsg) error {
	for _, pm := range peers {
		if pm == nil || pm.From == d.share.NodeID {
			continue
		}
		peerPub := d.directory[pm.From]
		if peerPub == nil {
			return ErrDirectoryIncomplete
		}
		enc, ok := pm.Encaps[d.share.NodeID]
		if !ok {
			return fmt.Errorf("pulsar: distributed IngestSessions: peer %x sent no encapsulation for us", pm.From[:4])
		}
		mySS, ok := d.mySS[pm.From]
		if !ok {
			return fmt.Errorf("pulsar: distributed IngestSessions: no local session secret toward %x (SessionRound first)", pm.From[:4])
		}
		peerSS, err := VerifyPeerEncapsulation(d.identity, peerPub, enc.Ct, enc.Sig)
		if err != nil {
			return fmt.Errorf("pulsar: distributed IngestSessions: verify peer %x: %w", pm.From[:4], err)
		}
		key, err := DeriveSessionKey(d.share.NodeID, pm.From, d.sid, mySS, peerSS)
		if err != nil {
			return fmt.Errorf("pulsar: distributed IngestSessions: derive key with %x: %w", pm.From[:4], err)
		}
		d.myRow[pm.From] = key
	}
	// Require a key for every peer in the quorum.
	for _, q := range d.quorum {
		if q == d.share.NodeID {
			continue
		}
		if _, ok := d.myRow[q]; !ok {
			return ErrDistSessionIncomplete
		}
	}
	return nil
}

// BeginAttempt constructs the per-attempt inner single-share party
// machine. Called once per FIPS 204 rejection-restart attempt; the
// session-key row (SessionRound/IngestSessions) is attempt-independent
// and is reused across attempts.
func (d *DistributedSigner) BeginAttempt(attempt uint32) error {
	if len(d.myRow) != len(d.quorum)-1 {
		return ErrDistSessionIncomplete
	}
	signer, err := NewAlgebraicThresholdSignerCtx(
		d.params, d.setup, d.sid, attempt, d.quorum, d.share, d.myRow, d.ctx, d.msg, d.rng)
	if err != nil {
		return err
	}
	if err := signer.SetQuorumEvalPoints(d.evalPoints); err != nil {
		return err
	}
	d.inner = signer
	d.attempt = attempt
	return nil
}

// Round1 emits this node's Round-1 broadcast (commit D_i + per-pair MACs).
func (d *DistributedSigner) Round1() (*AlgebraicRound1Message, error) {
	if d.inner == nil {
		return nil, ErrDistNoAttempt
	}
	return d.inner.Round1()
}

// Round2W emits this node's W-only Round-2 staging message (reveal w_i).
// round1 is the collected Round-1 broadcasts from the full quorum.
func (d *DistributedSigner) Round2W(round1 []*AlgebraicRound1Message) (*AlgebraicRound2Message, *AbortEvidence, error) {
	if d.inner == nil {
		return nil, nil, ErrDistNoAttempt
	}
	return d.inner.Round2W(round1)
}

// Round2Sign emits this node's full Round-2 broadcast (Z, CS2, CT0 +
// MACs). round1 is the collected Round-1 broadcasts; round2W is the
// collected W-only staging messages from the full quorum.
//
// This is the public, message-driven Round-2: it reconstructs the
// package-private peerW map from the round2W message bytes internally,
// so external callers never touch polyVec. (The in-process orchestrator
// builds peerW directly because it lives in-package; an external chain
// driver cannot — this method is the bridge.)
func (d *DistributedSigner) Round2Sign(round1 []*AlgebraicRound1Message, round2W []*AlgebraicRound2Message) (*AlgebraicRound2Message, *AbortEvidence, error) {
	if d.inner == nil {
		return nil, nil, ErrDistNoAttempt
	}
	K, _, _ := modeShape(d.params.Mode)
	peerW := make(map[NodeID]polyVec, len(round2W)-1)
	for _, m := range round2W {
		if m == nil || m.NodeID == d.share.NodeID {
			continue
		}
		peerW[m.NodeID] = unpackPolyVec(m.W, K)
	}
	return d.inner.Round2Sign(round1, peerW)
}

// Aggregate is run by the designated aggregator (quorum[0]) to combine
// the collected round messages into a FIPS 204 signature. It holds NO
// share material: it passes only the aggregator's own pairwise
// session-key row to AlgebraicAggregateCtx (whose signature has no
// *PrivateKey / SkBytes / []*AlgebraicKeyShare parameter).
//
// On ErrAlgebraicRestart the whole quorum advances attempt+1 (re-run
// BeginAttempt → Round1 → Round2W → Round2Sign) and re-aggregates. The
// returned signature verifies under unmodified pulsar.VerifyCtx.
func (d *DistributedSigner) Aggregate(attempt uint32, round1 []*AlgebraicRound1Message, round2 []*AlgebraicRound2Message) (*Signature, error) {
	if !d.IsAggregator() {
		return nil, ErrDistNotAggregator
	}
	return AggregateDistributed(d.params, d.setup, d.ctx, d.msg, d.sid, attempt,
		d.quorum, d.evalPoints, d.myRow, round1, round2)
}

// AggregateDistributed is the free-function aggregation surface: any
// process holding the designated aggregator's pairwise session-key row
// (quorum[0]'s row) and the collected round messages can produce the
// signature WITHOUT any share. This is the load-bearing GATE C surface —
// its parameter list has NO share, NO sk, NO seed.
//
// aggregatorRow is quorum[0]'s pairwise session-key row (peer -> key);
// it is used only to authenticate the Round-2 MACs that every party
// computes toward quorum[0]. round1/round2 are the collected per-party
// broadcasts. The result verifies under pulsar.VerifyCtx(params,
// setup.Pub, msg, ctx, sig).
func AggregateDistributed(
	params *Params,
	setup *AlgebraicSetup,
	ctx []byte,
	msg []byte,
	sid [16]byte,
	attempt uint32,
	quorum []NodeID,
	evalPoints []uint32,
	aggregatorRow map[NodeID][32]byte,
	round1 []*AlgebraicRound1Message,
	round2 []*AlgebraicRound2Message,
) (*Signature, error) {
	if len(quorum) == 0 {
		return nil, ErrEmptyQuorum
	}
	// AlgebraicAggregateCtx reads only sessionKeys[quorum[0]] (the
	// aggregator's row) to verify the Round-2 MACs addressed to quorum[0].
	sessionKeys := map[NodeID]map[NodeID][32]byte{quorum[0]: aggregatorRow}
	return AlgebraicAggregateCtx(params, setup, ctx, msg, sid, attempt,
		quorum, evalPoints, len(quorum), round1, round2, sessionKeys)
}

// ensure crypto/rand stays imported even if SetRand is the only entropy
// override used in a build; BeginAttempt forwards d.rng (nil ⇒ inner
// signer falls back to crypto/rand internally).
var _ = rand.Reader
