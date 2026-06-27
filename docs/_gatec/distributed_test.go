// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// distributed_test.go — GATE C proof harness for the per-node
// distributed v0.3 algebraic threshold signer.
//
// These tests drive ONLY the PUBLIC DistributedSigner surface
// (NewDistributedSigner, SessionRound, IngestSessions, BeginAttempt,
// Round1, Round2W, Round2Sign, Aggregate / AggregateDistributed). Each
// validator is a SEPARATE *DistributedSigner object holding exactly one
// AlgebraicKeyShare; round messages move between them over an in-memory
// bus (plain slices). No orchestrator co-locates the shares. The single-
// share custody property is asserted at runtime (ShareCount) and is a
// compile-time fact of the API (Aggregate / AggregateDistributed take no
// share parameter).

import (
	"crypto/rand"
	"errors"
	"testing"
)

// distSetup is the test fixture for a (t, n) committee. The shares are
// produced by DealAlgebraicV03Shares — the GENESIS dealer. That dealer
// is a test fixture (and, in production, the fenced dev/test dispatcher
// or an opt-in TEE ceremony) — the GATE C property under test is that
// AFTER dealing, each share lives in a SEPARATE DistributedSigner and the
// SIGNING ceremony never co-locates them.
type distSetup struct {
	params     *Params
	setup      *AlgebraicSetup
	shares     []*AlgebraicKeyShare      // sorted ascending by NodeID
	identities map[NodeID]*IdentityKey   // per-member long-term identity
	directory  IdentityDirectory         // public halves only
}

func newDistSetup(t *testing.T, n, threshold int) *distSetup {
	t.Helper()
	params := MustParamsFor(ModeP65)

	committee := make([]NodeID, n)
	for i := 0; i < n; i++ {
		var id NodeID
		if _, err := rand.Read(id[:]); err != nil {
			t.Fatalf("committee id entropy: %v", err)
		}
		committee[i] = id
	}

	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("master seed entropy: %v", err)
	}
	setup, shares, err := DealAlgebraicV03Shares(params, committee, threshold, seed, rand.Reader)
	// Wipe our local copy of the master seed immediately (the dealer
	// already wiped its expansion internally).
	for i := range seed {
		seed[i] = 0
	}
	if err != nil {
		t.Fatalf("DealAlgebraicV03Shares: %v", err)
	}

	identities := make(map[NodeID]*IdentityKey, n)
	directory := make(IdentityDirectory, n)
	for _, s := range shares {
		ident, err := GenerateIdentity(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateIdentity: %v", err)
		}
		identities[s.NodeID] = ident
		directory[s.NodeID] = ident.PublicKey()
	}

	return &distSetup{
		params:     params,
		setup:      setup,
		shares:     shares,
		identities: identities,
		directory:  directory,
	}
}

// nodesForQuorum builds one SEPARATE DistributedSigner per member of the
// first `q` shares (the quorum). Each node receives exactly ONE share
// plus its own private identity; the directory carries only public keys.
func (ds *distSetup) nodesForQuorum(t *testing.T, q int, sid [16]byte, ctx, msg []byte) []*DistributedSigner {
	t.Helper()
	quorum := make([]NodeID, q)
	quorumShares := make([]*AlgebraicKeyShare, q)
	for i := 0; i < q; i++ {
		quorum[i] = ds.shares[i].NodeID
		quorumShares[i] = ds.shares[i]
	}
	evalPoints, err := V03QuorumEvalPoints(quorum, quorumShares)
	if err != nil {
		t.Fatalf("V03QuorumEvalPoints: %v", err)
	}
	nodes := make([]*DistributedSigner, q)
	for i := 0; i < q; i++ {
		nd, err := NewDistributedSigner(ds.params, ds.setup, ds.shares[i],
			ds.identities[quorum[i]], ds.directory, quorum, evalPoints, sid, ctx, msg)
		if err != nil {
			t.Fatalf("NewDistributedSigner[%d]: %v", i, err)
		}
		nodes[i] = nd
	}
	return nodes
}

// runCeremony drives the full distributed ceremony over an in-memory bus
// and returns the aggregated signature. Each node is a separate object;
// only round messages cross between them.
func runCeremony(nodes []*DistributedSigner, maxAttempts uint32) (*Signature, error) {
	// Round 0 — session establishment.
	sessionBus := make([]*SessionMsg, 0, len(nodes))
	for _, nd := range nodes {
		sm, err := nd.SessionRound()
		if err != nil {
			return nil, err
		}
		sessionBus = append(sessionBus, sm)
	}
	for _, nd := range nodes {
		if err := nd.IngestSessions(sessionBus); err != nil {
			return nil, err
		}
	}

	// FIPS 204 rejection-restart loop, driven leaderlessly: every node
	// advances attempt+1 on ErrAlgebraicRestart.
	for attempt := uint32(0); attempt < maxAttempts; attempt++ {
		for _, nd := range nodes {
			if err := nd.BeginAttempt(attempt); err != nil {
				return nil, err
			}
		}
		r1 := make([]*AlgebraicRound1Message, 0, len(nodes))
		for _, nd := range nodes {
			m, err := nd.Round1()
			if err != nil {
				return nil, err
			}
			r1 = append(r1, m)
		}
		r2w := make([]*AlgebraicRound2Message, 0, len(nodes))
		for _, nd := range nodes {
			m, _, err := nd.Round2W(r1)
			if err != nil {
				return nil, err
			}
			r2w = append(r2w, m)
		}
		r2 := make([]*AlgebraicRound2Message, 0, len(nodes))
		for _, nd := range nodes {
			m, _, err := nd.Round2Sign(r1, r2w)
			if err != nil {
				return nil, err
			}
			r2 = append(r2, m)
		}
		var agg *DistributedSigner
		for _, nd := range nodes {
			if nd.IsAggregator() {
				agg = nd
				break
			}
		}
		if agg == nil {
			return nil, errors.New("no designated aggregator in node set")
		}
		sig, err := agg.Aggregate(attempt, r1, r2)
		if err == nil {
			return sig, nil
		}
		if !errors.Is(err, ErrAlgebraicRestart) {
			return nil, err
		}
	}
	return nil, errors.New("no acceptance within maxAttempts")
}

// TestDistributedSign_SingleShareCustody is the headline GATE C proof:
//   - t SEPARATE node objects, ONE share each (asserted), all distinct;
//   - a full distributed ceremony over a message bus (no orchestrator);
//   - the result verifies under unmodified FIPS 204 ML-DSA.
func TestDistributedSign_SingleShareCustody(t *testing.T) {
	const n, threshold = 5, 3
	ds := newDistSetup(t, n, threshold)

	var sid [16]byte
	copy(sid[:], []byte("gatec-distsign-01"))
	msg := []byte("M-Chain finality: leaderless permissionless threshold signature")

	nodes := ds.nodesForQuorum(t, threshold, sid, nil, msg)

	// CUSTODY INVARIANT: every node holds exactly one share; no two nodes
	// share a NodeID. This is the runtime witness that no process is one
	// Lagrange combine from the key.
	seen := make(map[NodeID]bool, len(nodes))
	for i, nd := range nodes {
		if got := nd.ShareCount(); got != 1 {
			t.Fatalf("node %d ShareCount=%d, want exactly 1 (single-share custody violated)", i, got)
		}
		id := nd.NodeID()
		if seen[id] {
			t.Fatalf("node %d shares NodeID %x with another node — co-location!", i, id[:4])
		}
		seen[id] = true
	}

	sig, err := runCeremony(nodes, ds.params.MaxRestart)
	if err != nil {
		t.Fatalf("distributed ceremony: %v", err)
	}

	// The aggregator is itself just one validator holding one share; it
	// produced the signature from messages alone.
	for _, nd := range nodes {
		if nd.IsAggregator() && nd.ShareCount() != 1 {
			t.Fatalf("aggregator holds %d shares, want 1", nd.ShareCount())
		}
	}

	// VERIFY under unmodified FIPS 204 ML-DSA (Class N1 byte-validity).
	if err := VerifyCtx(ds.params, ds.setup.Pub, msg, nil, sig); err != nil {
		t.Fatalf("distributed signature failed FIPS 204 VerifyCtx: %v", err)
	}
	if err := Verify(ds.params, ds.setup.Pub, msg, sig); err != nil {
		t.Fatalf("distributed signature failed FIPS 204 Verify: %v", err)
	}
}

// TestDistributedSign_Ctx exercises the FIPS 204 §5.4 context-bound path
// through the distributed signer.
func TestDistributedSign_Ctx(t *testing.T) {
	const n, threshold = 4, 3
	ds := newDistSetup(t, n, threshold)

	var sid [16]byte
	copy(sid[:], []byte("gatec-distsign-ct"))
	ctx := []byte("lux-evm-precompile-mldsa-v1")
	msg := []byte("ctx-bound M-Chain certificate")

	nodes := ds.nodesForQuorum(t, threshold, sid, ctx, msg)
	sig, err := runCeremony(nodes, ds.params.MaxRestart)
	if err != nil {
		t.Fatalf("distributed ctx ceremony: %v", err)
	}
	if err := VerifyCtx(ds.params, ds.setup.Pub, msg, ctx, sig); err != nil {
		t.Fatalf("ctx-bound distributed signature failed VerifyCtx: %v", err)
	}
	// And it must NOT verify under the empty ctx — context binding holds.
	if err := VerifyCtx(ds.params, ds.setup.Pub, msg, nil, sig); err == nil {
		t.Fatalf("ctx-bound signature wrongly verified under empty ctx (context binding broken)")
	}
}

// TestDistributedSign_SubQuorumCannotSign proves the threshold bound two
// ways:
//
//	(a) the aggregator cannot combine fewer than t Round-2 contributions
//	    — AlgebraicAggregateCtx refuses with ErrInsufficientQuor;
//	(b) a (t-1)-member quorum (a colluding sub-threshold coalition that
//	    pools its shares into its OWN smaller committee) produces a
//	    signature that FAILS FIPS 204 verification, because Lagrange
//	    interpolation over t-1 points does not reconstruct the degree-
//	    (t-1) secret.
func TestDistributedSign_SubQuorumCannotSign(t *testing.T) {
	const n, threshold = 5, 3
	ds := newDistSetup(t, n, threshold)

	var sid [16]byte
	copy(sid[:], []byte("gatec-subquorum-01"))
	msg := []byte("sub-quorum must not sign")

	// (a) Full quorum rounds, but aggregate with only t-1 Round-2 msgs.
	nodes := ds.nodesForQuorum(t, threshold, sid, nil, msg)
	if _, err := func() (*Signature, error) {
		sessionBus := make([]*SessionMsg, 0, len(nodes))
		for _, nd := range nodes {
			sm, err := nd.SessionRound()
			if err != nil {
				return nil, err
			}
			sessionBus = append(sessionBus, sm)
		}
		for _, nd := range nodes {
			if err := nd.IngestSessions(sessionBus); err != nil {
				return nil, err
			}
		}
		for _, nd := range nodes {
			if err := nd.BeginAttempt(0); err != nil {
				return nil, err
			}
		}
		r1 := make([]*AlgebraicRound1Message, 0, len(nodes))
		for _, nd := range nodes {
			m, err := nd.Round1()
			if err != nil {
				return nil, err
			}
			r1 = append(r1, m)
		}
		r2w := make([]*AlgebraicRound2Message, 0, len(nodes))
		for _, nd := range nodes {
			m, _, err := nd.Round2W(r1)
			if err != nil {
				return nil, err
			}
			r2w = append(r2w, m)
		}
		r2 := make([]*AlgebraicRound2Message, 0, len(nodes))
		for _, nd := range nodes {
			m, _, err := nd.Round2Sign(r1, r2w)
			if err != nil {
				return nil, err
			}
			r2 = append(r2, m)
		}
		// Drop one contribution — only t-1 of t.
		var agg *DistributedSigner
		for _, nd := range nodes {
			if nd.IsAggregator() {
				agg = nd
			}
		}
		return agg.Aggregate(0, r1[:threshold-1], r2[:threshold-1])
	}(); !errors.Is(err, ErrInsufficientQuor) {
		t.Fatalf("aggregating t-1 contributions: got err=%v, want ErrInsufficientQuor", err)
	}

	// (b) A t-1-member quorum produces a non-verifying signature.
	subNodes := ds.nodesForQuorum(t, threshold-1, sid, nil, msg)
	sig, err := runCeremony(subNodes, ds.params.MaxRestart)
	if err != nil {
		// Acceptable: the sub-threshold coalition could not even complete
		// the ceremony. Either outcome proves it cannot sign.
		return
	}
	if verr := VerifyCtx(ds.params, ds.setup.Pub, msg, nil, sig); verr == nil {
		t.Fatalf("a (t-1)-member coalition produced a VERIFYING signature — threshold broken!")
	}
}
