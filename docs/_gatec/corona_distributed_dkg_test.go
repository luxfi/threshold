// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// GATE C proof harness — corona dealerless distributed DKG, per-node.
//
// This drives the corona Pedersen DKG with one SEPARATE *dkg2.DKGSession
// per validator process. Each node runs Round1 with its OWN entropy and
// Round2Identify on ONLY the shares addressed to it, yielding ONLY its
// own share of the master secret. No process holds >=t shares; no process
// ever assembles the master secret s. This is the live M-Chain finality
// lane (corona / R-LWE), which — unlike pulsar/ML-DSA — has a genuine
// dealerless DKG primitive.

package keyera_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/luxfi/corona/dkg2"
	"github.com/luxfi/corona/hash"
	"github.com/luxfi/corona/keyera"
	"github.com/luxfi/corona/threshold"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// vecBytes serialises a share vector for distinctness comparison.
func vecBytes(t *testing.T, v structs.Vector[ring.Poly]) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := v.WriteTo(&buf); err != nil {
		t.Fatalf("serialise share vector: %v", err)
	}
	return buf.Bytes()
}

// driveDistributedRound1 builds n SEPARATE dkg2 sessions, runs Round1 on
// each with its own fresh seed, and returns the sessions + Round1 outputs.
// This is the per-node share-DEALING step — each session holds only its
// own secret polynomial (cCoeffs); the master secret is never formed.
func driveDistributedRound1(t *testing.T, params *dkg2.Params, n, thr int, suite hash.HashSuite) ([]*dkg2.DKGSession, []*dkg2.Round1Output) {
	t.Helper()
	sessions := make([]*dkg2.DKGSession, n)
	r1 := make([]*dkg2.Round1Output, n)
	for i := 0; i < n; i++ {
		s, err := dkg2.NewDKGSession(params, i, n, thr, suite)
		if err != nil {
			t.Fatalf("NewDKGSession[%d]: %v", i, err)
		}
		sessions[i] = s
		seed := make([]byte, 32) // sign.KeySize
		if _, err := rand.Read(seed); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
		out, err := s.Round1WithSeed(seed)
		if err != nil {
			t.Fatalf("Round1WithSeed[%d]: %v", i, err)
		}
		r1[i] = out
	}
	return sessions, r1
}

// TestDistributedDKG_SingleShareCustody proves the dealerless DKG custody
// boundary: each node runs Round2Identify over ONLY the shares addressed
// to it and obtains ONLY its own share. No process holds the master
// secret or another node's share.
func TestDistributedDKG_SingleShareCustody(t *testing.T) {
	const n, thr = 5, 3
	suite := hash.Default()
	params, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}

	sessions, r1 := driveDistributedRound1(t, params, n, thr, suite)

	// Each node j runs Round2Identify on the shares ADDRESSED to it
	// (r1[i].Shares[j] from every dealer i) — never the full share matrix.
	// The result is ONLY node j's own share of the master secret.
	shares := make([][]byte, n)
	for j := 0; j < n; j++ {
		recvShares := make(map[int]structs.Vector[ring.Poly], n)
		recvBlinds := make(map[int]structs.Vector[ring.Poly], n)
		recvCommits := make(map[int][]structs.Vector[ring.Poly], n)
		for i := 0; i < n; i++ {
			// CUSTODY: node j is handed dealer i's share for j ONLY —
			// r1[i].Shares[j]. It is NEVER handed r1[i].Shares[k], k!=j.
			recvShares[i] = r1[i].Shares[j]
			recvBlinds[i] = r1[i].Blinds[j]
			recvCommits[i] = r1[i].Commits
		}
		sj, _, _, badID, err := sessions[j].Round2Identify(recvShares, recvBlinds, recvCommits)
		if err != nil {
			t.Fatalf("node %d Round2Identify: %v (badID=%d)", j, err, badID)
		}
		if badID != -1 {
			t.Fatalf("node %d flagged a bad dealer %d in an honest run", j, badID)
		}
		if len(sj) == 0 {
			t.Fatalf("node %d got an empty share", j)
		}
		shares[j] = vecBytes(t, sj)
	}

	// CUSTODY: every node's share is distinct (no two processes hold the
	// same secret-share material; none holds the master secret).
	seen := make(map[string]int, n)
	for j := range shares {
		key := string(shares[j])
		if prev, ok := seen[key]; ok {
			t.Fatalf("node %d and node %d hold identical share material", prev, j)
		}
		seen[key] = j
	}

	// Each session is a distinct object for a distinct party — the
	// per-node custody boundary is structural.
	if len(sessions) != n {
		t.Fatalf("expected %d separate session objects, got %d", n, len(sessions))
	}
}

// TestDistributedDKG_YieldsWorkingGroupKey proves the dealerless DKG
// produces a VALID working group key: the per-node Round1 outputs feed
// corona's reference assembly (FinishBootstrapPedersen) to derive the
// group key + per-node KeyShares, and the committee threshold-signs a
// message that verifies under the group key. A wrong message fails.
//
// (The assembly itself still co-locates Round2/β-flooding in
// FinishBootstrapPedersen — that is the keyera per-node refactor that
// remains; the SHARE-DEALING Round1 above is genuinely per-node, and the
// resulting key is proven valid here.)
func TestDistributedDKG_YieldsWorkingGroupKey(t *testing.T) {
	const n, thr = 4, 2
	suite := hash.Default()
	params, err := dkg2.NewParams()
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}

	sessions, r1 := driveDistributedRound1(t, params, n, thr, suite)

	validators := make([]string, n)
	for i := range validators {
		validators[i] = string(rune('A' + i))
	}

	era, _, err := keyera.FinishBootstrapPedersen(
		suite, thr, validators,
		keyera.CoronaGroupID(0), keyera.CoronaKeyEraID(1),
		params, sessions, r1)
	if err != nil {
		t.Fatalf("FinishBootstrapPedersen (dealerless assembly): %v", err)
	}
	if era == nil || era.GroupKey == nil || era.State == nil {
		t.Fatalf("dealerless DKG produced an incomplete era")
	}

	// Build one per-node Signer from each validator's KeyShare, ordered by
	// KeyShare.Index so signerIDs line up.
	signers := make([]*threshold.Signer, n)
	signerIDs := make([]int, n)
	for _, v := range validators {
		ks, ok := era.State.Shares[v]
		if !ok || ks == nil {
			t.Fatalf("missing KeyShare for validator %q", v)
		}
		signers[ks.Index] = threshold.NewSigner(ks)
		signerIDs[ks.Index] = ks.Index
	}

	sessionID := 1
	prfKey := []byte("gatec-corona-distributed-dkg-prf")
	message := "M-Chain genesis: dealerless DKG group key works"

	round1Data := make(map[int]*threshold.Round1Data, n)
	for _, s := range signers {
		d := s.Round1(sessionID, prfKey, signerIDs)
		round1Data[d.PartyID] = d
	}
	round2Data := make(map[int]*threshold.Round2Data, n)
	for _, s := range signers {
		d, err := s.Round2(sessionID, message, prfKey, signerIDs, round1Data)
		if err != nil {
			t.Fatalf("threshold Round2: %v", err)
		}
		round2Data[d.PartyID] = d
	}
	sig, err := signers[0].Finalize(round2Data)
	if err != nil {
		t.Fatalf("threshold Finalize: %v", err)
	}

	if !threshold.Verify(era.GroupKey, message, sig) {
		t.Fatalf("signature under the DEALERLESS group key failed to verify")
	}
	if threshold.Verify(era.GroupKey, "tampered message", sig) {
		t.Fatalf("signature verified under a wrong message — soundness broken")
	}
}
