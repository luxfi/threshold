# GATE C — per-node distributed single-share threshold signer (pulsar v0.3)

This directory holds the PROVEN GATE C distributed signer for pulsar's
v0.3 algebraic ML-DSA threshold path. It is the per-node decomposition
of the in-process `OrchestrateV03Sign{,Ctx}` driver.

It lives here (a go-ignored `_`-prefixed dir — `go build ./...` skips it)
rather than in a buildable package because:

1. It MUST compile inside the `pulsar` package
   (`github.com/luxfi/pulsar/ref/go/pkg/pulsar`), as a sibling to
   `orchestrate.go`, because the public per-node API leaks one
   package-private type: `AlgebraicThresholdSigner.Round2Sign` takes
   `peerW map[NodeID]polyVec`. `distributed.go`'s message-driven
   `Round2Sign(round1, round2W)` is the bridge that reconstructs that
   private map from the public `AlgebraicRound2Message.W` bytes via the
   in-package `unpackPolyVec`. No external package can do this.
2. `threshold` pins the released `pulsar v1.1.1`, which HAS the v0.3
   algebraic API and hosts the dispatcher (`pkg/thresholdd/pulsar.go`)
   that this signer decomposes. pulsar HEAD is, concurrently, mid gate-A
   refactor that removed the v0.3 algebraic API from `main` (it builds,
   but `AlgebraicThresholdSigner`/`OrchestrateV03Sign`/`Round2W` are gone
   on HEAD; the released v1.1.1/v1.1.2 modules still carry them).

## What it proves (the red HIGH finding)

> "no-reconstruct" ≠ "no all-shares custody."

`OrchestrateV03Sign` never materialises the master sk, but it constructs
all `t` `AlgebraicThresholdSigner`s — all `t` `AlgebraicKeyShare`s — in
ONE process. `distributed.go` replaces that with `DistributedSigner`:
each validator process holds EXACTLY ONE `*AlgebraicKeyShare` and ONE
private `*IdentityKey`; round messages move between processes; the
designated aggregator (`quorum[0]`) combines from messages alone via
`AlgebraicAggregateCtx` (whose signature has no `*PrivateKey`, no
`SkBytes`, no `[]*AlgebraicKeyShare`).

## Single-share custody — type-enforced + grep-proven

The ONLY share-bearing surfaces in `distributed.go` are singular:

```
116:	share *AlgebraicKeyShare        // struct field — one pointer, never a slice
165:	share *AlgebraicKeyShare,        // NewDistributedSigner param — one share
```

There is no `[]*AlgebraicKeyShare`, `quorumShares`, or `allShares` in the
code. `AggregateDistributed(...)` takes the aggregator's pairwise
session-key row + the round messages — no share, no sk, no seed.

## Reproduce the proof (against immutable released v1.1.1)

```sh
export SDKROOT="$(xcrun --show-sdk-path)"; export GOWORK=off
rm -rf /tmp/pulsar-gatec
cp -r "$(go env GOMODCACHE)/github.com/luxfi/pulsar@v1.1.1" /tmp/pulsar-gatec
chmod -R u+w /tmp/pulsar-gatec
cp distributed.go distributed_test.go /tmp/pulsar-gatec/ref/go/pkg/pulsar/
cd /tmp/pulsar-gatec/ref/go
go test ./pkg/pulsar/ -run TestDistributedSign -v -count=1
```

Observed (pulsar v1.1.1):

```
--- PASS: TestDistributedSign_SingleShareCustody (0.30s)
--- PASS: TestDistributedSign_Ctx (0.28s)
--- PASS: TestDistributedSign_SubQuorumCannotSign (0.87s)
PASS
ok  	github.com/luxfi/pulsar/ref/go/pkg/pulsar	1.903s
```

The existing v0.3 algebraic suite (`TestAlgebraic*`, `TestPulsar_Wire*`,
`TestOrchestrate*`) also stays green with these files present
(non-disruptive — the files only ADD).

## To land in production

Drop `distributed.go` + `distributed_test.go` into the pulsar package
that carries the v0.3 algebraic API. Against released v1.1.1/v1.1.2 they
compile and pass as-is. Against pulsar HEAD they must first be ported to
whatever aggregate model the gate-A refactor settles on (the per-node
decomposition is identical: one share per process, message-driven rounds,
share-free aggregate — only the type names change).

## Honest scope (see ../DISTRIBUTED_SIGNER_GATEC.md)

- BUILT + PROVEN: the pulsar v0.3 distributed signer (this dir).
- NOT BUILT (designed): corona dealerless distributed DKG driver
  (the live M-Chain finality lane has the dealerless `dkg2` primitive;
  the per-node network driver is the remaining work) and the quasar
  `EpochManager` self-node custody refactor.
- RESEARCH-GRADE GAP: a dealerless, byte-FIPS-204-compatible ML-DSA
  (pulsar) DKG. `pulsar.NewDKGSession` is the v0.1 SEED DKG — it
  reconstructs the master sk at every party and yields a v0.1 `KeyShare`,
  NOT an `AlgebraicKeyShare`. It is not the dealerless algebraic path.
