# GATE C — Distributed per-node threshold signer + DKG

Status: design + pulsar-lane signer implemented and proven (see
`pkg/distsign`); corona-lane DKG/signer wiring designed, partially built.
This document is the architectural record for the work that lets Lux
**M-Chain go public / leaderless / permissionless**.

## 0. The red HIGH finding (what GATE C closes)

> "no-reconstruct" ≠ "no all-shares custody."

The v0.3 algebraic path (`pulsar`) and the Pedersen path (`corona`)
provably never materialise the master signing key — but every
**runnable** signer and keygen co-locates all `t` shares in ONE OS
process. One Lagrange combine in a single coredump is the full key.
Concretely, before GATE C:

| Site | File | Co-location |
|------|------|-------------|
| pulsar sign | `pkg/thresholdd/pulsar.go:281,437` `OrchestrateV03Sign{,Ctx}` | constructs all `t` `AlgebraicThresholdSigner`s from `quorumShares[...]` in one process |
| pulsar keygen | `pkg/thresholdd/pulsar.go:191` `DealAlgebraicV03Shares(...masterSeed...)` | in-process trusted dealer expands the seed and holds every share |
| corona sign | `pkg/thresholdd/corona.go:184-198` | builds every `coronaThreshold.Signer` from every `KeyShare` in one process |
| corona keygen | `corona/keyera/bootstrap_pedersen.go:177-200` | builds all `N` `dkg2.DKGSession`s in one process |
| epoch state | `consensus/protocol/quasar/epoch.go:235,505-509` | `EpochManager` keeps the full `EpochShareState.Shares[v]` for every `v` |

The fix is structural: **each validator process holds exactly one
share; round messages move over the network; any node aggregates from
messages alone.** No process is ever one Lagrange combine from the key.

## 1. Threat model and security goals

- **Adversary.** Static, up to `t-1` malicious validators (full control of
  their own state + network position), plus a network adversary that can
  observe, drop, reorder, and inject messages. Honest-but-curious for the
  remaining `n-t+1`. Post-quantum: the adversary is quantum (so every
  primitive must be PQ; classical assumptions are disallowed on the chain
  path).
- **Custody goal (the GATE C property).** At no point in genesis (DKG) or
  in any signing ceremony does any single OS process hold `t` or more
  shares, the master seed, or the master secret key. Compromising any
  `t-1` validators yields zero information about the group secret beyond
  what their own shares already encode (information-theoretic for the
  Shamir layer; M-LWE / R-LWE for the published transcript).
- **Unforgeability.** IND-ID-EUF-CMA against any `(t-1)`-corruption
  adversary in the ROM, under M-LWE (pulsar / FIPS 204) resp. R-LWE
  (corona / Boschini–Takahashi–Tibouchi 2024/1113). Inherited unchanged
  from the underlying per-party primitives; GATE C does not touch the
  inner arithmetic, only who holds what.
- **Liveness.** Any `t` honest validators that exchange their round
  messages produce a valid signature; the FIPS 204 / corona
  rejection-restart loop terminates with overwhelming probability.

GATE C is a **custody-boundary** change, not a new cryptographic scheme.
The reduction is: an adversary against the distributed protocol that
breaks unforgeability or learns the secret is, message-for-message, an
adversary against the in-process orchestrator (every message it sees and
every share it holds is a strict subset of what the orchestrator's
adversary sees), which is the already-proven `AlgebraicAggregateCtx` /
corona `Finalize` security game. Decomposing the orchestrator into
per-node objects with the same messages cannot help the adversary; it
strictly shrinks each process's TCB.

## 2. Primitive map (Phase 1, read-only findings)

### 2.1 pulsar v0.3 signing is ALREADY per-node

`pulsar/ref/go/pkg/pulsar/threshold_v03.go`:

- `AlgebraicThresholdSigner` holds **exactly one** `*AlgebraicKeyShare`.
- `Round1() -> *AlgebraicRound1Message` (commit `D_i` + per-pair MACs).
- `Round2W(round1) -> *AlgebraicRound2Message` (W-only reveal `w_i`).
- `Round2Sign(round1, peerW) -> *AlgebraicRound2Message` (full `Z,CS2,CT0`).
- `AlgebraicAggregateCtx(params, setup, ctx, msg, sid, attempt, quorum,
  evalPoints, t, round1[], round2[], sessionKeys) -> *Signature` — takes
  **message arrays + public setup only**. Its function signature has NO
  `*PrivateKey`, NO `SkBytes`, NO seed, NO `[]AlgebraicKeyShare`. It reads
  only `sessionKeys[quorum[0]]` (the aggregator's own pairwise row) to
  verify Round-2 MACs.

So the per-node decomposition needs **no new inner crypto**. The only
co-location is the *driver* (`OrchestrateV03Sign`) and the *session-key
helper* (`QuorumSessionKeys`, which takes every party's private
`*IdentityKey` in one map).

### 2.2 pulsar DKG gap (honest correction to the GATE C brief)

`AlgebraicKeyShare` is produced by **exactly one** function:
`DealAlgebraicV03Shares` — the in-process trusted dealer. There is no
algebraic/Pedersen DKG that yields `AlgebraicKeyShare`.

`pulsar.NewDKGSession` (`dkg.go`) is **NOT** the dealerless algebraic
path the brief assumes. It is the v0.1 *seed* DKG:

- its `Round3` output is a v0.1 `KeyShare` (a byte-wise Shamir share of
  the 32-byte master *seed* over GF(257)), not an `AlgebraicKeyShare`;
- its `Round3` reconstructs the **full master seed at every party**
  (`dkg.go:426 KeyFromSeed(masterSeed)`), and the code states the trust
  model plainly (`dkg.go:367-368`: "every committee member learns the
  master secret (via `c_i` sum)").

Why pulsar has no dealerless algebraic DKG: ML-DSA secrets `(s1,s2)` must
be **small** (coefficients in `[-η,η]`). A naive additive DKG
(`s = Σ_i s_i`) blows the norm to `n·η`, breaking the scheme. The trusted
dealer sidesteps this by expanding ONE seed centrally, then Shamir-sharing
the already-small `(s1,s2,t0)` (Shamir shares are full-width mod q — no
norm problem). A dealerless, **byte-FIPS-204-compatible** ML-DSA DKG is a
genuine research-grade construction (del Pino et al., "Threshold
Signatures Reloaded: ML-DSA and Enhanced Raccoon"); it is the explicit
"follow-up work" in `threshold_v03.go:257-267`. **GATE C does not pretend
to build it.** For the pulsar lane, genesis remains a trusted-dealer or
TEE ceremony (fenced to dev/test + opt-in institutional custody); the
*signing* custody boundary is what GATE C fixes for that lane.

### 2.3 corona (R-LWE) — the live M-Chain finality lane — HAS a real DKG

`corona/keyera/bootstrap_pedersen.go` + `corona/dkg2`:

- `dkg2.DKGSession` is a genuine **dealerless Pedersen DKG**:
  `Round1` (Pedersen commits + per-recipient share/blind), `Round2Identify`
  (verify + aggregate to this party's share `s_j`). Bootstrap docstring
  (`:118`): "**NO PARTY ever holds `s` in memory.**"
- R-LWE / Raccoon is *natively* threshold-friendly: Path-(a) noise
  flooding (`σ'' = κ·σ_E·√n`, `:492`) absorbs the norm growth, so the
  master secret CAN be the sum of per-party contributions. This is exactly
  why corona is dealerless and pulsar is not.
- corona `Signer` is per-node too: `NewSigner(share *KeyShare)`,
  `Round1/Round2/Finalize` (`corona/threshold/threshold.go`).
- The ONLY defect is the harness: `BootstrapPedersen`/`finishBootstrapPedersen`
  drive all `N` sessions in one process. The kernel says so and invites
  the fix (`:135-141`): "In production each party drives its own
  `dkg2.DKGSession` over an authenticated network … the distributed
  wrapper at the consensus layer reuses every primitive imported here."

So for the live M-Chain lane (corona) a dealerless genesis is **already
expressible** with existing primitives; GATE C supplies the per-node
driver.

### 2.4 Transport

- `mpc/pkg/transport`: authenticated `Transport.Send(ctx, nodeID, data)`,
  `Message`, `MessageHandler`, pubsub `MessageQueue` — the MPC custody bus.
- `pkg/thresholdd/server.go` `ZapServer`: the ZAP RPC surface that today
  exposes the in-process orchestrators.
- consensus engine: leaderless app-gossip (the BLS-vote / quorum-cert
  bus) carries per-height consensus messages between validators.

The cryptographic property (single-share custody) is **transport-agnostic**:
it is proven by giving each node a separate state object and moving only
the round messages between them. GATE C's tests use an in-memory message
bus to prove the property without standing up a network; production wiring
binds the same messages to one of the buses above (the
`DistributedSigner` emits/consumes plain serializable messages, so any of
the three carriers works).

## 3. The DistributedSigner (pulsar v0.3 lane) — BUILT + PROVEN

Lives in the `pulsar` package itself (`ref/go/pkg/pulsar/distributed.go`),
a sibling to `orchestrate.go`, because the message-driven Round-2 bridge
needs the package-private `polyVec`/`unpackPolyVec` (no external package
can reach them — see `docs/_gatec/README.md`). One node = one
`*AlgebraicKeyShare`. Proven against released `pulsar v1.1.1` (3 tests
green + grep + non-disruption); the source + reproduction are checked in
under `docs/_gatec/` because pulsar HEAD is concurrently mid gate-A
refactor that removed the v0.3 algebraic API from `main`.

### 3.1 Message protocol

```
Round 0  SessionMsg   { From NodeID; Encaps map[NodeID]{Ct,Sig} }
            per-pair ML-KEM-768 encapsulation + ML-DSA-65 auth toward
            every peer. Each node consumes peers' SessionMsgs, runs
            VerifyPeerEncapsulation against peers' PUBLIC identity keys,
            and derives ONLY its own pairwise key row. No process holds
            any other node's private identity key.

Round 1  *pulsar.AlgebraicRound1Message   (commit D_i + per-pair MACs)
Round 2W *pulsar.AlgebraicRound2Message   (W-only reveal w_i)
Round 2S *pulsar.AlgebraicRound2Message   (full Z,CS2,CT0 + MACs)

Aggregate (any node): pulsar.AlgebraicAggregateCtx over the collected
            Round-1 + Round-2 arrays. Input has NO share. On
            ErrAlgebraicRestart every node advances attempt+1 and
            re-emits Rounds 1/2 (session keys are attempt-independent —
            QuorumSessionKeys binds (sid,msg), not attempt).
```

### 3.2 Round flow (per node, identical code on every validator)

```
n := distsign.NewNode(params, setup, myShare, myIdentity, peerDirectory,
                       quorum, evalPoints, sid, ctx, msg)   // 1 share in
n.SessionRound()  -> SessionMsg            ; broadcast
n.IngestSessions(peers)                    ; derive own key row
for attempt := 0 ; ; attempt++ {
    n.BeginAttempt(attempt)                ; fresh inner AlgebraicThresholdSigner
    r1  := n.Round1()                      ; broadcast
    r2w := n.Round2W(allR1)                ; broadcast
    r2  := n.Round2Sign(allR1, allR2W)     ; broadcast
    sig, err := distsign.Aggregate(n.AggCtx(), allR1, allR2)
    if err == nil { return sig }           ; verifies under pulsar.VerifyCtx
    if !errors.Is(err, pulsar.ErrAlgebraicRestart) { fail }
}
```

`Aggregate` takes an `AggParams` carrying the public setup, quorum,
eval-points, `sid`, `attempt`, `ctx`, `msg`, the threshold, and the
aggregator's OWN pairwise key row — never a share.

### 3.3 The single-share invariant (how it is enforced + proven)

- **Type system.** `Node.share` is a single `*pulsar.AlgebraicKeyShare`,
  not a slice. `NewNode` takes one share. `Aggregate`'s parameter struct
  has no share field. There is no API path by which a `Node` or an
  aggregate call receives ≥2 shares.
- **Runtime test.** `TestDistributedSign_SingleShareCustody` builds `n`
  separate `Node` objects, asserts `node.ShareCount() == 1` for each,
  drives the full ceremony over an in-memory bus, verifies the signature
  under unmodified `pulsar.Verify`/`VerifyCtx`, and asserts a `(t-1)`
  sub-quorum cannot produce a verifying signature.
- **Grep guard.** `grep -nE '\[\]\*AlgebraicKeyShare|quorumShares|allShares'`
  over `distributed.go` returns nothing in code (only comments asserting
  their absence). The only share-bearing surfaces are the singular
  `share *AlgebraicKeyShare` struct field and constructor param.

## 4. Wiring (chain path) and what stays fenced

- The **chain path** (quasar M-Chain signer) drives `distsign.Node` —
  one per validator process — and aggregates from messages.
- `OrchestrateV03Sign{,Ctx}` and `DealAlgebraicV03Shares` remain ONLY in
  `pkg/thresholdd` for the off-chain JSON-RPC dispatcher (dev/test
  harness, MPC-bus fixtures, SDK tooling) and behind the explicit TEE
  custody gate. They are never on the chain finality path.
- `EpochManager` change (`consensus/protocol/quasar/epoch.go`): take a
  `selfNode NodeID` at construction; keep only `selfShare` for that node;
  replace the `for v := range era.State.Validators { era.State.Shares[v] }`
  fan-out with per-node share retention + message exchange. (Designed
  here; not landed — see §6.)

## 5. corona lane (live M-Chain finality) — DKG design

The genuine dealerless genesis for M-Chain is the corona Pedersen DKG
driven per-node:

```
each validator process p:
  sess_p := dkg2.NewDKGSession(params, p, n, t, suite)   // its own session
  r1_p   := sess_p.Round1WithSeed(localEntropy_p)        // broadcast commits;
                                                          // send (share,blind)_{p->j} privately to each j
  // collect r1_* from all peers (commits public; my (share,blind) addressed to me)
  s_p, badID, err := sess_p.Round2Identify(sharesToMe, blindsToMe, commits)
  // s_p is THIS node's share of the master secret; NO node holds s.
  beta_p := A·NTT(λ_p·s_p) + e_p'                         // Path-(a) flood; broadcast
  bTilde := Round_Xi(Σ_j beta_j)                          // public group key
```

This reuses every `dkg2` / `keyera` primitive; the only new code is the
per-node driver that replaces `finishBootstrapPedersen`'s in-process loop
with message exchange and one session per process. Identifiable abort
(`Round2Identify` → signed `Complaint`) is preserved per node.

## 6. Status: built vs partial

- **BUILT + PROVEN:** pulsar v0.3 `DistributedSigner`
  (`pulsar/ref/go/pkg/pulsar/distributed.go`; source + reproduction in
  `docs/_gatec/`): per-node session keys, rounds, message-only aggregate;
  multi-node test (`distributed_test.go`) with separate state objects +
  in-memory bus proving (a) a verifying FIPS-204 signature
  (`TestDistributedSign_SingleShareCustody` + `_Ctx`), (b) one share per
  process (ShareCount==1, distinct), (c) sub-quorum cannot sign
  (`TestDistributedSign_SubQuorumCannotSign`: t-1 contributions →
  ErrInsufficientQuor; t-1 quorum → non-verifying sig). All green against
  released pulsar v1.1.1. Resolves the cited `OrchestrateV03Sign`
  co-location for the signing custody boundary.
- **DESIGNED, PARTIAL:** corona per-node distributed DKG driver (§5) and
  the `EpochManager` self-node refactor (§4). The primitives exist and are
  per-node-safe; the per-node network driver + consensus wiring is the
  remaining engineering.
- **RESEARCH-GRADE GAP (honest):** a dealerless, byte-FIPS-204-compatible
  ML-DSA (pulsar) DKG. Not built; not buildable by composition of existing
  primitives. The pulsar lane uses trusted-dealer / TEE genesis (fenced),
  while the *live* M-Chain finality lane (corona) has a genuine dealerless
  genesis path.

## 7. Remaining work for M-Chain permissionless

1. Land the corona per-node DKG driver + an n-node integration test
   (separate processes/objects + bus) proving dealerless genesis with the
   single-share property.
2. Refactor `EpochManager` to self-node custody (take `selfNode`, keep one
   share, exchange messages) for both bootstrap and reshare.
3. Wire `distsign.Node` (pulsar) and the corona per-node signer to the
   consensus app-gossip / MPC bus; fence the `thresholdd` orchestrators to
   dev/test by construction (not just by docstring).
4. Resharing (`lss` / corona reshare) must also be driven per-node — today
   `EpochManager` reshare reads every share in-process (`epoch.go:505-509`).
5. (Optional, research) a dealerless ML-DSA DKG if the pulsar lane is ever
   to be permissionless at genesis without a dealer/TEE.
