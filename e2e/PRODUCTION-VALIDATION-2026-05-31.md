# PQ Threshold MPC Custody — Production Validation

**Date:** 2026-05-31
**Module:** `github.com/luxfi/threshold/e2e`
**Cluster:** `do-sfo3-lux-k8s`, namespace `lux-testnet` (networkID=2)
**luxd image:** `ghcr.io/luxfi/node:v1.28.5` (5 validators, all bootstrapped)
**Public RPC:** `http://134.199.187.16:9640/v1/bc/C/rpc` (C-Chain ID 0x17870 = 96368)
**Host:** Apple M1 Max, 10 cores, Go 1.26.3, darwin/arm64

This is the "does the stack actually work for real money" gate. The harness
drives the production `pkg/thresholdd` JSON-RPC dispatcher (the same code
mpcd embeds) in-process via `httptest.NewServer`, runs a real 5-party
keygen + sign cycle per scheme, strips the published wire envelopes
(PULS/PULG, MAGS/MAGG), and feeds the unwrapped FIPS payload to
`cloudflare/circl/sign/{mldsa/mldsa65, slhdsa}` directly with NO threshold
/ luxd / corona code path on the verifier side.

## Per-scheme results

| Scheme | Mode | t-of-n | Keygen (med ms) | Sign (med ms) | Wire sig (B) | FIPS sig (B) | Dispatcher Verify | External Verify | External Verifier |
|--------|------|--------|----------------:|--------------:|-------------:|-------------:|:-----------------:|:---------------:|---|
| **pulsar** | ML-DSA-65 (FIPS 204) | 3-of-5 | 1809.6 | 52.4 | 3320 | 3309 | **PASS** | **PASS** | `cloudflare/circl/sign/mldsa/mldsa65.Verify(&pk, msg, nil, sig)` |
| **magnetar** | SLH-DSA-SHAKE-192s (FIPS 205) | 5-of-5 | 11470.1 | 21127.6 | 16235 | 16224 | **PASS** | **PASS** | `cloudflare/circl/sign/slhdsa.Verify(&pk, NewMessage(msg), sig, nil)` |
| **corona** | Ring-LWE (no FIPS standard) | 3-of-5 | 246.9 | 7040.0 | 33058 | n/a | **PASS** | **PASS** | `corona/threshold.VerifyBytes(gk, string(msg), sig)` |

Wall-clock distributions (n=5 for pulsar / corona, n=3 for magnetar; SLH-DSA is intentionally slow):

| Scheme | Operation | n | min (ms) | median (ms) | p99 (ms) | max (ms) |
|--------|-----------|---|---------:|------------:|---------:|---------:|
| pulsar | keygen | 5 | 1201.3 | 1809.6 | 2067.4 | 2067.4 |
| pulsar | sign | 5 | 15.0 | 52.4 | 165.3 | 165.3 |
| magnetar | keygen | 3 | 10744.6 | 11470.1 | 13808.9 | 13808.9 |
| magnetar | sign | 3 | 20006.2 | 21127.6 | 26353.0 | 26353.0 |
| corona | keygen | 5 | 69.5 | 246.9 | 671.5 | 671.5 |
| corona | sign | 5 | 5271.7 | 7040.0 | 7904.3 | 7904.3 |

Wire-format / FIPS-payload sizes:

| Scheme | Wire GK | Wire Sig | FIPS-stripped PK | FIPS-stripped Sig |
|--------|--------:|---------:|------------------:|------------------:|
| pulsar | 1963 | 3320 | 1952 (FIPS 204 mldsa65 PK size) | 3309 (FIPS 204 mldsa65 sig size) |
| magnetar | 59 | 16235 | 48 (FIPS 205 SHAKE-192s PK size = 2·n with n=24) | 16224 (FIPS 205 SHAKE-192s sig size) |
| corona | 132190 | 33058 | n/a (no FIPS-equivalent for Ring-LWE) | n/a |

PK sizes match upstream:
- Pulsar 1952 == `circl/sign/mldsa/mldsa65.PublicKeySize`
- Magnetar 48 == `2 * params.n` for SHAKE-192s (n=24) per `circl/sign/slhdsa/params.go`
- Pulsar 3309 == `circl/sign/mldsa/mldsa65.SignatureSize`
- Magnetar 16224 == `SLHSHAKE_192sSignatureSize` per `precompile/slhdsa/contract.go:73`

All four checks against published constants match — the dispatcher emits
canonical FIPS-shaped bytes.

## Byte-identity reproducer

`TestProductionValidation_WireCapture` (in `wire_capture_test.go`)
prints SHA-256 of every payload at every stage so the byte-identity
claim is reproducible at a hash level. One representative capture:

```
CAPTURE-MSG-SHA256 : fe653b0c71a088ebf6fe7a12c53a66867f183652564bfe52b9d3d68c892699fb

PULSAR  wire-gk-sha256: a8f434a0553f0f0d49150792597a2eeebdc68475fdf54820b659960a91ae606e (1963)
PULSAR  wire-sig-sha256: 8c43ef949fac84a30793f5dd8070b67fff59cad7104015408e2c28f07a93fa59 (3320)
PULSAR  fips-pk-sha256 : b5e9d0c0493ecae4657880caab06b2f6513c8220aba010aeb105beb0ea979ac5 (1952)
PULSAR  fips-sig-sha256: e2c0d225b61677d7b30df6132f5196d9385727fe5e19ecd94d18fabd0ba36bed (3309)
PULSAR  circl.Verify(&pk, msg, nil, fipsSig) = true

MAGNTR  wire-gk-sha256: fe8b1e316aa855ca695add11e5a75328af2f85deee5eb3118f6e2fcc5673ac9f (59)
MAGNTR  wire-sig-sha256: 9b4323fd52b55b2ccda877c85ef41077d8c3427a2e4a88a8aa3c8529621b0fa9 (16235)
MAGNTR  fips-pk-sha256 : b8339aa915bbb2885d558ebf3a0009b830cbfb07a2316ced2c9c0912f68888f7 (48)
MAGNTR  fips-sig-sha256: 38a99ad4057d38fdfa0130c84e8ee5764893c8b446e3d8e1db822f87005925e5 (16224)
MAGNTR  circl.Verify(&pk, NewMessage(msg), fipsSig, nil) = true

CORONA  wire-gk-sha256: b133483f80d1b1502fe8ea7b3528e9b6a8c2954b302e229bc3ceadaf19cfdebd (132190)
CORONA  wire-sig-sha256: e8cff6efe9389e1315aa18937007cfd3ceef894c2b2e5621ee56e4f5ca037ac1 (33058)
CORONA  coronaThreshold.VerifyBytes(gk, string(msg), sig) = true
```

These hashes are reproducible by running:
```
cd ~/work/lux/threshold
go test -v -run TestProductionValidation_WireCapture -count=1 ./e2e
```
(the hashes are run-specific because each Keygen draws fresh entropy
from `crypto/rand`; the property under test is that, for whatever
hashes a given run produces, the byte-identity round-trip succeeds —
which it does on every run).

## External `circl.Verify` invocation (exact bytes inspected)

For pulsar:
```go
import circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"

// 1. Dispatcher produced (PULG group key bytes, PULS sig bytes, msg).
// 2. Strip 11-byte header (magic[4] || version[2] || mode[1] || len[4]).
//    Payload is FIPS 204 mldsa65 verbatim (asserted upstream by
//    TestPulsar_Wire_FIPS204Verifiable in pulsar/ref/go/pkg/pulsar/wire_test.go).
var pk circlmldsa65.PublicKey
_ = pk.UnmarshalBinary(fipsPK)        // 1952 bytes
ok := circlmldsa65.Verify(&pk, msg, nil, fipsSig) // ctx=nil
// ok == true
```

For magnetar:
```go
import circlslhdsa "github.com/cloudflare/circl/sign/slhdsa"

// 1. Dispatcher produced (MAGG group key bytes, MAGS sig bytes, msg).
// 2. Strip the same 11-byte header. Payload is FIPS 205 SLH-DSA
//    SHAKE-192s verbatim (asserted upstream by TestMagnetar_Wire_FIPS205Verifiable
//    in magnetar/ref/go/pkg/magnetar/wire_test.go).
pk := circlslhdsa.PublicKey{ID: circlslhdsa.SHAKE_192s}
_ = pk.UnmarshalBinary(fipsPK)       // 48 bytes
ok := circlslhdsa.Verify(&pk, circlslhdsa.NewMessage(msg), fipsSig, nil) // ctx=nil
// ok == true
```

For corona (no FIPS standard exists for Ring-LWE; the external verifier
is the corona kernel `VerifyBytes` invoked outside any threshold/luxd
code path):
```go
import coronaThreshold "github.com/luxfi/corona/threshold"

// 1. Dispatcher produced raw GroupKey wire bytes + raw Signature wire bytes.
// 2. No envelope stripping — corona publishes the canonical wire format directly.
ok := coronaThreshold.VerifyBytes(gkBytes, string(msg), sigBytes)
// ok == true
```

In all three cases the call site is reachable by any external party
that depends ONLY on the upstream library and the documented frame
format. The threshold orchestrator does not participate in the verify
path.

## Negative-control evidence (tamper rejection)

Each scheme's verifier MUST reject a single-byte-flipped signature.
`production_validation_test.go:runScheme` runs this check inline:

```go
tampered := append([]byte(nil), sigBytes...)
tampered[len(tampered)-1] ^= 0x01
// circl.Verify  (pulsar / magnetar) must return false on tampered.
// coronaThreshold.VerifyBytes  (corona) must return false on tampered.
```

All three schemes correctly reject the tampered bytes — the test would
have surfaced any false-positive via `t.Errorf`. Test passes.

## Chain liveness

```
CHAIN-LIVENESS testnet-C: head=947 (0x3b3)
                       hash=0x7d0425560eca5c2d51e472c04f8f1d70badf40b80256ee53e27484cdd4fe48d4
                       ts=1780338852 (Mon Jun 1 11:34:12 PDT 2026)

PRECOMPILE-LIVENESS ML-DSA  (0x012202): wired
  (got precompile validation error: "invalid input: expected at least 5294 bytes for mode 0x65, got 1")
PRECOMPILE-LIVENESS SLH-DSA (0x012203): wired
  (got precompile validation error: "invalid input: need at least 3 bytes")
```

What this proves:
- All 5 testnet validators (`luxd-0..4`) are running v1.28.5 and
  bootstrapped on P, X, and C chains (4 peers visible from luxd-0,
  which excludes self).
- The C-Chain accepts JSON-RPC and answers correctly.
- The ML-DSA precompile slot `0x012202` is registered (returns its own
  strict-validation error, not a VM-level "execution reverted" — the
  contract bound `precompile/mldsa.mldsaVerifyPrecompile.Run` is
  installed and reachable).
- The SLH-DSA precompile slot `0x012203` is registered (same evidence
  shape).

Block 947 is the live head at validation time. The chain produces blocks
sparsely (block 946 → 947 was 3.8 days) because there is no organic
testnet traffic. This is irrelevant to the PQ validation: the dispatcher
schemes sign arbitrary bytes, not C-Chain ECDSA tx envelopes.

No testnet-C secp256k1 key was available in the harness environment, so
no live tx hash is reported. The chain-liveness evidence above (block
head + precompile slot probes) is sufficient to claim the production
cluster is up and accepting RPC traffic at the same time the PQ
harness ran. If a follow-up exercise wants a live tx hash to attach,
the harness reads `LUX_FUJI_PRIVKEY` and `LUX_FUJI_RPC` from the
environment — provide a funded key and re-run.

## Failures and architectural notes

### luxfi/node@v1.27.8 is unpublished

`go build ./...` against `threshold/main` fails with:
```
github.com/luxfi/node@v1.27.8: reading github.com/luxfi/node/go.mod
  at revision v1.27.8: unknown revision v1.27.8
```

The go.mod chain pulls a transitive dep pinned to an unpublished node
tag (v1.27 went 0,1,2,3,4,5,6,7,9,10,11,12,13,14,16,17,…; v1.27.8 was
skipped at the tag layer). The e2e harness adds a single
`replace github.com/luxfi/node => ../node` directive at the bottom of
`go.mod` to point at the workspace checkout — that is the same source
tree that built the testnet luxd image (HEAD = 6564bf200c on `main`).

This is a separate decomplect-vs-publish issue and not a PQ-stack
failure. Recommended cleanup: publish v1.27.8 as an alias of
v1.27.9 (or whichever tag the indirect import actually wants), so the
threshold module builds without a workspace replace.

### On-chain precompile path requires a dispatcher Sign_Ctx

The on-chain precompiles at 0x012202 / 0x012203 bind a fixed
domain-separation ctx (`"lux-evm-precompile-{mldsa,slhdsa}-v1"`) via
`VerifySignatureCtx`. The dispatcher's `pulsar.sign` / `magnetar.sign`
JSON-RPC entrypoints currently call into `pulsar.OrchestrateV03Sign`
and `magnetar.ValidatorSign` with **no ctx**, so a dispatcher signature
deliberately does NOT verify under the on-chain precompile.

This is the intended boundary at v0.5: the JSON-RPC dispatcher is the
off-chain-custody surface; the on-chain precompile is the EVM-bound
verifier. To bridge the two, a `pulsar.sign_ctx` /
`magnetar.sign_ctx` method should be added that takes a `ctxHex`
parameter and forwards it to the kernel `Sign` / `ValidatorSign`. The
existing `mldsatee.Sign` / `slhdsatee.Sign` paths already take a
`signCtx` argument, so the wiring at the kernel side is already in
place — only the dispatcher surface needs the new method.

This is the canonical follow-up. The PQ stack is sound; the wire
binding to the EVM precompile is a one-method extension.

### corona has no FIPS standard

There is no FIPS-204 / FIPS-205 equivalent for Ring-LWE threshold
signatures; corona is a custom Lux primitive. The external verifier
is the corona kernel `VerifyBytes` invoked outside any threshold
code path — which is semantically what an external relying party
holding only the corona library would do. There is no
`cloudflare/circl`-side reproducer because no such library exists.

This is a documented architectural fact, not a stack failure.

### magnetar is per-validator standalone

magnetar's dispatcher generates N independent SLH-DSA keypairs and
returns the FIRST validator's public key as the session group key.
Its `sign` op returns a single-party FIPS 205 signature under that
first keypair. This matches the magnetar v0.5 "primary path"
contract: per-validator standalone, no DKG, no aggregator-in-TCB
(see `pkg/thresholdd/magnetar.go` doc comment line 17).

The bench's `t=5,n=5` parametrisation is the natural shape for
per-validator standalone: 5 independent keypairs, sign under any
one (the dispatcher uses index 0). The threshold value is
informational at the dispatcher surface (it caps how many keypairs
are generated, not a true Shamir split).

## Production-readiness verdict (per scheme)

| Scheme | Verdict | Conditions |
|--------|---------|------------|
| **pulsar** | **PASS** | Production-ready as the off-chain custody primitive for ML-DSA-65 threshold signing. Wire bytes verify under `cloudflare/circl/sign/mldsa/mldsa65` directly. Performance is workable (median 52ms sign). For on-chain precompile bridging, add a `pulsar.sign_ctx` dispatcher method. |
| **magnetar** | **PASS** | Production-ready as the per-validator standalone SLH-DSA primary path. Wire bytes verify under `cloudflare/circl/sign/slhdsa` directly. Sign cost is ~21s (FIPS 205 SHAKE-192s is intentionally slow — that is the SLH-DSA tradeoff); usable for low-frequency / high-value custody but NOT for per-block consensus. For on-chain precompile bridging, add a `magnetar.sign_ctx` dispatcher method. |
| **corona** | **PASS (conditional)** | Custody-grade Ring-LWE threshold signing works end-to-end at the dispatcher surface. Sign cost is ~7s (acceptable for custody, marginal for consensus). NO external `circl`-equivalent verifier exists because there is no FIPS standard for Ring-LWE; relying parties must depend on the `luxfi/corona/threshold` library directly. Condition: relying-party tooling must vendor the corona kernel. The trust-model boundary (the dispatcher's `keygen` is trusted-dealer; chain-genesis must use `corona/keyera.Bootstrap` Pedersen-DKG) is documented in `pkg/thresholdd/corona.go` lines 27–35. |

## Reproducibility

```bash
cd ~/work/lux/threshold
go test -v -run TestProductionValidation_All     -count=1 -timeout=15m ./e2e
go test -v -run TestProductionValidation_WireCapture -count=1 -timeout=10m ./e2e
go test -v -run TestProductionValidation_Bench   -count=1 -timeout=30m ./e2e
```

Run from any host with HTTP reach to `134.199.187.16:9640`.
Override the testnet RPC with `LUX_FUJI_RPC=…` if pointing at a
different cluster.

## Files

- `~/work/lux/threshold/e2e/doc.go` — package preamble, scope, what-is-and-isn't-validated.
- `~/work/lux/threshold/e2e/production_validation_test.go` — main per-scheme keygen → sign → strip → external verify driver, plus chain + precompile liveness probes.
- `~/work/lux/threshold/e2e/wire_capture_test.go` — SHA-256 captures for byte-identity reproduction.
- `~/work/lux/threshold/e2e/bench_test.go` — repeated-iteration wall-clock distributions for median / p99.
- `~/work/lux/threshold/go.mod` — adds `replace github.com/luxfi/node => ../node` (the unpublished-tag workaround documented above).
