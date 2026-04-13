# mldsa-bench

Benchmarks PQ signing patterns for Lux quasar consensus and the
hierarchical quorum architecture of [LP-045](../../../lps/LP-045-hierarchical-quorum-certs.md).

## Build

```bash
cd github.com/luxfi/threshold
go build ./cmd/mldsa-bench/
```

## Modes

### `individual`
Every validator signs the block hash; verifier verifies all sigs.
Baseline — "what it costs if we never aggregate."

### `committee`
Sample `k` of `n` validators; those `k` sign individually. Represents one
cluster in the hierarchical design.

### `hierarchical`
`n` validators partitioned into `clusters`. Each cluster signs, clusters
combine into a root QC. Models LP-045 two-layer aggregation.

## Measured on a MacBook M3 (10 cores, arm64)

### Individual signing (pre-aggregation baseline)

| n | Keygen | Sign (parallel) | Verify (parallel) | Per-validator sign | Sig total |
|---|--------|-----------------|-------------------|--------------------|-----------|
| 3   | 587 µs   | 1.78 ms | 366 µs | 592 µs | 7.3 kB |
| 5   | 1.72 ms  | 2.20 ms | 637 µs | 439 µs | 12.1 kB |
| 10  | 1.02 ms  | 1.70 ms | 693 µs | 170 µs | 24.2 kB |
| 100 | 14.4 ms  | 8.87 ms | 3.57 ms | 89 µs  | 242 kB |

Per-validator latency drops as n grows because keygen/sign run in parallel
across 10 cores. Raw cost per signature: ~430 µs sign, ~40 µs verify.

### Committee (sampled subset signs)

| n | k | Sign | Verify | Sig size |
|---|---|------|--------|----------|
| 100 | 32 | 3.57 ms | 4.14 ms | 77 kB |
| 100 | 64 | 8.05 ms | 6.34 ms | 155 kB |

### Hierarchical (LP-045 two-layer)

| n | clusters | cluster size | Sign | Verify | Sig total |
|---|----------|--------------|------|--------|-----------|
| 100 | 4  | 25 | 14.7 ms | 5.35 ms | 242 kB |
| 100 | 10 | 10 | 10.0 ms | 5.09 ms | 242 kB |

### ML-DSA-65 (NIST Level III)

| n | mode | Sign | Verify | Sig size |
|---|------|------|--------|----------|
| 100 | individual   | 25.1 ms | 9.4 ms  | 331 kB |
| 100 | hierarchical (4 clusters) | 21.3 ms | 22.6 ms | 331 kB |

## Key findings

1. **100 validators sign in under 10 ms** on a single laptop at ML-DSA-44.
   No threshold math needed at this stage — it's just parallel individual signatures.

2. **Committee sampling (k=32)** cuts signing work by 3× vs all-100 signing.
   This is the LP-045 primary optimization.

3. **Hierarchical aggregation is a workload-shaping tool**, not a compute
   reduction. Total compute is the same; it's parallelizable across cluster
   aggregators and moves the verification cost off the chain's hot path.

4. **ML-DSA-65 is ~3× slower** than ML-DSA-44 on this hardware. Level III
   at 100 validators is still under 30 ms per block — fine for Quasar
   finality at any realistic block time.

## Light mnemonic

The harness derives 100 deterministic keypairs from a single 32-byte master
seed. No interactive keygen, no mainnet wallet material, no network I/O.
Reproducible across runs — same seed yields the same validators.

To use a real mnemonic instead (for localnet tests that need persistence),
swap the seed source for `BIP39 → BIP32 → per-validator child` derivation.

## Running on localnet

The same harness can drive a real network. Start a localnet with
[netrunner](../../netrunner/) and the bench calls the validator RPCs for
actual block-signing timing:

```bash
# Start 3-node localnet
cd $LUX/netrunner
./bin/netrunner start-local --num-nodes=3 --network-id=1337

# (After extending mldsa-bench with a --rpc-endpoints flag)
./mldsa-bench -mode=individual -n=3 -level=44 \
  -rpc-endpoints=http://127.0.0.1:9650,http://127.0.0.1:9652,http://127.0.0.1:9654
```

The benchmark then issues `quasar.signBlock` RPCs to the localnet
validators instead of running in-process.

## Usage

```bash
# Minimal
./mldsa-bench -mode=individual -n=10

# Full
./mldsa-bench -mode=hierarchical -n=100 -clusters=4 -level=65 -runs=5
```
