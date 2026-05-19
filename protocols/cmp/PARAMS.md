# PARAMS — CGGMP21 (Lux Profile)

> Parameter-set registry for the Lux CGGMP21 profile.

## §1 Pinned curve

The Lux profile uses **secp256k1 exclusively**:

| Field | Value |
|---|---|
| Curve | secp256k1 |
| Curve order | `2^256 - 432420386565659656852420866394968145599` (n) |
| Hash | SHA-256 |
| Transcript-binding tag | `lux-cmp-secp256k1-v1` |
| Signature size | 70-72 bytes (DER-encoded) |
| Single-party verifier | RFC 6979 / SEC1 ECDSA verification |
| LP | [LP-4720](https://github.com/luxfi/LPs/blob/main/LPs/lp-4720-cggmp21-threshold-ecdsa-precompile.md) |

## §2 Paillier parameters

| Field | Value |
|---|---|
| Modulus bit length | 2048 |
| Modulus type | Biprime (product of two distinct safe primes) |
| Prime quality | Per CCS '21 Appendix C |
| Generation source | `pkg/paillier` |

The 2048-bit choice matches CCS '21 §6.1 recommendation. Smaller
moduli (1024) would not provide the 112-bit security margin
required.

## §3 Pedersen parameters

| Field | Value |
|---|---|
| Source | `pkg/pedersen` |
| Generation | Derived at keygen alongside Paillier (per CCS '21 §6.2) |
| Group | Subgroup of (Z/NZ)* where N is the party's Paillier modulus |

## §4 Threshold ranges

| Range | Bound |
|---|---|
| Minimum `t` | 2 |
| Maximum `n` | 32 |

The upper bound of 32 reflects the quadratic cost of Paillier
operations per signing round. Above n=32, presign latency exceeds
operational windows for high-throughput bridge use cases.

### 4.1 Recommended operating points

| Use case | Pinned (t, n) | Rationale |
|---|---|---|
| Bitcoin/Ethereum bridge custody | (5, 9) | Industry standard; 4-Byzantine tolerance |
| Cross-chain relay | (3, 5) | Faster signing; lower tolerance |
| Account-abstracted threshold wallet | (2, 3) | Minimum-viable threshold |
| Federated DEX custody | (7, 11) | Wider committee, same tolerance |

These are recommendations, not normative. Deployments may choose
any `(t, n)` within §4.

## §5 Zero-knowledge subprotocol parameters

The Lux profile uses CCS '21 ZK subprotocols (`pkg/zk/*`) without
modification:

| Subprotocol | Purpose | Lux profile delta |
|---|---|---|
| `affg`, `affp` | Affine ciphertext relations | none |
| `dec`, `enc`, `encelg` | Paillier ciphertext relations | none |
| `fac` | Factorization-soundness | none |
| `log`, `logstar` | Discrete-log relations | none |
| `mod` | Modular-arithmetic relations | none |
| `mul`, `mulstar` | Multiplicative relations | none |
| `nth` | n-th-power relations | none |
| `prm` | Pedersen-parameter relations | none |
| `sch`, `elog` | Schnorr / extended-log proofs | none |

## §6 Round parameters

| Phase | Rounds | Latency target |
|---|---|---|
| Keygen | 4 | <10 seconds per party (n=7) |
| Presign | 3 | <500 ms per party (n=7) |
| Sign | 1 | <50 ms per party (n=7) |

Latency targets are operational; signing throughput SHOULD precompute
presignatures to keep online signing latency at the §6 row's value.

## §7 Cross-references

- `SPEC.md` §3 — integration contract
- `README.md` — overview
- LP-4720 / LP-4730 / LP-4700
- Upstream: CCS '21 + ePrint 2021/060
