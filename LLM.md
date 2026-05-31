# LLM.md - Threshold Signatures Library

AI assistant context for the Lux Threshold Signatures Library.

## Project Overview

Production-ready universal threshold signature implementation supporting 20+ blockchains with post-quantum security. Written in Go 1.25, forked from `taurusgroup/multi-party-sig`.

## Architecture

```
threshold/
├── cmd/threshold-cli/     # CLI tool
├── cmd/thresholdd/        # JSON-RPC 2.0 daemon — all six schemes over one socket (127.0.0.1:7300)
├── internal/              # Private implementation details
│   ├── bip32/            # BIP-32 key derivation
│   ├── elgamal/          # ElGamal encryption
│   ├── mta/              # Multiplicative-to-Additive conversion
│   ├── ot/               # Oblivious transfer (recently updated from upstream)
│   ├── params/           # Protocol parameters (ZKModIterations=128)
│   ├── round/            # Round-based protocol framework
│   └── test/             # Testing infrastructure
├── pkg/                   # Public API
│   ├── ecdsa/            # ECDSA signatures
│   ├── hash/             # BLAKE3-based hashing
│   ├── math/             # Cryptographic arithmetic (curve, polynomial, sample)
│   ├── paillier/         # Homomorphic encryption
│   ├── party/            # Party identification
│   ├── pool/             # Thread pool for parallelization
│   ├── protocol/         # Protocol handler framework
│   ├── taproot/          # BIP-340/341 support
│   └── zk/               # 17 zero-knowledge proof systems
├── protocols/             # Protocol implementations
│   ├── cmp/              # CMP ECDSA (4-round signing, 7-round presign)
│   ├── frost/            # FROST Schnorr/EdDSA (2-round signing)
│   ├── lss/              # LSS dynamic resharing
│   ├── doerner/          # 2-of-2 optimized ECDSA
│   ├── corona/           # Post-quantum lattice-based (R-LWE)
│   └── bls/              # BLS aggregate signatures
└── docs/                  # Documentation
```

## Key Protocols

| Protocol | Algorithm | Rounds | Performance | Features |
|----------|-----------|--------|-------------|----------|
| **CMP** | ECDSA | 4 sign, 7 presign | ~15ms | Identifiable aborts |
| **FROST** | Schnorr/EdDSA | 2 | ~8ms | BIP-340 Taproot |
| **LSS** | ECDSA | Variable | ~35ms reshare | Dynamic resharing |
| **Doerner** | ECDSA | 2-party | ~5ms | Constant-time |
| **Corona** | Lattice (R-LWE) | Variable | - | Post-quantum |

## Important Conventions

### Naming Differences from Upstream

This fork uses different field naming from upstream `taurusgroup/multi-party-sig`:
- `Delta` (public) instead of `_Delta` (private)
- `_KDelta` instead of `_K_Delta`

When merging upstream, adapt their code to our conventions.

### Security Parameters

Key constants in `internal/params/params.go`:
- `SecParam = 256` - Security parameter (bits)
- `OTParam = 128` - OT security parameter
- `StatParam = 80` - Statistical security
- `ZKModIterations = 128` - Paillier-Blum validation (increased from 12 for security)
- `BitsBlumPrime = 1024`, `BitsPaillier = 2048`

### Package Imports

Use luxfi packages exclusively:
```go
import (
    "github.com/luxfi/threshold/pkg/..."
    "github.com/luxfi/threshold/internal/..."
    "github.com/luxfi/threshold/protocols/..."
)
```

Use `luxfi/crypto`, `luxfi/log`, `luxfi/zmq` exclusively.

## thresholdd — unified JSON-RPC dispatcher

The dispatcher itself lives in **`pkg/thresholdd/`** (importable
package: `github.com/luxfi/threshold/pkg/thresholdd`). Two startup
paths consume the same `NewServer()`:

1. **`cmd/thresholdd/`** — standalone CLI binary used for development,
   CI, and the JSON-RPC test rig in `pkg/thresholdd/thresholdd_test.go`.
2. **`luxfi/mpc`'s production daemon `mpcd`** — embeds the dispatcher
   on `--threshold-listen` (default `127.0.0.1:7300`). In production
   there is exactly one daemon: `mpcd`. The standalone `thresholdd`
   exists for dev tooling and as the canonical test surface.

Both expose every scheme (cggmp21, frost, pulsar, corona, bls,
doerner) on one process-local socket. Wire format mirrors the teleport
mpc bus (`teleport/mpc/src/signers/rpc.ts`):

```
POST / with body:
  {"jsonrpc":"2.0","id":N,"method":"<scheme>.<op>","params":{...}}
```

Methods (three ops per namespace):

| Method | Params | Result |
|--------|--------|--------|
| `<scheme>.keygen` | `{threshold, participants}` | `{publicKey: hex, shares: [hex, ...]}` |
| `<scheme>.sign` | `{messageHex, pubKeyHex}` | `{signatureHex}` |
| `<scheme>.verify` | `{messageHex, signatureHex, pubKeyHex}` | `{ok: bool}` |

Bind defaults to `127.0.0.1:7300` (process-local IPC; not network-
exposed). `--listen :0` takes a random port for parallel test runs.

Status per scheme:
- `cggmp21` — full keygen + sign via `protocols/cmp` (CGGMP21 fork)
- `frost` — full RFC 9591 secp256k1 via `protocols/frost`
- `pulsar` — full Pulsar M-LWE via `luxfi/corona/threshold`
- `corona` — full Corona R-LWE via `luxfi/threshold/protocols/corona`
- `bls` — full Shamir/Lagrange via `protocols/bls.TrustedDealer`
- `doerner` — round-protocol non-functional upstream; surface reserved,
  every op returns an explicit error. Fix upstream and remove the guard.

Pulsar/Corona Signature/GroupKey types lack stable wire encodings, so
the daemon mints opaque 32-byte tokens for `publicKey` and signature
handles and stashes the live objects in-process. Tokens are not durable
across daemon restarts — this is by design for process-local IPC.

Tests: `go test ./cmd/thresholdd/ -timeout 600s` (8 tests, ~15s total).

## Recent Changes (December 2024)

### Upstream Merge
- Increased `ZKModIterations` from 12 to 128 (security fix)
- Improved Extended OT monochrome check (based on paper revision)
- Added `doubleFieldElement` type for proper GF(2^k) multiplication
- New functions: `randFe`, `pluckColumnToFieldElement`, `transposeToFieldSizeElements`, `adjustBatchSize`

### Cleanup
- Renamed legacy upstream references to Lux throughout
- Removed obsolete `.old` and `.bak` files
- Updated chain symbol to LUX

## Testing

```bash
# Run all tests
go test ./... -timeout 120s

# Protocol-specific
go test ./protocols/cmp/... -timeout 120s
go test ./protocols/lss/... -timeout 120s
go test ./internal/ot/... -timeout 120s

# With race detection
go test -race ./... -timeout 180s
```

Note: `pkg/protocol` has a known flaky test (`TestHandler_WaitForResultTimeout`) unrelated to core functionality.

## Blockchain Support

**Tier 1 (Full Native)**: XRPL, Ethereum, Bitcoin, Solana, TON, Cardano
**Tier 2 (Ready)**: Cosmos, Polkadot, Lux, BSC, NEAR, Aptos, Sui, Tezos, Algorand, Stellar, Hedera, Flow, Kadena, Mina

EVM chains use `protocols/lss/adapters/evm.go` with chain config in `GetChainConfig()`.

## Performance Benchmarks

| Operation | 3-of-5 | 5-of-9 | 7-of-11 | 10-of-15 |
|-----------|--------|--------|---------|----------|
| Key Gen | 12ms | 28ms | 45ms | 82ms |
| Signing | 8ms | 15ms | 24ms | 40ms |
| Resharing | 20ms | 35ms | 52ms | 75ms |
| Verification | 2ms | 2ms | 2ms | 2ms |

## Common Tasks

### Adding a New Chain Adapter

1. Add chain constant in `protocols/lss/adapters/evm.go` or appropriate file
2. Add config in `GetChainConfig()`
3. Update `protocols/lss/factory.go` with chain info
4. Add to `SupportedChains()` list
5. Update tests in `full_coverage_test.go`

### Merging Upstream

```bash
git remote add upstream https://github.com/taurusgroup/multi-party-sig.git
git fetch upstream
git log --oneline upstream/main ^main  # Check new commits
# Manually apply changes adapting naming conventions
```

## Dependencies

Core:
- `github.com/cronokirby/saferith` - Constant-time arithmetic
- `github.com/zeebo/blake3` - Fast hashing
- `github.com/fxamacker/cbor/v2` - Binary serialization

Lux:
- `github.com/luxfi/crypto`
- `github.com/luxfi/log`
- `github.com/luxfi/zmq/v4`

## References

- CMP Protocol: https://eprint.iacr.org/2021/060
- FROST Protocol: https://eprint.iacr.org/2020/852.pdf
- OT Extensions: https://eprint.iacr.org/2015/546
- LSS Protocol: `protocols/lss/README.md`
