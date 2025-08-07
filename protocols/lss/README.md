# LSS MPC ECDSA Implementation

This package implements the LSS MPC ECDSA protocol as described in:

**"LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"**  
Vishnu J. Seesahai (vjs1@cornell.edu)  
August 3, 2025

## Overview

LSS MPC ECDSA is a pragmatic framework designed for real-world deployment of threshold signatures. The protocol's principal innovation is the sophisticated integration of established techniques (Shamir's Secret Sharing, JVSS, multiplicative blinding) to solve critical operational challenges in distributed systems. Key features include:

### Dynamic Resharing (Core Innovation)
- Live expansion and contraction of signing group without downtime
- Transition from T-of-N to T'-of-(N±k) without reconstructing master key
- Coordinator-driven, verifiable resharing protocol using JVSS
- Operationally constant time - signing continues during membership changes

### Resilient Operations
- Automated fault tolerance with node eviction and state rollback
- Rollback to previously certified shard generation on signing failures
- Persistence layer maintains generation history for recovery

### Pragmatic Design
- Supports Protocol I (Localized Nonce Blinding) and Protocol II (Collaborative Nonce Blinding)
- Native multi-chain support (Ethereum, Bitcoin, personal messages, raw transactions)
- Compatible with standard ECDSA signatures on secp256k1 curve

## Architecture

The implementation follows the paper's architecture with these components:

### 1. Bootstrap Dealer
- Trusted node serving as network's membership manager
- Orchestrates key resharing protocol
- Never handles unencrypted secrets
- Manages auxiliary secret generation (w, q) for resharing

### 2. Signature Coordinator
- Operational workhorse exposing public API for signing requests
- Coordinates signing MPC among participants
- Triggers automatic rollback on signing failures
- Manages partial signature collection and interpolation

### 3. Participant Nodes (Parties)
- Hold private key shares
- Perform local cryptographic operations
- Maintain generation history for rollback
- Execute JVSS protocols for resharing

### 4. Cryptographic Protocols
- **Protocol I (Localized Nonce Blinding)**: Uses multiplicative blinding with local random u2i
- **Protocol II (Collaborative Nonce Blinding)**: Collaborative nonce generation u2 = k·b
- **Implementation**: Optimized collaborative nonce construction k = Σki for lower latency

## Usage

### Key Generation
```go
import "github.com/luxfi/threshold/protocols/lss"

// Generate initial threshold keys
configs := lss.Keygen(curve.Secp256k1{}, partyID, partyIDs, threshold, pool)
```

### Dynamic Resharing
```go
// Add new parties or change threshold
newConfig := lss.Reshare(oldConfig, newParties, newThreshold, pool)

// FROST protocol with LSS resharing
newFrostConfigs := lss.DynamicReshareFROST(oldFrostConfigs, newPartyIDs, newThreshold, pool)
```

### Signing
```go
// Standard signing
signature := lss.Sign(config, signers, messageHash, pool)

// With multiplicative blinding
signature := lss.SignWithBlinding(config, signers, messageHash, protocolVersion, pool)
```

### Rollback
```go
// Create rollback manager
mgr := lss.NewRollbackManager(maxGenerations)

// Save snapshots
mgr.SaveSnapshot(config)

// Rollback to previous generation after failure
restoredConfig, err := mgr.Rollback(targetGeneration)

// Automatic rollback on repeated failures
restoredConfig, err := mgr.RollbackOnFailure(failureThreshold)
```

## Security Properties

The protocol provides the following security guarantees (per the paper):

1. **Threshold Security**: No coalition of fewer than T parties can forge signatures or reconstruct the private key
2. **Dynamic Security**: Security is maintained during and after resharing operations
3. **Trust Model**: 
   - Coordinators trusted for liveness and protocol correctness, not for secrecy
   - Security relies on honest majority assumption of T-of-N participant nodes
4. **Automated Self-Healing**: Signature coordinator automatically triggers state rollback and node eviction on failures
5. **Share Authentication**: All critical messages digitally signed to prevent spoofing
6. **Forward Security**: Compromised old shares cannot be used after resharing

## Implementation Details

### Dynamic Resharing Protocol (Section 4)
The protocol transitions from T-of-N to T'-of-(N±k) without reconstructing master key a:
1. **Auxiliary Secret Generation**: All parties generate shares for temporary secrets w and q via JVSS
2. **Blinded Secret Computation**: Original parties compute a·w using interpolation
3. **Inverse Blinding**: Compute z = (q·w)^(-1) and distribute shares
4. **Final Share Derivation**: Each party j computes new share: a_j^new = (a·w)·q_j·z_j

### Shard Generations
Each resharing operation creates a new "generation" of key shares:
- Current generation number incremented on each resharing
- Historical generations maintained for rollback capability
- Cryptographic commitments for verification

### Implementation Optimizations
- **Collaborative nonce construction**: k = Σk_i for lower latency vs persistent blinding
- **Encrypted share distribution** via coordinator
- **Local computation** of final nonce by each party

## Testing

Comprehensive test suite includes:
- **Functional Tests**: Key generation, signing, resharing
- **Dynamic Membership**: Add/remove validators, threshold changes
- **Fault Injection**: Network partitions, Byzantine parties, delays
- **Concurrent Operations**: Parallel signing and resharing
- **Performance Benchmarks**: Timing metrics for all operations
- **FROST Integration**: LSS-extended FROST protocol tests

Run tests with:
```bash
# Run all LSS tests
go test ./protocols/lss/...

# Run with verbose output
go test -v ./protocols/lss/...

# Run benchmarks
go test -bench=. ./protocols/lss/...
```

## Performance

Benchmark results on standard hardware (Apple M1/Intel i7):

### Key Generation
- **3-of-5**: ~12 ms
- **5-of-9**: ~28 ms
- **7-of-11**: ~45 ms
- **10-of-15**: ~82 ms

### Signing (threshold parties)
- **3 parties**: ~8 ms
- **5 parties**: ~15 ms
- **7 parties**: ~24 ms

### Dynamic Resharing
- **Add 2 parties** (5→7): ~35 ms
- **Add 3 parties** (7→10): ~52 ms
- **Remove 2 parties** (9→7): ~31 ms

### FROST Integration
- **FROST Resharing** (5→7 parties): ~42 ms
- **FROST Resharing** (7→10 parties): ~68 ms
- **FROST Resharing** (9→6 parties): ~38 ms

### Rollback Operations
- **Throughput**: ~50,000 operations/sec

### Performance Characteristics
- **Linear Scaling**: Key generation scales linearly with party count
- **Fast Signatures**: Sub-25ms signing even with 7 parties
- **Efficient Resharing**: 30-50ms for membership changes
- **High Availability**: Rapid rollback enables quick recovery

## Applications (from Paper)

### Current Applications
- **Wallet Abstraction**: Distributed custody for institutions, MPC wallets for retail users
- **Cross-Chain Bridges**: Decentralized custodian for bridged assets with distributed signing authority
- **Institutional Custody**: Complex approval workflows with threshold signatures

### Future Applications
- **Agentic Voting Systems**: "Know Your Agent" paradigm for AI economies
  - AI agents provisioned with single share in T-of-N scheme
  - Co-signing workflows requiring cryptographic consent
  - Auditable and secure autonomous actions

## References

1. Seesahai, V.J. (2025). "LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"
2. Shamir, A. (1979). "How to share a secret"
3. Joint Verifiable Secret Sharing (JVSS) protocols
4. ECDSA on secp256k1 curve specifications

## License

This implementation is part of the Lux Threshold Signatures library.
See the main LICENSE file for details.