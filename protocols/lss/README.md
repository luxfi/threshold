# LSS MPC ECDSA Implementation

This package implements the LSS MPC ECDSA protocol as described in:

**"LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"**  
Vishnu J. Seesahai (vjs1@cornell.edu)  
August 3, 2025

## Overview

LSS (presumably Lindell-Shamir-Shmalo or similar) MPC ECDSA is a pragmatic framework designed for real-world deployment of threshold signatures with the following key features:

### Dynamic Resharing
- Add or remove parties without reconstructing the master private key
- No downtime during membership changes
- Supports threshold modification (t-of-n → t'-of-n')

### Resilient Signatures
- Fault tolerance against non-responsive parties
- Rollback capability to previous shard generations
- Byzantine fault tolerance mechanisms

### Pragmatic Design
- Optimized for practical deployment scenarios
- Supports both Protocol I and Protocol II with multiplicative blinding
- Compatible with standard ECDSA signatures (Bitcoin, Ethereum)

## Architecture

The implementation consists of several key components:

### 1. Bootstrap Dealer
- Initiates dynamic resharing protocols
- Manages shard generation lifecycle
- Coordinates membership changes

### 2. Signature Coordinator
- Orchestrates threshold signing operations
- Handles partial signature aggregation
- Triggers rollback on failures

### 3. JVSS (Joint Verifiable Secret Sharing)
- Provides verifiable secret sharing for auxiliary values
- Ensures security during resharing operations
- Supports complaint mechanisms

### 4. Blinding Protocols
- Protocol I: Basic multiplicative blinding
- Protocol II: Enhanced blinding with additional security
- Protects against various attacks on the signing process

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
newConfig := lss.Reshare(oldConfig, newThreshold, newParties, pool)
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
// Rollback to previous generation after failure
err := lss.Rollback(config, targetGeneration, evictedParties)
```

## Security Properties

The protocol provides the following security guarantees:

1. **Threshold Security**: No coalition of fewer than t parties can forge signatures or reconstruct the private key
2. **Dynamic Security**: Security is maintained during and after resharing operations
3. **Fault Tolerance**: System continues to operate with up to n-t party failures
4. **Forward Security**: Compromised old shares cannot be used after resharing

## Implementation Details

### Shard Generations
Each resharing operation creates a new "generation" of key shares. The system maintains:
- Current generation number
- Historical generations for rollback
- Cryptographic commitments for verification

### Network Requirements
- Authenticated point-to-point channels
- Reliable broadcast for critical messages
- Timeout mechanisms for non-responsive parties

### Storage Requirements
- Secure storage for secret shares
- Persistence of generation history
- Public verification data

## Testing

Comprehensive test suite includes:
- Functional correctness tests
- Security property verification
- Byzantine fault tolerance tests
- Property-based testing
- Performance benchmarks

Run tests with:
```bash
make test-lss
```

## Performance

Benchmark results on standard hardware:
- Key generation (5-of-9): ~X ms
- Signing (threshold parties): ~Y ms
- Resharing (add 2 parties): ~Z ms

## References

1. Seesahai, V.J. (2025). "LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"
2. Gennaro, R., & Goldfeder, S. (2018). "Fast multiparty threshold ECDSA with fast trustless setup"
3. Canetti, R., et al. (2021). "UC non-interactive, proactive, threshold ECDSA with identifiable aborts"

## License

This implementation is part of the Lux Threshold Signatures library.
See the main LICENSE file for details.