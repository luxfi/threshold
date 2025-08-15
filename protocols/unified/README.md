# Unified MPC-LSS: Dynamic Threshold Signatures for ECDSA & EdDSA

## Overview

A unified threshold signature protocol that combines Linear Secret Sharing (LSS) with support for both ECDSA and EdDSA/Schnorr signatures, featuring native dynamic resharing capabilities.

## Architecture

### Core Design Principles

1. **Signature Agnostic Core**: The LSS resharing logic is independent of the signature algorithm
2. **Pluggable Signature Schemes**: ECDSA and EdDSA implementations as separate modules
3. **Unified Config Structure**: Single configuration supporting both signature types
4. **Dynamic Participant Management**: Add/remove parties without changing public keys

### Key Features

- **Multi-Signature Support**: ECDSA (secp256k1) and EdDSA (ed25519)
- **Dynamic Resharing**: Change threshold and participants on-the-fly
- **Protocol Compatibility**: Works alongside existing CMP and FROST implementations
- **Efficient Operations**: 2-round signing for both signature types

## Technical Specification

### Unified Configuration

```go
type UnifiedConfig struct {
    // Common fields
    ID              party.ID
    Threshold       int
    Generation      uint64
    PartyIDs        []party.ID
    
    // Signature type
    SignatureScheme SignatureType // ECDSA or EdDSA
    
    // Curve-specific
    Group           curve.Curve   // secp256k1 or ed25519
    
    // Shared secrets (works for both)
    SecretShare     curve.Scalar
    PublicKey       curve.Point
    
    // Additional ECDSA requirements (if needed)
    ECDSAConfig     *ECDSAExtensions
    
    // Verification shares for all parties
    VerificationShares map[party.ID]curve.Point
}

type SignatureType int

const (
    SignatureECDSA SignatureType = iota
    SignatureEdDSA
    SignatureSchnorr
)

type ECDSAExtensions struct {
    // Paillier keys for multiplication
    PaillierKey *paillier.SecretKey
    PedersenParams *pedersen.Parameters
    // Additional ECDSA-specific fields
}
```

### Protocol Flow

#### 1. Key Generation (DKG)

```
Phase 1: Initial Share Distribution
- Each party generates polynomial f_i(x) with random secret
- Compute and broadcast commitments
- Distribute shares to all parties

Phase 2: Share Aggregation
- Verify received shares
- Compute final share as sum
- Derive public key collectively

Phase 3: Signature-Specific Setup
- For ECDSA: Generate Paillier keys, Pedersen parameters
- For EdDSA: Store verification shares only
```

#### 2. Dynamic Resharing

```
Input: Old config, new parties, new threshold
Output: New config with same public key

Phase 1: Auxiliary Secret Generation (JVSS)
- Generate blinding factors w, q via JVSS
- All parties (old + new) participate

Phase 2: Blinded Share Transfer
- Old parties: send blinded shares a_i * w_i
- Interpolate to get a * w

Phase 3: Unblinding & Distribution
- Compute z = (q * w)^{-1}
- Distribute z shares to new parties
- New parties compute: a'_j = (a * w) * z_j * q_j

Phase 4: Signature-Specific Migration
- For ECDSA: Transfer/regenerate Paillier keys
- For EdDSA: Update verification shares
```

#### 3. Signing

**EdDSA/Schnorr (2 rounds):**
```
Round 1: Nonce commitment
- Generate k_i, compute R_i = k_i * G
- Broadcast R_i

Round 2: Signature shares
- Aggregate R = Σ λ_i * R_i
- Compute challenge c = H(R, Y, m)
- Send z_i = k_i + c * λ_i * x_i
- Combine: z = Σ z_i
```

**ECDSA (2-3 rounds with preprocessing):**
```
Round 1: Multiplicative share generation
- Use Paillier for multiplication protocols
- Generate k_i shares

Round 2: Inverse computation
- Compute k^{-1} via MPC
- Calculate signature shares

Round 3: Combination
- Aggregate shares
- Output (r, s) signature
```

### Implementation Structure

```
protocols/unified/
├── config/
│   ├── config.go          # Unified configuration
│   └── extensions.go      # Signature-specific extensions
├── keygen/
│   ├── dkg.go            # Distributed key generation
│   └── rounds.go         # DKG protocol rounds
├── reshare/
│   ├── reshare.go        # Dynamic resharing protocol
│   ├── auxiliary.go      # JVSS for auxiliary secrets
│   └── transfer.go       # Share transfer logic
├── sign/
│   ├── ecdsa/
│   │   ├── presign.go    # ECDSA preprocessing
│   │   └── sign.go       # ECDSA signing
│   └── eddsa/
│       └── sign.go       # EdDSA signing
└── tests/
    └── unified_test.go   # Comprehensive tests
```

## Advantages

### Over Separate Protocols

1. **Unified Management**: Single system for all threshold signatures
2. **Code Reuse**: Common resharing logic for both signature types
3. **Simplified Operations**: One protocol to maintain and audit

### Over Static Schemes

1. **Dynamic Adaptation**: Adjust to changing security requirements
2. **Disaster Recovery**: Replace compromised parties
3. **Operational Flexibility**: Scale participants up or down

## Compatibility Matrix

| Feature | Unified MPC-LSS | CMP (ECDSA) | FROST (EdDSA) | Original LSS |
|---------|----------------|-------------|---------------|--------------|
| ECDSA Support | ✅ | ✅ | ❌ | ❌ |
| EdDSA Support | ✅ | ❌ | ✅ | ✅ |
| Dynamic Resharing | ✅ | ❌ | ❌ | ✅ |
| Threshold Change | ✅ | ❌ | ❌ | ✅ |
| Add/Remove Parties | ✅ | Limited | ❌ | ✅ |
| Signing Rounds | 2-3 | 5-8 | 2 | 2 |
| Identifiable Abort | ✅ | ✅ | ❌ | ✅ |

## Security Considerations

### Assumptions
- Honest majority (t < n/2)
- Secure channels between parties
- Random oracle model for hash functions

### Additional ECDSA Security
- Paillier key generation security
- Range proofs for ECDSA operations
- Protection against bias in k generation

### EdDSA Security
- Deterministic nonce generation option
- Canonical point encoding
- Protection against rogue key attacks

## Migration Path

### From FROST to Unified
1. Export FROST config (private share, public key, verification shares)
2. Create UnifiedConfig with SignatureEdDSA
3. Run resharing protocol if needed
4. Verify signatures match

### From CMP to Unified
1. Export CMP config (ECDSA share, Paillier keys)
2. Create UnifiedConfig with SignatureECDSA
3. Import Paillier and Pedersen parameters
4. Run test signatures

## Testing Strategy

- Unit tests for each component
- Integration tests for cross-signature resharing
- Stress tests with 100+ parties
- Byzantine fault injection tests
- Performance benchmarks for both signature types

## Future Enhancements

1. **BLS Signatures**: Add BLS12-381 support
2. **Threshold RSA**: Extend to RSA signatures
3. **Post-Quantum**: Integration with Ringtail
4. **Hardware Security**: HSM integration
5. **Network Optimization**: Reduce communication rounds