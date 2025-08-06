# Crypto Consolidation Plan for Lux Ecosystem

## Overview

The Lux ecosystem has multiple cryptographic implementations spread across several projects:
- `/lux/crypto` - General purpose crypto library
- `/lux/threshold` - Threshold signature schemes (this project)
- `/lux/tss` - Another threshold signature implementation (Gennaro-Goldfeder)

This document outlines a plan to consolidate and standardize cryptographic primitives across the ecosystem.

## Current State Analysis

### 1. ECDSA Implementations

| Project | Implementation | Backend | Features |
|---------|---------------|---------|----------|
| crypto | secp256k1 | libsecp256k1 (C) + assembly | Ethereum compatible, hardware optimized |
| threshold | Generic ECDSA | decred/secp256k1 (Go) | Threshold signatures, generic curve interface |
| tss | ECDSA TSS | Gennaro-Goldfeder | Multi-party threshold signatures |

### 2. Curve Implementations

| Project | Curves | Notes |
|---------|--------|-------|
| crypto | secp256k1, secp256r1, bn256 | Hardware optimized |
| threshold | secp256k1, generic interface | Extensible to any curve |
| tss | secp256k1, ed25519 | Fixed curves |

### 3. Mathematical Primitives

| Project | Features | Use Case |
|---------|----------|----------|
| crypto | Basic big.Int operations | General crypto |
| threshold | Modular arithmetic, polynomials, sampling | Threshold crypto |
| tss | Field operations | TSS specific |

## Consolidation Strategy

### Phase 1: Create Unified Crypto Foundation (Week 1-2)

1. **Create new structure in `/lux/crypto`**:
```
/lux/crypto/
├── curves/           # Unified curve implementations
│   ├── interface.go  # Generic curve interface from threshold
│   ├── secp256k1/    # Consolidate all secp256k1 implementations
│   ├── secp256r1/    
│   ├── bn256/
│   └── ed25519/      # From tss project
├── primitives/       # Basic crypto primitives
│   ├── ecdsa/        # Unified ECDSA
│   ├── eddsa/        # EdDSA from tss
│   ├── hash/         # Blake3, Keccak256, SHA256
│   └── random/       # Secure random generation
└── math/             # Mathematical primitives
    ├── field/        # Field operations
    ├── polynomial/   # From threshold
    └── sampling/     # Cryptographic sampling
```

2. **Extract and merge common interfaces**:
   - Use threshold's generic `curve.Curve` interface as base
   - Add crypto's optimized implementations as backends
   - Keep pure Go and CGO versions

### Phase 2: Update Threshold Project (Week 3-4)

1. **Replace internal crypto with unified library**:
   - Update imports to use `github.com/luxfi/crypto`
   - Remove duplicate implementations
   - Keep threshold-specific protocols (CMP, FROST, LSS)

2. **Move general primitives to crypto**:
   - Paillier encryption
   - Pedersen commitments
   - Zero-knowledge proof frameworks

3. **Update structure**:
```
/lux/threshold/
├── protocols/        # Threshold-specific protocols only
│   ├── cmp/         # Keep as-is
│   ├── frost/       # Keep as-is
│   └── lss/         # Keep as-is
├── internal/        # Internal threshold logic
│   ├── mta/         # Keep (threshold specific)
│   ├── ot/          # Move to crypto
│   └── round/       # Keep (protocol framework)
└── pkg/             # Public APIs
    └── protocol/    # Protocol abstractions
```

### Phase 3: Consolidate TSS Projects (Week 5-6)

1. **Analyze overlap between threshold and tss**:
   - Both implement threshold signatures
   - Different protocols (CMP/FROST/LSS vs Gennaro-Goldfeder)
   - Consider merging or maintaining as separate specialized libraries

2. **Recommended approach**:
   - Keep both projects but share crypto foundation
   - `threshold` for newer protocols (CMP, FROST, LSS)
   - `tss` for established Gennaro-Goldfeder implementation

### Phase 4: Migration and Testing (Week 7-8)

1. **Create migration guide**:
   - Import path changes
   - API compatibility layer
   - Type conversion utilities

2. **Update all dependent projects**:
   - Update imports in node, wallet, bridge, etc.
   - Run comprehensive test suite
   - Performance benchmarks

## Implementation Details

### 1. Curve Interface Unification

```go
// In crypto/curves/interface.go
type Curve interface {
    // From threshold project
    Name() string
    NewScalar() Scalar
    NewPoint() Point
    ScalarBits() int
    // Additional methods...
}

// Implementations can optimize
type Secp256k1 struct {
    backend Backend // Can be CGO or pure Go
}
```

### 2. ECDSA Standardization

```go
// In crypto/primitives/ecdsa/
type Signature struct {
    R, S *big.Int // Standard format
}

// Conversion utilities
func FromThresholdSignature(sig threshold.Signature) *Signature
func ToEthereumFormat(sig *Signature) ([]byte, error)
```

### 3. Performance Considerations

- Keep assembly optimizations from crypto project
- Provide build tags for CGO vs pure Go
- Benchmark critical paths

## Benefits

1. **Reduced code duplication**: ~40% less crypto code
2. **Consistent APIs**: Single interface for all crypto operations
3. **Better testing**: Consolidated test suite
4. **Performance**: Best implementation for each use case
5. **Maintainability**: Single source of truth for crypto

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking changes | Provide compatibility layer |
| Performance regression | Comprehensive benchmarks |
| Security issues | Gradual migration with extensive testing |
| Integration complexity | Clear migration guide |

## Timeline

- Week 1-2: Create unified crypto structure
- Week 3-4: Update threshold project
- Week 5-6: Consolidate TSS projects
- Week 7-8: Migration and testing
- Week 9-10: Deploy to dependent projects

## Next Steps

1. Review and approve this plan
2. Create crypto v2 branch
3. Begin implementation
4. Set up CI/CD for new structure
5. Coordinate with dependent projects

## Conclusion

This consolidation will significantly improve the Lux crypto ecosystem by:
- Eliminating duplication
- Standardizing interfaces
- Improving performance
- Simplifying maintenance

The phased approach ensures minimal disruption while maximizing benefits.