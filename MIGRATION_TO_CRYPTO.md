# Migration Guide: Using Shared Crypto Library

This guide explains how to migrate threshold to use the shared `/lux/crypto` library while maintaining independence.

## Overview

The threshold package will remain independent but use shared cryptographic primitives from `/lux/crypto`. This eliminates duplication while preserving threshold-specific protocols.

## Migration Steps

### 1. Update go.mod

```go
module github.com/luxfi/threshold

go 1.21

require (
    github.com/luxfi/crypto v0.2.0
    // Remove these as they're now in crypto:
    // github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
    // github.com/zeebo/blake3 v0.2.3
)
```

### 2. Update Imports

#### Curves

```go
// Before:
import "github.com/luxfi/threshold/pkg/math/curve"

// After:
import "github.com/luxfi/crypto/curves/secp256k1"

// For generic interface:
import "github.com/luxfi/crypto/curves"
```

#### Math Operations

```go
// Before:
import "github.com/luxfi/threshold/pkg/math/arith"
import "github.com/luxfi/threshold/pkg/math/polynomial"
import "github.com/luxfi/threshold/pkg/math/sample"

// After:
import "github.com/luxfi/crypto/math/modular"
import "github.com/luxfi/crypto/math/polynomial"
import "github.com/luxfi/crypto/math/sample"
```

#### Hash Functions

```go
// Before:
import "github.com/luxfi/threshold/pkg/hash"

// After:
import "github.com/luxfi/crypto/hash/blake3"
```

### 3. Code Updates

#### Using Curves

```go
// Before:
group := curve.Secp256k1{}
scalar := group.NewScalar()
point := scalar.ActOnBase()

// After:
curve := secp256k1.New() // Auto-selects best implementation
scalar := curve.NewScalar()
point := curve.ScalarBaseMult(scalar.Bytes())
```

#### Modular Arithmetic

```go
// Before:
n := big.NewInt(9991)
nMod := arith.ModulusFromBigInt(n)
result := nMod.Exp(base, exp)

// After:
n := big.NewInt(9991)
mod := modular.New(n)
result := mod.Exp(base, exp)
```

#### Polynomial Operations

```go
// Before:
poly := polynomial.New(group, coeffs)
y := poly.Evaluate(x)

// After:
field := modular.New(group.Order())
poly := polynomial.NewOverField(field, coeffs)
y := poly.Evaluate(x)
```

### 4. Type Compatibility

For backward compatibility during migration, create type aliases:

```go
// pkg/math/curve/compat.go
package curve

import "github.com/luxfi/crypto/curves"

// Type aliases for compatibility
type Curve = curves.Curve
type Scalar = curves.Scalar
type Point = curves.Point

// Secp256k1 returns the secp256k1 curve
func Secp256k1() Curve {
    return curves.MustGet("secp256k1")
}
```

### 5. What Stays in Threshold

Keep these threshold-specific components:

```
threshold/
├── protocols/       # All protocol implementations stay
│   ├── cmp/        # CMP protocol
│   ├── frost/      # FROST protocol
│   └── lss/        # LSS protocol
├── internal/
│   ├── round/      # Round-based protocol framework
│   ├── mta/        # MtA protocol (threshold specific)
│   └── test/       # Protocol testing utilities
└── pkg/
    ├── protocol/   # Protocol abstractions
    └── party/      # Party management
```

### 6. What Moves to Crypto

Move these to shared crypto:

- `pkg/math/curve/` → `crypto/curves/`
- `pkg/math/arith/` → `crypto/math/modular/`
- `pkg/math/polynomial/` → `crypto/math/polynomial/`
- `pkg/math/sample/` → `crypto/math/sample/`
- `pkg/hash/` → `crypto/hash/`
- `pkg/ecdsa/` → Keep wrapper, use `crypto/primitives/ecdsa/`
- `internal/elgamal/` → `crypto/primitives/elgamal/`
- `internal/ot/` → `crypto/protocols/ot/`

## Build Configuration

### Using CGO Optimizations

```bash
# Default build (auto-detects best options)
go build

# Force pure Go
go build -tags purego

# Enable all optimizations
CGO_ENABLED=1 go build

# Check which implementation is used
go test -v -run TestImplementation
```

### Performance Comparison

```go
// Test which implementation you're using
curve := secp256k1.New()
fmt.Printf("Using implementation: %s\n", curve.Implementation())
// Output: "cgo-libsecp256k1" or "pure-go"
```

## Testing Migration

### 1. Compatibility Tests

```bash
# Run all tests to ensure compatibility
go test ./...

# Run benchmarks to compare performance
go test -bench=. ./...
```

### 2. Integration Tests

```go
// Verify protocols still work
func TestCMPWithNewCrypto(t *testing.T) {
    curve := secp256k1.New()
    // Run CMP protocol...
}
```

## Benefits After Migration

1. **Less Code**: ~40% reduction in crypto code
2. **Better Performance**: CGO optimizations when available
3. **Unified Testing**: Shared test vectors and benchmarks
4. **Easier Updates**: Update crypto in one place
5. **Maintained Independence**: Threshold protocols remain separate

## Rollback Plan

If issues arise, type aliases allow easy rollback:

```go
// Temporarily redirect back to old implementation
type Curve = oldcurve.Curve

// Or use build tags
//go:build use_old_crypto
```

## Timeline

1. **Week 1**: Create `/lux/crypto` structure
2. **Week 2**: Migrate math primitives
3. **Week 3**: Update threshold imports
4. **Week 4**: Testing and benchmarking
5. **Week 5**: Deploy to other projects

## Questions?

- For crypto library: See `/lux/crypto/README.md`
- For migration help: Check examples in `/lux/crypto/examples/`
- For threshold protocols: No changes to protocol logic