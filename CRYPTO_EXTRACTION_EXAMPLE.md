# Crypto Extraction Example: ECDSA Consolidation

This document shows a concrete example of how to extract and consolidate ECDSA implementations from threshold into the shared crypto library.

## Current Implementation in Threshold

### 1. Generic Curve Interface (`pkg/math/curve/`)

```go
// curve.go
type Curve interface {
    Name() string
    NewScalar() Scalar
    NewPoint() Point
    ScalarBits() int
    SafeScalarBytes() int
    Order() Scalar
}

type Scalar interface {
    Curve() Curve
    Add(that Scalar) Scalar
    Sub(that Scalar) Scalar
    Neg() Scalar
    Mul(that Scalar) Scalar
    Invert() Scalar
    Equal(that Scalar) bool
    IsZero() bool
    Set(that Scalar) Scalar
    SetNat(nat *saferith.Nat) Scalar
    Act(that Point) Point
    ActOnBase() Point
    // ... more methods
}

type Point interface {
    Curve() Curve
    Identity() Point
    Add(that Point) Point
    Sub(that Point) Point
    Neg() Point
    Equal(that Point) bool
    IsIdentity() bool
    Set(that Point) Point
    XScalar() Scalar
    // ... more methods
}
```

### 2. ECDSA Signature (`pkg/ecdsa/`)

```go
type Signature struct {
    R curve.Point
    S curve.Scalar
}

func (sig Signature) Verify(X curve.Point, hash []byte) bool {
    // Custom verification using curve operations
}

func (sig Signature) SigEthereum() ([]byte, error) {
    // Convert to Ethereum format
}
```

## Proposed Unified Structure in Crypto

### 1. Move to `/lux/crypto/curves/`

```go
// /lux/crypto/curves/curve.go
package curves

// Keep the same interface from threshold
type Curve interface {
    Name() string
    NewScalar() Scalar
    NewPoint() Point
    ScalarBits() int
    SafeScalarBytes() int
    Order() Scalar
}

// Add backend selection
type Backend int

const (
    BackendPureGo Backend = iota
    BackendCGO
    BackendAssembly
)

// Registry for curve implementations
var curves = map[string]func(Backend) Curve{}

func Register(name string, constructor func(Backend) Curve) {
    curves[name] = constructor
}

func Get(name string, backend Backend) (Curve, error) {
    if c, ok := curves[name]; ok {
        return c(backend), nil
    }
    return nil, fmt.Errorf("unknown curve: %s", name)
}
```

### 2. Secp256k1 Implementation

```go
// /lux/crypto/curves/secp256k1/secp256k1.go
package secp256k1

import (
    "github.com/luxfi/crypto/curves"
    "github.com/luxfi/crypto/curves/internal/secp256k1_cgo"
    "github.com/luxfi/crypto/curves/internal/secp256k1_pure"
)

func init() {
    curves.Register("secp256k1", New)
}

func New(backend curves.Backend) curves.Curve {
    switch backend {
    case curves.BackendCGO:
        return secp256k1_cgo.New()
    case curves.BackendAssembly:
        // Use assembly optimized version
        return secp256k1_asm.New()
    default:
        return secp256k1_pure.New()
    }
}
```

### 3. Unified ECDSA

```go
// /lux/crypto/primitives/ecdsa/ecdsa.go
package ecdsa

import (
    "crypto/subtle"
    "github.com/luxfi/crypto/curves"
)

// Standard signature format
type Signature struct {
    R, S []byte
}

// Threshold-compatible signature
type CurveSignature struct {
    R curves.Point
    S curves.Scalar
}

// Sign using generic curve interface
func Sign(curve curves.Curve, privateKey curves.Scalar, hash []byte) (*CurveSignature, error) {
    // Implementation
}

// Verify using generic curve interface
func Verify(curve curves.Curve, publicKey curves.Point, hash []byte, sig *CurveSignature) bool {
    // Port from threshold implementation
}

// Format conversions
func (sig *CurveSignature) ToStandard() (*Signature, error) {
    r, _ := sig.R.MarshalBinary()
    s, _ := sig.S.MarshalBinary()
    return &Signature{R: r, S: s}, nil
}

func (sig *CurveSignature) ToEthereum() ([]byte, error) {
    // Port from threshold's SigEthereum
}
```

## Migration Strategy

### 1. Update Threshold Imports

```go
// Before: threshold/pkg/ecdsa/signature.go
import "github.com/luxfi/threshold/pkg/math/curve"

// After: 
import "github.com/luxfi/crypto/curves"
import "github.com/luxfi/crypto/primitives/ecdsa"
```

### 2. Type Aliases for Compatibility

```go
// threshold/pkg/math/curve/curve.go
package curve

import "github.com/luxfi/crypto/curves"

// Type aliases for backward compatibility
type Curve = curves.Curve
type Scalar = curves.Scalar
type Point = curves.Point

// Keep secp256k1 working
var Secp256k1 = curves.MustGet("secp256k1", curves.BackendPureGo)
```

### 3. Update ECDSA Package

```go
// threshold/pkg/ecdsa/signature.go
package ecdsa

import (
    "github.com/luxfi/crypto/primitives/ecdsa"
    "github.com/luxfi/threshold/pkg/math/curve"
)

// Wrap the crypto library signature
type Signature struct {
    *ecdsa.CurveSignature
}

// Keep existing API
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
    return ecdsa.Verify(X.Curve(), X, hash, sig.CurveSignature)
}
```

## Testing Strategy

### 1. Compatibility Tests

```go
func TestBackwardCompatibility(t *testing.T) {
    // Test that old code still works
    curve := curve.Secp256k1
    scalar := curve.NewScalar()
    point := scalar.ActOnBase()
    
    // Should work exactly as before
}
```

### 2. Performance Benchmarks

```go
func BenchmarkECDSA(b *testing.B) {
    benchmarks := []struct {
        name    string
        backend curves.Backend
    }{
        {"PureGo", curves.BackendPureGo},
        {"CGO", curves.BackendCGO},
        {"Assembly", curves.BackendAssembly},
    }
    
    for _, bb := range benchmarks {
        b.Run(bb.name, func(b *testing.B) {
            curve := curves.MustGet("secp256k1", bb.backend)
            // Benchmark operations
        })
    }
}
```

## Benefits of This Approach

1. **No breaking changes**: Type aliases maintain compatibility
2. **Performance choice**: Users can select backend
3. **Code reuse**: Single implementation shared across projects
4. **Clean separation**: Crypto primitives separate from protocols
5. **Easy testing**: Can test different backends

## Next Steps

1. Implement the curves package structure
2. Port threshold's curve implementations
3. Add crypto's optimized backends
4. Create compatibility layer
5. Update threshold to use new structure
6. Benchmark and optimize