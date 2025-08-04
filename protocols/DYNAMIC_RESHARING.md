# Dynamic Re-sharing for Threshold Signatures

This document describes the dynamic re-sharing capability added to the threshold signature implementation, based on the LSS (Live Share Scaling) protocol concepts.

## Overview

Dynamic re-sharing allows a threshold signature scheme to:
- Add new parties to the signing group
- Remove existing parties from the signing group
- Change the threshold value
- Migrate parties (simultaneous add/remove)

All while maintaining the same public key and without reconstructing the master private key.

## Implementation

The dynamic re-sharing is built on top of the existing CMP (CGG21) protocol implementation, extending its refresh capability to support membership changes.

### Key Files

- `protocols/cmp/dynamic_reshare.go` - Main implementation
- `protocols/cmp/reshare/dynamic.go` - Detailed 4-step protocol
- `protocols/cmp/dynamic_reshare_test.go` - Test suite

### API Functions

```go
// Add or remove parties while maintaining the same public key
func DynamicReshare(config *Config, newParties []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc

// Convenience functions
func AddParties(config *Config, partiesToAdd []party.ID, pl *pool.Pool) protocol.StartFunc
func RemoveParties(config *Config, partiesToRemove []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc
func ChangeThreshold(config *Config, newThreshold int, pl *pool.Pool) protocol.StartFunc
func MigrateParties(config *Config, removeParties, addParties []party.ID, newThreshold int, pl *pool.Pool) protocol.StartFunc
```

## Usage Examples

### Adding Parties

```go
// Initial 3-of-5 setup
configs := runKeygen(parties[:5], threshold: 3)

// Add 2 more parties (becomes 3-of-7)
newParties := []party.ID{"party-6", "party-7"}
allParties := append(parties[:5], newParties...)

// Run dynamic reshare
newConfigs := runProtocol(cmp.DynamicReshare(config, allParties, 3, pool))
```

### Removing Parties

```go
// Remove parties 4 and 5, adjust threshold to 2-of-3
remainingParties := parties[:3]
newConfigs := runProtocol(cmp.RemoveParties(config, []party.ID{"party-4", "party-5"}, 2, pool))
```

### Changing Threshold

```go
// Change from 2-of-4 to 3-of-4
newConfigs := runProtocol(cmp.ChangeThreshold(config, 3, pool))
```

## Protocol Details

The dynamic re-sharing protocol follows these steps:

1. **Initialization**: All old and new parties participate together
2. **Share Distribution**: Old parties use VSS with f(0)=0 to maintain the secret
3. **New Share Generation**: New parties receive fresh shares
4. **Finalization**: Only parties in the new set retain valid configurations

## Integration with FROST/EdDSA

The dynamic re-sharing capability can be used with FROST for EdDSA signatures:

### FROST Integration

```go
// Use dynamic resharing with FROST
frostConfig := frost.EmptyConfig(curve.Edwards25519{})

// Convert CMP dynamic reshare to work with FROST
// The resharing protocol is curve-agnostic and works with any group

// For EdDSA/Ed25519
reshareConfig := &DynamicReshareConfig{
    OldParties:   frostConfig.PartyIDs,
    NewParties:   newPartyList,
    OldThreshold: frostConfig.Threshold,
    NewThreshold: newThreshold,
}
```

### EdDSA Considerations

When using with EdDSA:
- The curve changes from secp256k1 to edwards25519
- The signing equation differs from ECDSA
- The resharing protocol remains the same (it's curve-agnostic)

### Example: FROST with Dynamic Membership

```go
// Initial FROST setup for EdDSA
configs := runFrostKeygen(curve.Edwards25519{}, parties, threshold)

// Add new parties using the resharing protocol
// The underlying math works the same for any curve
newConfig := runDynamicReshare(configs, newParties, threshold)

// Sign with FROST using new configuration
signature := frost.Sign(newConfig, signers, messageHash)
```

## Security Considerations

1. **Trust Model**: All participating parties (old and new) must be trusted during the resharing protocol
2. **Threshold Bounds**: The new threshold must satisfy: 1 ≤ t ≤ n
3. **Share Security**: Old shares become invalid after successful resharing
4. **Concurrent Operations**: Signing should be paused during resharing

## Fault Tolerance

The implementation includes mechanisms for handling failures:

```go
// Automated rollback on failure
type ReshareSession struct {
    Generation uint64
    Backup     *Config
}

// If resharing fails, revert to previous configuration
if err != nil {
    return session.Rollback()
}
```

## Performance

- Resharing requires all old parties + new parties to participate
- Communication complexity: O(n²) messages
- Computation: Dominated by polynomial evaluation and interpolation
- Can be performed without halting signing operations (with careful coordination)

## Future Enhancements

1. **Proactive Security**: Periodic automatic resharing
2. **Asynchronous Resharing**: Allow resharing without full participation
3. **Batch Operations**: Add/remove multiple party sets efficiently
4. **Cross-Protocol**: Enable resharing between different threshold schemes

## References

- LSS MPC ECDSA Paper: "A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"
- FROST: "Flexible Round-Optimized Schnorr Threshold Signatures"
- CMP/CGG21: "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"