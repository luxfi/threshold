# Context Policy - Minimal & Clean

## The Pattern: Least Typing, Clean Semantics

**Single parameter everywhere**: Just pass `ctx context.Context`

## Implementation

### 1. Optional Type Alias for Cleaner Call Sites
```go
// pkg/protocol/context.go
type Context = context.Context  // Just an alias
```

### 2. Tiny Context Helpers
```go
// Immutable session info carried in context
type SessionInfo struct {
    SessionID []byte
    SelfID    party.ID
    PartyIDs  []party.ID
    Threshold int
    Group     curve.Curve
    Protocol  string
}

// Set once at protocol boundary
func WithSession(ctx context.Context, info SessionInfo) context.Context

// Minimal typing getters (panic if missing - fail fast)
func SessionID(ctx context.Context) []byte   { return MustSession(ctx).SessionID }
func Self(ctx context.Context) party.ID      { return MustSession(ctx).SelfID }
func Parties(ctx context.Context) []party.ID { return MustSession(ctx).PartyIDs }
func Threshold(ctx context.Context) int      { return MustSession(ctx).Threshold }
func Group(ctx context.Context) curve.Curve  { return MustSession(ctx).Group }
```

### 3. Set Once, Then Forget
```go
// At protocol start
func StartKeygen(selfID party.ID, parties []party.ID, threshold int) {
    ctx := context.Background()
    ctx = protocol.WithSession(ctx, protocol.SessionInfo{
        SessionID: GenerateSessionID(),
        SelfID:    selfID,
        PartyIDs:  parties,
        Threshold: threshold,
        Group:     curve.Secp256k1{},
        Protocol:  "cmp",
    })
    // Pass ctx to all protocol functions
}
```

### 4. Use in Code (Short & Sweet)
```go
func processRound(ctx protocol.Context) error {
    // One-token access to session info
    threshold := protocol.Threshold(ctx)
    self := protocol.Self(ctx)
    
    // Respect cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    // Do work...
    return nil
}
```

## What Goes in Context

✅ **YES**: Small, immutable session data
- Session ID
- Party identifiers  
- Threshold parameters
- Protocol name
- Request/trace IDs

❌ **NO**: Heavy dependencies or global utilities
- Database connections
- Network handlers
- Cryptographic keys
- Mutable state
- Mutexes

## Global Packages - Use Directly

**Don't pass these through context - use the packages directly:**

### Logging
```go
import "github.com/luxfi/log"

// Just use it directly everywhere
log.Info("processing round", "session", sessionID, "round", roundNum)
log.Debug("message received", "from", sender, "type", msgType)
```

### Metrics
```go
import "github.com/luxfi/metric"

// Use directly for instrumentation
metric.Inc("threshold.keygen.started")
metric.Record("threshold.sign.duration", time.Since(start))
```

These are global utilities designed to be used directly - no need to thread them through context or parameters.

## Why This Pattern?

1. **Least typing**: Call sites just pass `ctx`, accessors are 3-4 chars
2. **No `ok` plumbing**: Fail fast with panic if session missing
3. **No wrapper types**: Just aliases and helpers
4. **Idiomatic Go**: Standard context.Context everywhere
5. **Fast & safe**: No heavy objects in context

## Migration Example

### Before (heavy context struct)
```go
type Context struct {
    SessionID []byte
    Network   NetworkHandler
    Storage   Database
    Logger    Logger
    Metrics   MetricsCollector
    // ... lots of deps
}

func Sign(ctx *Context, msg []byte) error {
    ctx.Logger.Info("signing")
    ctx.Metrics.Inc("sign.attempts")
    // ...
}
```

### After (minimal context + global packages)
```go
import (
    "github.com/luxfi/log"
    "github.com/luxfi/metric"
)

func Sign(ctx context.Context, network NetworkHandler, msg []byte) error {
    // Use global packages directly
    log.Info("signing", "session", protocol.SessionID(ctx))
    metric.Inc("threshold.sign.attempts")
    
    // network passed explicitly - clear dependencies
    // ...
}
```

## Summary

- **One type**: `context.Context` (or aliased `protocol.Context`)
- **One setter**: `WithSession()` at boundaries
- **Tiny getters**: `Self(ctx)`, `Threshold(ctx)`, etc.
- **Explicit deps**: Pass heavy objects as parameters
- **Fail fast**: Panic if required context missing

This gives you the ergonomics of a custom context with zero overhead and maximum clarity.