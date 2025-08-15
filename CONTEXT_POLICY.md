# Context Policy - Threshold Signature Library

## What context.Context is for
- **Cancellation propagation** (`ctx.Done()`)
- **Deadlines/timeouts** (`context.WithTimeout`)
- **Request-scoped, incidental values** (rare—trace IDs, test knobs) using small, immutable values

## What it is NOT for
- Business data (party IDs, threshold values, curves, keys)
- Long-lived state
- Storing in structs

## Naming Rules
- The stdlib type is always named `ctx context.Context` and is the **first parameter**
- Never define another type named `Context`. Rename existing ones:
  - `protocols/*/context.go` → `protocols/*/runtime.go`
  - `type Context` → `type Runtime` (or `SessionRuntime`, `ProtocolRuntime`)
- Immutable configuration → `Config` or `Params`
- Service/dependency bundle → `Deps` (Pool, Network, Storage, Logger)
- Runtime metadata (party IDs, session IDs) → `Runtime` (read-only)

## Reference Signatures

### Protocol Operations
```go
// Key generation
func Keygen(ctx context.Context, rt Runtime, cfg Config, deps Deps) ([]*Config, error)

// Signing
func Sign(ctx context.Context, rt Runtime, msg []byte, deps Deps) (*Signature, error)

// Resharing
func Reshare(ctx context.Context, rt Runtime, newParties []party.ID, deps Deps) ([]*Config, error)
```

### Round Processing
```go
func (r *Round) Process(ctx context.Context, msg Message) (*Round, error)
func (r *Round) Finalize(ctx context.Context) (interface{}, error)
func (r *Round) Abort(ctx context.Context) error
```

### Network Operations
```go
func (n *Network) Send(ctx context.Context, to party.ID, msg Message) error
func (n *Network) Broadcast(ctx context.Context, msg Message) error
func (n *Network) Receive(ctx context.Context) (Message, error)
```

### Storage
```go
func (s *Store) Save(ctx context.Context, key string, share Share) error
func (s *Store) Load(ctx context.Context, key string) (Share, error)
func (s *Store) Delete(ctx context.Context, key string) error
```

**Never store ctx on any struct. Always pass it in.**

## Concurrency & Cancellation Pattern

```go
func (p *Protocol) Run(ctx context.Context) error {
    g, ctx := errgroup.WithContext(ctx)
    
    // Round processor
    g.Go(func() error {
        ticker := time.NewTicker(p.cfg.RoundInterval)
        defer ticker.Stop()
        for {
            select {
            case <-ctx.Done():
                return ctx.Err()
            case <-ticker.C:
                if err := p.processRound(ctx); err != nil {
                    return err
                }
            }
        }
    })
    
    // Message handler
    g.Go(func() error {
        for {
            select {
            case <-ctx.Done():
                return ctx.Err()
            case msg := <-p.msgChan:
                if err := p.handleMessage(ctx, msg); err != nil {
                    return err
                }
            }
        }
    })
    
    return g.Wait()
}
```

## Key Points
- Derive child contexts for time-boxed operations: `ctxRound, cancel := context.WithTimeout(ctx, p.cfg.RoundTimeout)`
- Always select on `ctx.Done()` in loops
- Use `errgroup` for goroutine lifecycles tied to `ctx`

## Testing

```go
func TestProtocol_Run(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()
    
    err := protocol.Run(ctx)
    require.ErrorIs(t, err, context.DeadlineExceeded) // proved it listened to ctx
}
```

## Migration Plan

### 1. Create Runtime/Config/Deps Types
```go
// protocols/common/runtime.go
type Runtime struct {
    SessionID  []byte
    SelfID     party.ID
    PartyIDs   []party.ID
    Threshold  int
    Group      curve.Curve
}

type Config struct {
    MaxRounds      int
    RoundTimeout   time.Duration
    MessageTimeout time.Duration
}

type Deps struct {
    Pool    *pool.Pool
    Network Network
    Storage Storage
    Logger  log.Logger
}
```

### 2. Update Function Signatures
All protocol functions should follow:
```go
func Operation(ctx context.Context, rt Runtime, cfg Config, deps Deps) (Result, error)
```

### 3. Remove ctx Fields
Search and remove any struct fields holding context:
```go
// BAD
type Protocol struct {
    ctx context.Context // DELETE THIS
}

// GOOD
type Protocol struct {
    rt   Runtime
    cfg  Config
    deps Deps
}
```

### 4. Add Proper Cancellation
Every goroutine must respect context cancellation:
```go
// BAD
go func() {
    for {
        // infinite loop
    }
}()

// GOOD
go func() {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            // work
        }
    }
}()
```

## Anti-patterns to Eliminate

❌ `context.TODO()` in production paths
❌ `context.WithCancel(context.Background())` deep inside libs
❌ Passing large structs via `ctx.Value`
❌ Blocking goroutines that don't check `ctx.Done()`
❌ Storing `ctx` in struct fields

## Lint Configuration

Add to `.golangci.yml`:
```yaml
linters-settings:
  gocritic:
    enabled-tags: [diagnostic]
  revive:
    rules:
      - name: context-as-arg
      - name: context-keys-type
linters:
  enable:
    - revive
    - gocritic
    - errcheck
    - unparam
```

## Bottom Line

✅ **YES**: One stdlib `context.Context` everywhere for cancellation/deadlines
✅ **YES**: Pass `ctx` as first parameter
✅ **YES**: Check `ctx.Done()` in all loops

❌ **NO**: More typed "Context" structs—rename them to Runtime/Env/Deps/Config
❌ **NO**: Storing `ctx` in structs
❌ **NO**: Smuggling business data through `ctx.Value`