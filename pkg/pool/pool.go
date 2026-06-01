package pool

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
)

// searchAlone runs f, which may return nil, until count elements are found.
func searchAlone(f func() interface{}, count int) []interface{} {
	results := make([]interface{}, count)
	for i := 0; i < len(results); i++ {
		results[i] = nil
		for results[i] == nil {
			results[i] = f()
		}
	}
	return results
}

// parallelizeAlone calculates the result of f count times.
func parallelizeAlone(f func(int) interface{}, count int) []interface{} {
	results := make([]interface{}, count)
	for i := 0; i < len(results); i++ {
		results[i] = f(i)
	}
	return results
}

// command is used to trigger our latent workers to do something.
//
// The idea is that a worker is told to either calculate a function once,
// or keep calculating a function until it returns a non nil result.
type command struct {
	search bool
	// This counter indicates the number of results that still need to be produced.
	ctr *int64
	// This channel is used to signal that the counter was modified
	ctrChanged chan<- struct{}
	// This is the index we evaluate our function at, when not searching
	i int
	f func(int) interface{}
	// This is the array where we put results
	results []interface{}
	// Mutex to protect concurrent access to results array during search
	mu *sync.Mutex
}

// workerSearch is the subroutine called when doing a search command.
//
// We need to keep searching for successful queries of f while *ctr > 0.
// When we find a successful result, we decrement *ctr.
func workerSearch(results []interface{}, ctrChanged chan<- struct{}, f func(int) interface{}, ctr *int64, mu *sync.Mutex) {
	for atomic.LoadInt64(ctr) > 0 {
		res := f(0)
		if res == nil {
			continue
		}
		i := atomic.AddInt64(ctr, -1)
		if i >= 0 {
			mu.Lock()
			results[i] = res
			mu.Unlock()
		}
		ctrChanged <- struct{}{}
	}
}

// worker starts up a new worker, listening to commands, and producing results.
func worker(commands <-chan command) {
	for c := range commands {
		if c.search {
			workerSearch(c.results, c.ctrChanged, c.f, c.ctr, c.mu)
		} else {
			c.results[c.i] = c.f(c.i)
			atomic.AddInt64(c.ctr, -1)
			c.ctrChanged <- struct{}{}
		}
	}
}

// Pool represents a pool of workers, used for parallelizing functions.
//
// Functions needing a *Pool will work with a nil receiver, doing the equivalent
// work on the current thread instead.
//
// By creating a pool, you avoid the overhead of spinning up goroutines for
// each new operation.
//
// A Pool is safe for concurrent use. Search and Parallelize may be called from
// multiple goroutines. TearDown blocks until every in-flight Search/Parallelize
// has returned, then closes the worker command channel; after TearDown returns,
// subsequent Search/Parallelize calls fall back to serial execution.
type Pool struct {
	// The common channel used to send commands to the workers.
	//
	// This effectively makes a work stealing pool.
	commands chan command
	// This holds the number of workers we've created
	workerCount int
	// inFlight gates send-vs-close races. Held read-locked for the duration
	// of every Search/Parallelize call so that TearDown — which takes the
	// write lock — cannot close p.commands while a sender is mid-send.
	inFlight sync.RWMutex
	// closed indicates if the pool has been torn down. Read under inFlight.RLock,
	// written under inFlight.Lock by TearDown.
	closed bool
}

// NewPool creates a new pool, with a certain number of workers.
//
// If count ⩽ 0, this will use the number of available CPUs instead.
func NewPool(count int) *Pool {
	var p Pool

	if count <= 0 {
		count = runtime.NumCPU()
	}

	p.commands = make(chan command)
	p.workerCount = count

	for i := 0; i < count; i++ {
		go worker(p.commands)
	}

	return &p
}

// TearDown cleanly tears down a pool, closing channels, etc.
//
// Blocks until every in-flight Search/Parallelize call has returned, so
// callers may safely defer it from the goroutine that owns the pool even
// when other goroutines are still using it.
func (p *Pool) TearDown() {
	if p == nil {
		return
	}
	// Acquire the write lock — this waits for every active Search/Parallelize
	// (each held with RLock) to drain, and prevents new ones from entering
	// the send loop while we close.
	p.inFlight.Lock()
	defer p.inFlight.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.commands)
}

// Search queries the function f, until count successes are found.
//
// f is supposed to try a single candidate, returning nil if that candidate isn't
// successful.
//
// The result will be an array containing the first count successes.
func (p *Pool) Search(count int, f func() interface{}) []interface{} {
	if p == nil {
		return searchAlone(f, count)
	}

	p.inFlight.RLock()
	defer p.inFlight.RUnlock()
	if p.closed {
		// Fall back to serial execution if pool is closed
		return searchAlone(f, count)
	}

	results := make([]interface{}, count)

	ctr := int64(count)
	// Buffer is sized for workerCount because, after ctr decrements to zero,
	// any worker still mid-iteration will still push one trailing signal
	// (for an i<0 attempt) before the next atomic.LoadInt64 lets it exit.
	// Sizing the buffer for workerCount means those trailing sends never block
	// the worker shutdown.
	ctrChanged := make(chan struct{}, p.workerCount)
	mu := &sync.Mutex{}
	cmd := command{
		search:     true,
		ctr:        &ctr,
		ctrChanged: ctrChanged,
		f:          func(_ int) interface{} { return f() },
		results:    results,
		mu:         mu,
	}
	// Send command to all workers
	for i := 0; i < p.workerCount; i++ {
		p.commands <- cmd
	}
	// Receive exactly count signals — every successful results[i] = res write
	// is followed by a send to ctrChanged, so receiving `count` of them gives
	// us a happens-before edge with every result write before we return.
	for i := 0; i < count; i++ {
		<-ctrChanged
	}

	return results
}

// Parallelize calls a function count times, passing in indices from 0..count-1.
//
// The result will be a slice containing [f(0), f(1), ..., f(count - 1)].
func (p *Pool) Parallelize(count int, f func(int) interface{}) []interface{} {
	if p == nil {
		return parallelizeAlone(f, count)
	}

	p.inFlight.RLock()
	defer p.inFlight.RUnlock()
	if p.closed {
		// Fall back to serial execution if pool is closed
		return parallelizeAlone(f, count)
	}

	results := make([]interface{}, count)

	ctr := int64(count)
	// Each completed task pushes exactly one signal.
	ctrChanged := make(chan struct{}, count)
	cmdI := 0
	received := 0
	for cmdI < count {
		cmd := command{
			search:     false,
			i:          cmdI,
			ctr:        &ctr,
			ctrChanged: ctrChanged,
			f:          f,
			results:    results,
		}
		// We won't be able to send all the commands without blocking, so we make
		// sure to interleave picking off the results of workers to free them up
		// to receive our commands
		select {
		case p.commands <- cmd:
			cmdI++
		case <-ctrChanged:
			received++
		}
	}
	// Drain the remaining signals so every results[i] = f(i) write has a
	// happens-before edge with our return.
	for received < count {
		<-ctrChanged
		received++
	}

	return results
}

// LockedReader wraps an io.Reader to be safe for concurrent reads.
//
// This type implements io.Reader, returning the same output.
//
// This means acquiring a lock whenever a read happens, so be aware of that
// for performance or concurrency reasons.
type LockedReader struct {
	reader io.Reader
	m      sync.Mutex
}

// NewLockedReader creates a LockedReader by wrapping an underlying value.
func NewLockedReader(r io.Reader) *LockedReader {
	// Intentionally not initializing m, since the zero value is ok
	return &LockedReader{reader: r}
}

// Read implements io.Reader for LockedReader
//
// The behavior is to return the same output as the underlying reader. The difference
// is that it's safe to call this function concurrently.
//
// Naturally, when calling this function concurrently, what value ends up getting
// read is raced, but you won't end up reading the same value twice, or otherwise
// messing up the state of the reader.
func (r *LockedReader) Read(p []byte) (int, error) {
	r.m.Lock()
	defer r.m.Unlock()
	return r.reader.Read(p)
}
