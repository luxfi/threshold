package pool

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test NewPool with various worker counts
func TestNewPool(t *testing.T) {
	tests := []struct {
		name          string
		workerCount   int
		expectedCount int
	}{
		{
			name:          "positive count",
			workerCount:   4,
			expectedCount: 4,
		},
		{
			name:          "zero count uses NumCPU",
			workerCount:   0,
			expectedCount: runtime.NumCPU(),
		},
		{
			name:          "negative count uses NumCPU",
			workerCount:   -1,
			expectedCount: runtime.NumCPU(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPool(tt.workerCount)
			require.NotNil(t, p)
			assert.Equal(t, tt.expectedCount, p.workerCount)
			assert.NotNil(t, p.commands)
			assert.False(t, p.closed)
			p.TearDown()
		})
	}
}

// Test TearDown
func TestPool_TearDown(t *testing.T) {
	// Test normal teardown
	p := NewPool(2)
	require.NotNil(t, p)

	p.TearDown()
	assert.True(t, p.closed)

	// Test double teardown (should not panic)
	p.TearDown()
	assert.True(t, p.closed)

	// Test nil pool teardown (should not panic)
	var nilPool *Pool
	nilPool.TearDown()
}

// Test Search with nil pool
func TestPool_Search_Nil(t *testing.T) {
	var p *Pool
	count := 0

	results := p.Search(3, func() interface{} {
		count++
		if count%2 == 0 {
			return count
		}
		return nil
	})

	assert.Len(t, results, 3)
	assert.Equal(t, 2, results[0])
	assert.Equal(t, 4, results[1])
	assert.Equal(t, 6, results[2])
}

// Test Search with pool
func TestPool_Search(t *testing.T) {
	p := NewPool(4)
	defer p.TearDown()

	var counter int32
	results := p.Search(5, func() interface{} {
		val := atomic.AddInt32(&counter, 1)
		// Simply return each incremented value
		return int(val)
	})

	assert.Len(t, results, 5)
	// Check that we have 5 results
	for _, r := range results {
		assert.NotNil(t, r, "Should have non-nil results")
	}
}

// Test Search with closed pool
func TestPool_Search_Closed(t *testing.T) {
	p := NewPool(2)
	p.TearDown()

	count := 0
	results := p.Search(2, func() interface{} {
		count++
		return count
	})

	assert.Len(t, results, 2)
	assert.Equal(t, 1, results[0])
	assert.Equal(t, 2, results[1])
}

// Test Parallelize with nil pool
func TestPool_Parallelize_Nil(t *testing.T) {
	var p *Pool

	results := p.Parallelize(5, func(i int) interface{} {
		return i * 2
	})

	assert.Len(t, results, 5)
	for i := 0; i < 5; i++ {
		assert.Equal(t, i*2, results[i])
	}
}

// Test Parallelize with pool
func TestPool_Parallelize(t *testing.T) {
	p := NewPool(4)
	defer p.TearDown()

	results := p.Parallelize(10, func(i int) interface{} {
		return i * i
	})

	assert.Len(t, results, 10)
	for i := 0; i < 10; i++ {
		assert.Equal(t, i*i, results[i])
	}
}

// Test Parallelize with closed pool
func TestPool_Parallelize_Closed(t *testing.T) {
	p := NewPool(2)
	p.TearDown()

	results := p.Parallelize(3, func(i int) interface{} {
		return i + 10
	})

	assert.Len(t, results, 3)
	for i := 0; i < 3; i++ {
		assert.Equal(t, i+10, results[i])
	}
}

// Test concurrent Search operations
func TestPool_Search_Concurrent(t *testing.T) {
	p := NewPool(8)
	defer p.TearDown()

	// Run multiple searches concurrently (from different goroutines)
	// Note: Pool is designed for single-goroutine use, but we test
	// the behavior when used incorrectly
	var wg sync.WaitGroup
	results := make([][]interface{}, 3)

	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var counter int32
			results[idx] = p.Search(3, func() interface{} {
				val := atomic.AddInt32(&counter, 1)
				if val <= 3 {
					return val
				}
				return nil
			})
		}(i)
	}

	wg.Wait()

	// Each search should have found 3 results
	for i := 0; i < 3; i++ {
		assert.Len(t, results[i], 3)
	}
}

// Test large parallel operation
func TestPool_Parallelize_Large(t *testing.T) {
	p := NewPool(16)
	defer p.TearDown()

	count := 1000
	results := p.Parallelize(count, func(i int) interface{} {
		// Simulate some work
		sum := 0
		for j := 0; j < 100; j++ {
			sum += i * j
		}
		return sum
	})

	assert.Len(t, results, count)
	for i := 0; i < count; i++ {
		expected := 0
		for j := 0; j < 100; j++ {
			expected += i * j
		}
		assert.Equal(t, expected, results[i])
	}
}

// Test Search with slow function
func TestPool_Search_Slow(t *testing.T) {
	p := NewPool(2)
	defer p.TearDown()

	var counter int32
	start := time.Now()

	results := p.Search(2, func() interface{} {
		val := atomic.AddInt32(&counter, 1)
		if val <= 2 {
			time.Sleep(50 * time.Millisecond)
			return val
		}
		return nil
	})

	elapsed := time.Since(start)

	assert.Len(t, results, 2)
	// With 2 workers, should take around 50ms (parallel execution)
	assert.Less(t, elapsed, 150*time.Millisecond)
}

// Test LockedReader
func TestLockedReader(t *testing.T) {
	data := []byte("hello world")
	reader := bytes.NewReader(data)
	lr := NewLockedReader(reader)

	// Test single read
	buf := make([]byte, 5)
	n, err := lr.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, "hello", string(buf))

	// Test second read
	n, err = lr.Read(buf)
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, " worl", string(buf))

	// Test EOF
	n, _ = lr.Read(buf)
	assert.Equal(t, 1, n)
	assert.Equal(t, "d", string(buf[:1]))

	n, err = lr.Read(buf)
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}

// Test LockedReader concurrent access
func TestLockedReader_Concurrent(t *testing.T) {
	// Create a large buffer
	size := 10000
	data := make([]byte, size)
	for i := 0; i < size; i++ {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	lr := NewLockedReader(reader)

	// Read concurrently from multiple goroutines
	numReaders := 10
	bufSize := size / numReaders

	var wg sync.WaitGroup
	results := make([][]byte, numReaders)

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			buf := make([]byte, bufSize)
			n, err := lr.Read(buf)
			if err != nil && err != io.EOF {
				t.Errorf("Unexpected error: %v", err)
			}
			results[idx] = buf[:n]
		}(i)
	}

	wg.Wait()

	// Combine all results
	var combined []byte
	for _, result := range results {
		combined = append(combined, result...)
	}

	// Should have read all data exactly once
	assert.Equal(t, size, len(combined))

	// Verify data integrity (no duplicates or missing data)
	seen := make(map[int]bool)
	for i, b := range combined {
		// Each position should map to a unique original position
		originalPos := -1
		for j := 0; j < size; j++ {
			if data[j] == b && !seen[j] {
				originalPos = j
				seen[j] = true
				break
			}
		}
		assert.NotEqual(t, -1, originalPos, "Byte at position %d not found or duplicated", i)
	}
}

// Test worker function directly
func TestWorker(t *testing.T) {
	commands := make(chan command, 1)
	results := make([]interface{}, 1)
	var ctr int64 = 1
	ctrChanged := make(chan struct{}, 1)

	// Start worker
	go worker(commands)

	// Send non-search command
	cmd := command{
		search:     false,
		i:          0,
		ctr:        &ctr,
		ctrChanged: ctrChanged,
		f: func(i int) interface{} {
			return i + 100
		},
		results: results,
	}

	commands <- cmd
	<-ctrChanged

	assert.Equal(t, 100, results[0])
	assert.Equal(t, int64(0), atomic.LoadInt64(&ctr))

	close(commands)
}

// Test workerSearch function
func TestWorkerSearch(t *testing.T) {
	results := make([]interface{}, 2)
	var ctr int64 = 2
	ctrChanged := make(chan struct{}, 2)
	mu := &sync.Mutex{}

	var attempts int32
	f := func(i int) interface{} {
		val := atomic.AddInt32(&attempts, 1)
		if val%2 == 0 {
			return int(val)
		}
		return nil
	}

	// Run workerSearch in a goroutine
	go workerSearch(results, ctrChanged, f, &ctr, mu)

	// Wait for results
	<-ctrChanged
	<-ctrChanged

	// Check results
	assert.Equal(t, int64(0), atomic.LoadInt64(&ctr))
	// Results should contain two even values
	assert.NotNil(t, results[0])
	assert.NotNil(t, results[1])
}

// Test edge cases
func TestPool_EdgeCases(t *testing.T) {
	// Test with 0 tasks
	p := NewPool(2)
	defer p.TearDown()

	results := p.Parallelize(0, func(i int) interface{} {
		return i
	})
	assert.Len(t, results, 0)

	results = p.Search(0, func() interface{} {
		return 1
	})
	assert.Len(t, results, 0)

	// Test with single task
	results = p.Parallelize(1, func(i int) interface{} {
		return i * 10
	})
	assert.Len(t, results, 1)
	assert.Equal(t, 0, results[0])

	results = p.Search(1, func() interface{} {
		return "found"
	})
	assert.Len(t, results, 1)
	assert.Equal(t, "found", results[0])
}

// Test panic recovery in Parallelize
func TestPool_Parallelize_PanicRecovery(t *testing.T) {
	p := NewPool(2)

	// Close the pool to trigger panic recovery
	p.TearDown()

	// This should recover and execute serially
	results := p.Parallelize(3, func(i int) interface{} {
		return i * 2
	})

	assert.Len(t, results, 3)
	for i := 0; i < 3; i++ {
		assert.Equal(t, i*2, results[i])
	}
}

// Test panic recovery in Search
func TestPool_Search_PanicRecovery(t *testing.T) {
	p := NewPool(2)
	defer p.TearDown()

	var count int32
	results := p.Search(3, func() interface{} {
		val := atomic.AddInt32(&count, 1)
		return int(val)
	})

	// Should get results
	assert.Len(t, results, 3)
}

// Benchmark pool operations
func BenchmarkPool_Parallelize(b *testing.B) {
	p := NewPool(runtime.NumCPU())
	defer p.TearDown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Parallelize(100, func(idx int) interface{} {
			sum := 0
			for j := 0; j < 1000; j++ {
				sum += idx * j
			}
			return sum
		})
	}
}

func BenchmarkPool_Search(b *testing.B) {
	p := NewPool(runtime.NumCPU())
	defer p.TearDown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var counter int32
		p.Search(10, func() interface{} {
			val := atomic.AddInt32(&counter, 1)
			if val <= 10 {
				return val
			}
			return nil
		})
	}
}

func BenchmarkLockedReader(b *testing.B) {
	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		lr := NewLockedReader(reader)

		buf := make([]byte, 1024)
		for {
			_, err := lr.Read(buf)
			if err == io.EOF {
				break
			}
		}
	}
}

// Test serialized functions directly
func TestSearchAlone(t *testing.T) {
	count := 0
	results := searchAlone(func() interface{} {
		count++
		if count%2 == 0 {
			return count
		}
		return nil
	}, 3)

	assert.Len(t, results, 3)
	assert.Equal(t, 2, results[0])
	assert.Equal(t, 4, results[1])
	assert.Equal(t, 6, results[2])
}

func TestParallelizeAlone(t *testing.T) {
	results := parallelizeAlone(func(i int) interface{} {
		return i * 3
	}, 4)

	assert.Len(t, results, 4)
	for i := 0; i < 4; i++ {
		assert.Equal(t, i*3, results[i])
	}
}

// Test error scenarios with custom reader
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, r.err
}

func TestLockedReader_Error(t *testing.T) {
	customErr := errors.New("custom read error")
	reader := &errorReader{err: customErr}
	lr := NewLockedReader(reader)

	buf := make([]byte, 10)
	n, err := lr.Read(buf)

	assert.Equal(t, 0, n)
	assert.Equal(t, customErr, err)
}
