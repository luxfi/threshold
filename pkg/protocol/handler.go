// Package protocol provides the ultimate optimized protocol handler with Lux integration
package protocol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/internal/round"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/metric"
)

// StartFunc creates the first round of a protocol
type StartFunc func(sessionID []byte) (round.Session, error)

// MultiHandler is an alias for Handler for temporary compatibility
type MultiHandler = Handler

// NewMultiHandler creates a handler with default config (temporary compatibility)
func NewMultiHandler(create StartFunc, sessionID []byte) (*Handler, error) {
	// Create a test logger for compatibility
	logger := log.NewTestLogger(log.InfoLevel)
	config := DefaultConfig()
	return NewHandler(context.Background(), logger, nil, create, sessionID, config)
}

// Handler is the ONLY handler for threshold protocols - optimized for perfection
type Handler struct {
	// Core state with lock-free atomic operations
	currentRound atomic.Value // stores round.Session
	rounds       sync.Map     // round.Number -> round.Session
	result       atomic.Value // stores interface{}
	err          atomic.Value // stores *Error
	stopped      atomic.Bool  // tracks if handler is stopped

	// Sharded message storage for zero contention
	messages  *MessageStore
	broadcast *MessageStore

	// Processed message tracking - prevents race conditions
	processedBroadcasts sync.Map // "round:from" -> bool
	processedMessages   sync.Map // "round:from" -> bool

	// Verification in progress tracking - prevents concurrent verification of same message
	verifyingBroadcasts sync.Map // "round:from" -> bool
	verifyingMessages   sync.Map // "round:from" -> bool

	// Retry tracking - prevents goroutine accumulation from multiple retries
	pendingRetries sync.Map // round.Number -> bool

	// High-performance channels
	out      chan *Message
	incoming chan *Message
	priority chan *Message // High-priority messages

	// Output channel protection.
	//
	// outMu serializes "check outClosed then send to h.out" against "set outClosed
	// then close(h.out)". Senders hold RLock for the duration of the check+send
	// critical section; Stop / protocol-complete paths take the write lock around
	// the close. This is the only way to make the check-then-send race-free —
	// atomic.Bool alone can flip between the load and the chan op.
	outMu     sync.RWMutex
	outClosed atomic.Bool

	// roundMu serializes VerifyMessage / StoreMessage / StoreBroadcastMessage
	// calls against the live round.Session. Each party has its own Handler,
	// so this only orders state mutations within a single party — concurrent
	// VerifyMessage calls would race on shared round state (e.g. Pedersen
	// parameters whose saferith.Nat.Cmp mutates limb storage even on equal
	// values).
	roundMu sync.Mutex

	// Lifecycle management
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	closeOnce     sync.Once
	stopOnce      sync.Once
	closeDoneOnce sync.Once

	// Worker pool
	workers     int
	workerGroup sync.WaitGroup

	// Lux logging
	log log.Logger

	// Prometheus metrics
	metrics *Metrics

	// Protocol info
	protocolID string
	sessionID  []byte

	// Performance tuning
	config *Config

	// Round finalization tracking
	finalized sync.Map // round.Number -> bool

	// Performance tracking
	messagesProcessed uint64
	roundsCompleted   uint64
	protocolStartTime time.Time
}

// roundWrapper wraps a round.Session to ensure atomic.Value type consistency
type roundWrapper struct {
	round round.Session
}

// Config for handler - optimized for maximum performance
type Config struct {
	// Worker pools
	Workers         int // CPU cores * 2 by default
	PriorityWorkers int // 4 by default

	// Channels
	BufferSize     int // 10000 by default
	PriorityBuffer int // 1000 by default

	// Timeouts
	MessageTimeout  time.Duration // 30s by default
	RoundTimeout    time.Duration // 60s by default
	ProtocolTimeout time.Duration // 5m by default

	// Performance
	EnableBatching       bool          // true by default
	BatchSize            int           // 100 by default
	BatchTimeout         time.Duration // 10ms by default
	EnableCompression    bool          // true for large messages
	CompressionThreshold int           // 1KB by default

	// Memory
	EnablePooling  bool // true by default
	MaxMessageSize int  // 10MB by default

	// Reliability
	RetryAttempts int           // 3 by default
	RetryBackoff  time.Duration // 1s by default
}

// DefaultConfig returns the perfect configuration
func DefaultConfig() *Config {
	return &Config{
		Workers:              runtime.NumCPU() * 2,
		PriorityWorkers:      4,
		BufferSize:           10000,
		PriorityBuffer:       1000,
		MessageTimeout:       30 * time.Second,
		RoundTimeout:         60 * time.Second,
		ProtocolTimeout:      5 * time.Minute,
		EnableBatching:       true,
		BatchSize:            100,
		BatchTimeout:         10 * time.Millisecond,
		EnableCompression:    true,
		CompressionThreshold: 1024,
		EnablePooling:        true,
		MaxMessageSize:       10 * 1024 * 1024, // 10MB
		RetryAttempts:        3,
		RetryBackoff:         time.Second,
	}
}

// Metrics for Prometheus monitoring
type Metrics struct {
	// Counters
	messagesReceived   metric.Counter
	messagesSent       metric.Counter
	messagesDropped    metric.Counter
	roundsCompleted    metric.Counter
	protocolsCompleted metric.Counter
	protocolsFailed    metric.Counter

	// Gauges
	activeWorkers  metric.Gauge
	queuedMessages metric.Gauge
	currentRound   metric.Gauge
	memoryUsage    metric.Gauge

	// Histograms
	messageLatency   metric.Histogram
	roundDuration    metric.Histogram
	protocolDuration metric.Histogram
	queueWaitTime    metric.Histogram

	// Summaries
	messageSize metric.Summary
	batchSize   metric.Summary
}

// NewHandler creates the perfect protocol handler
func NewHandler(
	ctx context.Context,
	logger log.Logger,
	registry metric.Registerer,
	create StartFunc,
	sessionID []byte,
	config *Config,
) (*Handler, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if logger == nil || logger.IsZero() {
		return nil, errors.New("logger is required")
	}

	// Create initial round
	r, err := create(sessionID)
	if err != nil {
		logger.Error("failed to create initial round", log.Err(err))
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}

	// Create metrics if registry provided
	var metrics *Metrics
	if registry != nil {
		metrics = createMetrics(r.ProtocolID(), registry)
	}

	// Only add timeout if context doesn't already have one
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && config.ProtocolTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, config.ProtocolTimeout)
	} else {
		// Create a cancel func anyway for cleanup
		ctx, cancel = context.WithCancel(ctx)
	}

	h := &Handler{
		messages:          newMessageStore(),
		broadcast:         newMessageStore(),
		out:               make(chan *Message, config.BufferSize),
		incoming:          make(chan *Message, config.BufferSize),
		priority:          make(chan *Message, config.PriorityBuffer),
		ctx:               ctx,
		cancel:            cancel,
		done:              make(chan struct{}),
		workers:           config.Workers,
		log:               logger,
		metrics:           metrics,
		protocolID:        r.ProtocolID(),
		sessionID:         sessionID,
		config:            config,
		protocolStartTime: time.Now(),
	}

	// Store initial round with wrapper for atomic.Value type consistency
	h.currentRound.Store(&roundWrapper{round: r})
	h.rounds.Store(r.Number(), &roundWrapper{round: r})

	logger.Info("starting protocol handler",
		log.String("protocol", h.protocolID),
		log.Int("workers", config.Workers),
		log.Int("parties", r.N()),
		log.Int("threshold", r.Threshold()))

	// Start worker pools
	h.startWorkers()

	// Initialize first round
	go h.initializeRound(r)

	// Update metrics
	if metrics != nil {
		metrics.activeWorkers.Set(float64(config.Workers + config.PriorityWorkers))
	}

	return h, nil
}

func createMetrics(protocolID string, registry metric.Registerer) *Metrics {
	m := &Metrics{
		messagesReceived: metric.NewCounter(metric.CounterOpts{
			Name: fmt.Sprintf("threshold_%s_messages_received_total", protocolID),
			Help: "Total messages received",
		}),
		messagesSent: metric.NewCounter(metric.CounterOpts{
			Name: fmt.Sprintf("threshold_%s_messages_sent_total", protocolID),
			Help: "Total messages sent",
		}),
		messagesDropped: metric.NewCounter(metric.CounterOpts{
			Name: fmt.Sprintf("threshold_%s_messages_dropped_total", protocolID),
			Help: "Total messages dropped",
		}),
		roundsCompleted: metric.NewCounter(metric.CounterOpts{
			Name: fmt.Sprintf("threshold_%s_rounds_completed_total", protocolID),
			Help: "Total rounds completed",
		}),
		protocolsCompleted: metric.NewCounter(metric.CounterOpts{
			Name: fmt.Sprintf("threshold_%s_protocols_completed_total", protocolID),
			Help: "Total protocols completed",
		}),
		protocolsFailed: metric.NewCounter(metric.CounterOpts{
			Name: fmt.Sprintf("threshold_%s_protocols_failed_total", protocolID),
			Help: "Total protocols failed",
		}),
		activeWorkers: metric.NewGauge(metric.GaugeOpts{
			Name: fmt.Sprintf("threshold_%s_active_workers", protocolID),
			Help: "Active worker goroutines",
		}),
		queuedMessages: metric.NewGauge(metric.GaugeOpts{
			Name: fmt.Sprintf("threshold_%s_queued_messages", protocolID),
			Help: "Messages in queue",
		}),
		currentRound: metric.NewGauge(metric.GaugeOpts{
			Name: fmt.Sprintf("threshold_%s_current_round", protocolID),
			Help: "Current protocol round",
		}),
		memoryUsage: metric.NewGauge(metric.GaugeOpts{
			Name: fmt.Sprintf("threshold_%s_memory_usage_bytes", protocolID),
			Help: "Memory usage in bytes",
		}),
		messageLatency: metric.NewHistogram(metric.HistogramOpts{
			Name:    fmt.Sprintf("threshold_%s_message_latency_seconds", protocolID),
			Help:    "Message processing latency",
			Buckets: metric.ExponentialBuckets(0.001, 2, 10),
		}),
		roundDuration: metric.NewHistogram(metric.HistogramOpts{
			Name:    fmt.Sprintf("threshold_%s_round_duration_seconds", protocolID),
			Help:    "Round completion duration",
			Buckets: metric.ExponentialBuckets(0.01, 2, 10),
		}),
		protocolDuration: metric.NewHistogram(metric.HistogramOpts{
			Name:    fmt.Sprintf("threshold_%s_protocol_duration_seconds", protocolID),
			Help:    "Total protocol duration",
			Buckets: metric.ExponentialBuckets(0.1, 2, 10),
		}),
		queueWaitTime: metric.NewHistogram(metric.HistogramOpts{
			Name:    fmt.Sprintf("threshold_%s_queue_wait_seconds", protocolID),
			Help:    "Queue wait time",
			Buckets: metric.ExponentialBuckets(0.0001, 2, 10),
		}),
		messageSize: metric.NewSummary(metric.SummaryOpts{
			Name:       fmt.Sprintf("threshold_%s_message_size_bytes", protocolID),
			Help:       "Message size distribution",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}),
		batchSize: metric.NewSummary(metric.SummaryOpts{
			Name:       fmt.Sprintf("threshold_%s_batch_size", protocolID),
			Help:       "Batch processing size",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		}),
	}

	// Register all metrics
	registry.MustRegister(
		m.messagesReceived, m.messagesSent, m.messagesDropped,
		m.roundsCompleted, m.protocolsCompleted, m.protocolsFailed,
		m.activeWorkers, m.queuedMessages, m.currentRound, m.memoryUsage,
		m.messageLatency, m.roundDuration, m.protocolDuration, m.queueWaitTime,
		m.messageSize, m.batchSize,
	)

	return m
}

// startWorkers initializes all worker pools
func (h *Handler) startWorkers() {
	h.log.Debug("starting worker pools",
		log.Int("workers", h.workers),
		log.Int("priority", h.config.PriorityWorkers))

	// Start regular workers
	for i := 0; i < h.workers; i++ {
		h.workerGroup.Add(1)
		go h.messageWorker(i, false)
	}

	// Start priority workers
	for i := 0; i < h.config.PriorityWorkers; i++ {
		h.workerGroup.Add(1)
		go h.messageWorker(i, true)
	}

	// Start batch processor
	if h.config.EnableBatching {
		h.workerGroup.Add(1)
		go h.batchProcessor()
	}

	// Start round processor
	h.workerGroup.Add(1)
	go func() {
		defer h.workerGroup.Done()
		h.roundProcessor()
	}()

	// Start metrics updater
	if h.metrics != nil {
		h.workerGroup.Add(1)
		go func() {
			defer h.workerGroup.Done()
			h.metricsUpdater()
		}()
	}
}

// messageWorker processes messages with maximum efficiency
func (h *Handler) messageWorker(id int, isPriority bool) {
	defer h.workerGroup.Done()

	h.log.Debug("worker started",
		log.Int("id", id),
		log.Bool("priority", isPriority))

	source := h.incoming
	if isPriority {
		source = h.priority
	}

	for {
		select {
		case <-h.ctx.Done():
			h.log.Debug("worker stopping", log.Int("id", id))
			return

		case msg := <-source:
			start := time.Now()
			h.processMessage(msg)

			if h.metrics != nil {
				h.metrics.messageLatency.Observe(time.Since(start).Seconds())
			}
		}
	}
}

// processMessage handles a single message with perfection
func (h *Handler) processMessage(msg *Message) {
	if msg == nil {
		return
	}

	atomic.AddUint64(&h.messagesProcessed, 1)

	if h.metrics != nil {
		h.metrics.messagesReceived.Inc()
		h.metrics.messageSize.Observe(float64(len(msg.Data)))
	}

	// Extra debug for p2p round 3
	if msg.RoundNumber == 3 && !msg.Broadcast {
		h.log.Debug("processMessage: p2p round 3 START",
			log.String("from", string(msg.From)),
			log.String("to", string(msg.To)))
	}

	h.log.Debug("processing message",
		log.String("from", string(msg.From)),
		log.String("to", string(msg.To)),
		log.Uint16("round", uint16(msg.RoundNumber)),
		log.Bool("broadcast", msg.Broadcast),
		log.String("self", string(h.currentRound.Load().(*roundWrapper).round.SelfID())))

	// Check if already errored or completed
	if h.err.Load() != nil || h.result.Load() != nil {
		h.log.Debug("dropping message - protocol finished")
		return
	}

	// Handle abort messages
	if msg.RoundNumber == 0 {
		h.handleAbort(msg)
		return
	}

	// Decompress if needed
	if msg.Compressed {
		msg = h.decompressMessage(msg)
		if msg == nil {
			return
		}
	}

	// Store message for any round (needed for buffering future rounds)
	h.storeMessage(msg)

	// Get current round
	r := h.currentRound.Load().(*roundWrapper).round
	if r.Number() != msg.RoundNumber {
		h.log.Debug("message for different round (buffering)",
			log.Uint16("msg_round", uint16(msg.RoundNumber)),
			log.Uint16("current_round", uint16(r.Number())))
		// Still try to advance in case this completes the current round
		h.tryAdvanceRound()
		return
	}

	// Verify and process message for current round
	if msg.Broadcast {
		h.verifyBroadcast(msg)
	} else {
		h.verifyNormal(msg)
	}

	// Try to advance round
	h.tryAdvanceRound()
}

// batchProcessor handles batch message processing for maximum throughput
func (h *Handler) batchProcessor() {
	defer h.workerGroup.Done()

	ticker := time.NewTicker(h.config.BatchTimeout)
	defer ticker.Stop()

	batch := make([]*Message, 0, h.config.BatchSize)

	for {
		select {
		case <-h.ctx.Done():
			return

		case msg := <-h.incoming:
			batch = append(batch, msg)

			if len(batch) >= h.config.BatchSize {
				h.processBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				h.processBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// processBatch processes multiple messages together
func (h *Handler) processBatch(batch []*Message) {
	h.log.Debug("processing batch", log.Int("size", len(batch)))

	if h.metrics != nil {
		h.metrics.batchSize.Observe(float64(len(batch)))
	}

	for _, msg := range batch {
		h.processMessage(msg)
	}
}

// roundProcessor manages round advancement
func (h *Handler) roundProcessor() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var lastRound round.Number = 0
	var roundStartTime time.Time

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-ticker.C:
			r := h.currentRound.Load().(*roundWrapper).round

			// Track round transitions
			if r.Number() != lastRound {
				if lastRound > 0 {
					atomic.AddUint64(&h.roundsCompleted, 1)

					if h.metrics != nil {
						h.metrics.roundsCompleted.Inc()
						h.metrics.roundDuration.Observe(time.Since(roundStartTime).Seconds())
					}
				}

				h.log.Info("advanced to round", log.Uint16("round", uint16(r.Number())))
				lastRound = r.Number()
				roundStartTime = time.Now()

				if h.metrics != nil {
					h.metrics.currentRound.Set(float64(r.Number()))
				}
			}

			h.tryAdvanceRound()

		case <-h.done:
			return
		}
	}
}

// tryAdvanceRound attempts to advance to the next round
func (h *Handler) tryAdvanceRound() {
	r := h.currentRound.Load().(*roundWrapper).round

	h.log.Debug("tryAdvanceRound called",
		log.Uint16("current_round", uint16(r.Number())),
		log.String("self", string(r.SelfID())))

	// First, retry any unprocessed messages that might have returned ErrNotReady
	// This handles the case where round 3 messages arrive before round 2 completes
	h.retryUnprocessedMessages(r.Number())

	if !h.hasAllMessages(r) {
		return
	}

	// Use compare-and-swap for lock-free round advancement
	// The LoadOrStore returns the existing value if present, or stores and returns the new value
	if finalized, loaded := h.finalized.LoadOrStore(r.Number(), true); loaded && finalized.(bool) {
		h.log.Debug("round already finalized", log.Uint16("round", uint16(r.Number())))
		// Check if current round has actually advanced
		currentWrapper := h.currentRound.Load().(*roundWrapper)
		if currentWrapper.round.Number() > r.Number() {
			h.log.Debug("current round already advanced",
				log.Uint16("checking", uint16(r.Number())),
				log.Uint16("current", uint16(currentWrapper.round.Number())))
			return // We're already past this round
		}
		// Check if we need to advance to the next round that was stored by initializeRound
		nextRoundNum := r.Number() + 1
		if nextRoundObj, ok := h.rounds.Load(nextRoundNum); ok {
			nextRound := nextRoundObj.(*roundWrapper).round
			if nextRound.Number() > r.Number() {
				h.currentRound.Store(&roundWrapper{round: nextRound})
				h.log.Info("advancing to next round (already initialized)",
					log.Uint16("from", uint16(r.Number())),
					log.Uint16("to", uint16(nextRound.Number())))

				// CRITICAL: Check if the new round needs immediate initialization
				// This was previously missed for BroadcastRounds when taking this path
				broadcastRound, isBroadcastRound := nextRound.(round.BroadcastRound)
				if isBroadcastRound {
					bc := broadcastRound.BroadcastContent()
					if bc != nil {
						h.log.Debug("next round needs immediate initialization (BroadcastRound in already-finalized path)",
							log.Uint16("round", uint16(nextRound.Number())))
						go h.initializeRound(nextRound)
						return
					}
				} else if nextRound.MessageContent() != nil {
					h.log.Debug("next round needs immediate initialization (P2P-only in already-finalized path)",
						log.Uint16("round", uint16(nextRound.Number())))
					go h.initializeRound(nextRound)
					return
				}
				// CRITICAL FIX: For "pure finalize" rounds (no BroadcastContent AND no MessageContent),
				// we still need to call initializeRound so that Finalize is called to complete the protocol.
				// Example: LSS sign round3 has no content but its Finalize returns the signature result.
				h.log.Debug("next round is pure-finalize round (no content), initializing",
					log.Uint16("round", uint16(nextRound.Number())))
				go h.initializeRound(nextRound)
			}
		} else {
			// Round is finalized but next round not stored yet - another goroutine is still
			// running initializeRound/finalizeRound. Retry after a short delay to allow it to complete.
			// But first check if the protocol has completed (in which case there's no next round).
			select {
			case <-h.done:
				// Protocol completed, no retry needed
				h.log.Debug("round finalized, protocol completed, no retry needed",
					log.Uint16("round", uint16(r.Number())))
				return
			case <-h.ctx.Done():
				// Context canceled, no retry needed
				return
			default:
				// Check if a retry is already pending for this round to prevent goroutine accumulation
				if _, alreadyPending := h.pendingRetries.LoadOrStore(r.Number(), true); alreadyPending {
					// Another goroutine is already handling the retry, don't spawn another
					return
				}

				// Protocol still running, schedule retry
				h.log.Debug("round finalized but next round not yet stored, scheduling retry",
					log.Uint16("round", uint16(r.Number())),
					log.Uint16("expected_next", uint16(nextRoundNum)))
				go func() {
					defer h.pendingRetries.Delete(r.Number())
					select {
					case <-time.After(10 * time.Millisecond):
						// Check again if protocol is done before retrying
						select {
						case <-h.done:
							return
						case <-h.ctx.Done():
							return
						default:
							h.tryAdvanceRound()
						}
					case <-h.done:
						return
					case <-h.ctx.Done():
						return
					}
				}()
			}
		}
		return // Already finalized this round
	}

	h.log.Debug("finalizing round", log.Uint16("round", uint16(r.Number())))

	// Finalize round and get next round
	nextRound := h.finalizeRound(r)
	if nextRound == nil {
		h.log.Debug("finalizeRound returned nil")
		return
	}

	if nextRound.Number() == r.Number() {
		// Round returned itself - not ready to advance yet
		// This happens in LSS keygen round 1 when it doesn't have all broadcasts yet
		h.log.Debug("round returned itself in finalizeRound, not advancing",
			log.Uint16("round", uint16(r.Number())))
		// Remove from finalized map so we can try again later
		h.finalized.Delete(r.Number())
		return
	}

	if nextRound.Number() > r.Number() {
		h.currentRound.Store(&roundWrapper{round: nextRound})
		h.rounds.Store(nextRound.Number(), &roundWrapper{round: nextRound})

		h.log.Info("storing new currentRound",
			log.Uint16("from", uint16(r.Number())),
			log.Uint16("to", uint16(nextRound.Number())))

		// First process any unverified messages from the previous round
		if r.Number() > 0 {
			h.processQueuedMessages(r.Number())
		}

		// Check if the new round needs immediate initialization
		// This happens when a round has MessageContent (sends P2P messages) but doesn't
		// expect any incoming messages initially (like LSS round 2)
		// We need to finalize it immediately to send those messages
		//
		// Determine if the new round needs immediate initialization
		// This is needed for:
		// 1. P2P-only rounds (MessageContent != nil, no BroadcastContent) - to send P2P messages
		// 2. BroadcastRounds - to send their broadcasts
		//
		// Without immediate initialization, BroadcastRounds would deadlock:
		// handler waits for broadcasts, but broadcasts can only be sent by Finalize
		needsImmediateInit := false
		broadcastRound, isBroadcastRound := nextRound.(round.BroadcastRound)
		h.log.Debug("checking round for immediate init",
			log.Uint16("round", uint16(nextRound.Number())),
			log.Bool("isBroadcastRound", isBroadcastRound),
			log.Bool("hasMessageContent", nextRound.MessageContent() != nil))
		if isBroadcastRound {
			bc := broadcastRound.BroadcastContent()
			h.log.Debug("BroadcastContent check",
				log.Uint16("round", uint16(nextRound.Number())),
				log.Bool("hasContent", bc != nil))
			if bc != nil {
				// This is a BroadcastRound - it needs to be initialized to SEND its broadcasts
				needsImmediateInit = true
				h.log.Debug("round needs immediate initialization (BroadcastRound)",
					log.Uint16("round", uint16(nextRound.Number())))
			}
		} else if nextRound.MessageContent() != nil {
			// This is a P2P-only round (like LSS keygen round 2)
			// It needs to be initialized immediately to send messages
			needsImmediateInit = true
			h.log.Debug("round needs immediate initialization (P2P-only round)",
				log.Uint16("round", uint16(nextRound.Number())))
		}

		if needsImmediateInit {
			// Initialize the round immediately to send its messages
			go h.initializeRound(nextRound)
		} else {
			// Process any queued messages for new round
			go h.processQueuedMessages(nextRound.Number())
		}
	}
}

// Accept accepts a message with non-blocking queue management
func (h *Handler) Accept(msg *Message) {
	if msg == nil {
		return
	}
	if h.metrics != nil {
		h.metrics.queuedMessages.Inc()
	}

	// Debug log
	// if msg.RoundNumber == 3 && !msg.Broadcast {
	// 	fmt.Printf("Accept: p2p round 3 from %s to %s\n", msg.From, msg.To)
	// }

	// Try priority queue for important messages
	if msg.RoundNumber == 0 || msg.Broadcast {
		select {
		case h.priority <- msg:
			return
		default:
			// Fall through to regular queue
		}
	}

	// Try regular queue
	select {
	case h.incoming <- msg:

	case <-h.ctx.Done():
		h.log.Debug("dropping message - context canceled")

	default:
		// Queue full, drop message
		h.log.Warn("message queue full, dropping message",
			log.String("from", string(msg.From)))

		if h.metrics != nil {
			h.metrics.messagesDropped.Inc()
		}
	}
}

// Result returns the protocol result immediately if available
func (h *Handler) Result() (interface{}, error) {
	// Check if we already have a result
	if result := h.result.Load(); result != nil {
		duration := time.Since(h.protocolStartTime)
		h.log.Info("protocol completed successfully", log.Duration("duration", duration))

		if h.metrics != nil {
			h.metrics.protocolsCompleted.Inc()
			h.metrics.protocolDuration.Observe(duration.Seconds())
		}

		return result, nil
	}

	// Check if we have an error
	if err := h.err.Load(); err != nil {
		e := err.(*Error)
		h.log.Error("protocol failed", log.Err(e.Err))

		if h.metrics != nil {
			h.metrics.protocolsFailed.Inc()
		}

		return nil, *e
	}

	// Check if context was canceled
	select {
	case <-h.ctx.Done():
		h.log.Error("protocol canceled")

		if h.metrics != nil {
			h.metrics.protocolsFailed.Inc()
		}

		return nil, h.ctx.Err()
	default:
	}

	// Protocol not finished yet
	return nil, errors.New("protocol: not finished")
}

// WaitForResult blocks until the protocol completes or times out
func (h *Handler) WaitForResult() (interface{}, error) {
	timeout := h.config.ProtocolTimeout
	if timeout == 0 {
		timeout = 5 * time.Minute // Default timeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timer.C:
			h.log.Error("protocol timeout", log.Duration("timeout", h.config.ProtocolTimeout))

			if h.metrics != nil {
				h.metrics.protocolsFailed.Inc()
			}

			return nil, errors.New("protocol: timeout waiting for result")

		case <-ticker.C:
			if result := h.result.Load(); result != nil {
				duration := time.Since(h.protocolStartTime)
				h.log.Info("protocol completed successfully", log.Duration("duration", duration))

				if h.metrics != nil {
					h.metrics.protocolsCompleted.Inc()
					h.metrics.protocolDuration.Observe(duration.Seconds())
				}

				return result, nil
			}

			if err := h.err.Load(); err != nil {
				e := err.(*Error)
				h.log.Error("protocol failed", log.Err(e.Err))

				if h.metrics != nil {
					h.metrics.protocolsFailed.Inc()
				}

				return nil, *e
			}

		case <-h.ctx.Done():
			// When context is done, first check if we have a result
			// This handles the race where protocol completes and cancels context
			// but context Done fires before ticker case gets the result
			if result := h.result.Load(); result != nil {
				duration := time.Since(h.protocolStartTime)
				h.log.Info("protocol completed successfully (caught on context done)", log.Duration("duration", duration))

				if h.metrics != nil {
					h.metrics.protocolsCompleted.Inc()
					h.metrics.protocolDuration.Observe(duration.Seconds())
				}

				return result, nil
			}

			h.log.Error("protocol canceled")

			if h.metrics != nil {
				h.metrics.protocolsFailed.Inc()
			}

			return nil, h.ctx.Err()
		}
	}
}

// Listen returns the output channel
func (h *Handler) Listen() <-chan *Message {
	return h.out
}

// Stop gracefully shuts down the handler
func (h *Handler) Stop() {
	h.stopOnce.Do(func() {
		h.log.Info("stopping protocol handler")

		// Mark as stopped
		h.stopped.Store(true)

		// Cancel context to stop all workers
		h.cancel()

		// Wait for workers to finish
		h.workerGroup.Wait()

		// Close channels safely (out may already be closed by protocol completion).
		// Take outMu so any in-flight sendRoundMessage drains before we close.
		h.outMu.Lock()
		h.outClosed.Store(true)
		h.closeOnce.Do(func() {
			close(h.out)
		})
		h.outMu.Unlock()

		// Close other channels
		close(h.incoming)
		close(h.priority)
		h.closeDoneOnce.Do(func() {
			close(h.done)
		})

		h.log.Info("protocol handler stopped",
			log.Uint64("messages_processed", h.messagesProcessed),
			log.Uint64("rounds_completed", h.roundsCompleted))
	})
}

// CanAccept checks if a message can be accepted
func (h *Handler) CanAccept(msg *Message) bool {
	if msg == nil || msg.Data == nil {
		return false
	}

	r := h.currentRound.Load().(*roundWrapper).round

	// Check protocol and session ID
	if msg.Protocol != r.ProtocolID() {
		return false
	}

	if !bytes.Equal(msg.SSID, r.SSID()) {
		return false
	}

	// Check if we're the intended recipient
	if !msg.IsFor(r.SelfID()) {
		return false
	}

	// Check sender is valid
	if !r.PartyIDs().Contains(msg.From) {
		return false
	}

	// Check round number is valid
	if msg.RoundNumber > r.FinalRoundNumber() {
		return false
	}

	if msg.RoundNumber < r.Number() && msg.RoundNumber > 0 {
		return false
	}

	return true
}

// finalize method removed - functionality integrated into NewHandler

// metricsUpdater periodically updates gauge metrics
func (h *Handler) metricsUpdater() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return

		case <-ticker.C:
			// Update queue depth
			h.metrics.queuedMessages.Set(float64(len(h.incoming) + len(h.priority)))

			// Update memory usage
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			h.metrics.memoryUsage.Set(float64(m.Alloc))
		}
	}
}

// Helper methods for perfect protocol execution...

func (h *Handler) initializeRound(r round.Session) {
	if r == nil {
		h.log.Debug("initializeRound called with nil round, ignoring")
		return
	}
	h.log.Debug("initializing round", log.Uint16("round", uint16(r.Number())))

	// Process any messages that might already be waiting BEFORE claiming finalized lock
	h.processQueuedMessages(r.Number())

	// Check if this round needs to wait for incoming messages before Finalize.
	// There are three cases where we must wait:
	//
	// 1. FINAL round - aggregates data from all parties (e.g., SigmaShares in sign round 5)
	//    The final round's Finalize computes the final result using data from all parties.
	//
	// 2. Round with MessageContent (P2P messages) - StoreMessage populates state that Finalize uses
	//    Example: Sign round 3 - StoreMessage sets DeltaShareAlpha[from], Finalize reads DeltaShareAlpha[j]
	//    If we call Finalize before StoreMessage, we get nil pointer panics.
	//
	// 3. Round with BroadcastContent (broadcast messages) - StoreBroadcastMessage populates state
	//    Example: FROST round 2 - StoreBroadcastMessage sets ChainKeyCommitments, Finalize checks count
	//    If we call Finalize before StoreBroadcastMessage, we get "missing chain key commitments" errors.
	//
	// Note: Round 1 only SENDS broadcasts via Finalize, it doesn't RECEIVE broadcasts.
	// Rounds 2+ that have BroadcastContent DO receive broadcasts from the previous round.
	// So we only wait for broadcasts if r.Number() > 1.
	isFinalRound := r.Number() == r.FinalRoundNumber()
	hasIncomingP2P := r.MessageContent() != nil
	hasIncomingBroadcast := false
	if r.Number() > 1 {
		if br, ok := r.(round.BroadcastRound); ok && br.BroadcastContent() != nil {
			hasIncomingBroadcast = true
		}
	}

	// Determine if we should wait for messages before calling Finalize.
	//
	// Key insight: Some rounds (like LSS round 2) use a "send-first" pattern where
	// Finalize sends P2P messages first, then returns self to wait for replies.
	// Other rounds (like CMP/FROST) receive messages from the previous round's Finalize
	// and expect that data to be available when their Finalize is called.
	//
	// We can distinguish these cases by checking if ANY messages have arrived:
	// - If messages have arrived: they're "in flight" from previous round → wait for all
	// - If no messages yet: this might be a "send-first" round → call Finalize
	shouldWait := false

	if hasIncomingP2P {
		// For P2P-only rounds (like LSS round 2), we should ALWAYS call Finalize first.
		// The round's Finalize handles the "send-first, wait-for-replies" pattern:
		// - First Finalize: sends shares, stores own share, returns self
		// - Second Finalize: checks if all shares received, returns next round or self
		//
		// We previously waited if some P2P messages had arrived, but this caused a deadlock:
		// - Party A waits for all shares before Finalize
		// - But party A has shares that others need
		// - Everyone waits, no one sends
		//
		// Now we always call Finalize for P2P rounds, and let the round logic decide.
		// The round will return itself if it's not ready to advance.
		h.log.Debug("P2P round - will call Finalize to send shares",
			log.Uint16("round", uint16(r.Number())))
	}

	if hasIncomingBroadcast {
		// For broadcast rounds, we must ALWAYS call Finalize first to send our own broadcast.
		// Only wait if we've already sent our broadcast (check if it's stored).
		// CRITICAL FIX: If we wait before sending our own broadcast, we deadlock:
		// - Party A waits for B and C's broadcasts
		// - Party B waits for A and C's broadcasts
		// - No one sends, everyone waits
		selfBroadcastKey := fmt.Sprintf("%d:%s", r.Number(), r.SelfID())
		broadcasts := h.broadcast.LoadAll(r.Number())
		hasSentOwnBroadcast := broadcasts[r.SelfID()] != nil

		if hasSentOwnBroadcast && !h.hasAllMessages(r) {
			// We've sent our broadcast, now wait for others
			shouldWait = true
			h.log.Debug("broadcast round: sent own broadcast, waiting for others",
				log.Uint16("round", uint16(r.Number())),
				log.String("self", string(r.SelfID())))
		} else if !hasSentOwnBroadcast {
			// Haven't sent our broadcast yet - MUST call Finalize first
			h.log.Debug("broadcast round: need to send own broadcast first",
				log.Uint16("round", uint16(r.Number())),
				log.String("self", string(r.SelfID())))
		}
		_ = selfBroadcastKey // suppress unused warning
	}

	// Final round always waits for all messages
	if isFinalRound && !h.hasAllMessages(r) {
		shouldWait = true
	}

	if shouldWait {
		h.log.Debug("round waiting for all messages",
			log.Uint16("round", uint16(r.Number())),
			log.Bool("isFinal", isFinalRound),
			log.Bool("hasP2P", hasIncomingP2P),
			log.Bool("hasBroadcast", hasIncomingBroadcast))
		return
	}

	// Now we're ready to finalize - claim the lock
	if finalized, loaded := h.finalized.LoadOrStore(r.Number(), true); loaded && finalized.(bool) {
		h.log.Debug("round already being finalized, skipping",
			log.Uint16("round", uint16(r.Number())))
		return
	}

	// IMPORTANT: Call Finalize for rounds that:
	// 1. Need to send broadcasts/P2P messages
	// 2. Have all required incoming messages
	//
	// The round's Finalize method handles:
	// 1. Sending broadcasts/P2P messages
	// 2. Returning itself if waiting for incoming messages
	// 3. Returning the next round when ready to advance

	out := make(chan *round.Message, r.N()+1)

	// Start a goroutine to call Finalize and close the channel
	var nextRound round.Session
	var finalizeErr error
	done := make(chan struct{})

	go func() {
		defer close(out)
		defer close(done)
		// Hold roundMu so concurrent VerifyMessage / StoreMessage on the same
		// round (or its shared state) does not race with Finalize's reads.
		h.roundMu.Lock()
		defer h.roundMu.Unlock()
		nextRound, finalizeErr = r.Finalize(out)
	}()

	// Count messages for logging
	messageCount := 0

	// Process generated messages
	for msg := range out {
		messageCount++
		h.sendRoundMessage(msg, r)
	}

	// Wait for Finalize to complete
	<-done

	if finalizeErr != nil {
		h.handleError(finalizeErr, r.SelfID())
		return
	}

	h.log.Debug("generated messages",
		log.Uint16("round", uint16(r.Number())),
		log.Int("count", messageCount))

	// Store next round and advance if appropriate
	if nextRound != nil {
		// Check for protocol completion first
		if output, ok := nextRound.(*round.Output); ok {
			h.result.Store(output.Result)
			h.log.Info("protocol completed in initialization",
				log.String("self", string(r.SelfID())),
				log.Uint16("final_round", uint16(r.Number())))
			// Close done channel to signal completion to workers
			h.closeDoneOnce.Do(func() {
				close(h.done)
			})
			// Cancel context immediately to stop all workers
			// This must happen before WaitForResult returns
			h.cancel()
			// Close output channel asynchronously to allow final message delivery
			go func() {
				time.Sleep(10 * time.Millisecond)
				h.outMu.Lock()
				h.outClosed.Store(true)
				h.closeOnce.Do(func() {
					close(h.out)
				})
				h.outMu.Unlock()
			}()
			return
		}

		// Check for protocol abort
		if abort, ok := nextRound.(*round.Abort); ok {
			h.handleError(abort.Err, abort.Culprits...)
			return
		}

		if nextRound.Number() > r.Number() {
			// Store the next round for later use but DON'T advance to it yet
			// We need to wait for all round 1 messages to be processed first
			h.rounds.Store(nextRound.Number(), &roundWrapper{round: nextRound})
			// DON'T change currentRound yet - wait for tryAdvanceRound to do it
			h.log.Info("stored next round after initialization",
				log.Uint16("from", uint16(r.Number())),
				log.Uint16("next", uint16(nextRound.Number())))

			// Try to advance (which will check if we have all messages)
			go func() {
				time.Sleep(10 * time.Millisecond) // Small delay for message propagation
				h.tryAdvanceRound()
			}()
		} else if nextRound.Number() == r.Number() {
			// Round returned itself - not ready to advance yet
			// This happens in some protocols when waiting for messages
			h.log.Debug("round returned itself in initialization",
				log.Uint16("round", uint16(r.Number())),
				log.Bool("returned_self_in_initialize", true))

			// IMPORTANT: Unmark as finalized so it can be finalized again later
			// This is critical for protocols like LSS that return themselves when not ready
			h.finalized.Delete(r.Number())

			// CRITICAL FIX: Re-drive advancement immediately
			// Process any messages that arrived while we were initializing
			h.processQueuedMessages(r.Number())
			// Try to advance now that our outbound is sent + inbound is queued
			// Use a select with a timer to avoid blocking forever
			go func() {
				select {
				case <-time.After(10 * time.Millisecond):
					h.tryAdvanceRound()
				case <-h.ctx.Done():
					// Context canceled, don't try to advance
					return
				}
			}()
		}
	}
}

// safeSend sends a message to the output channel without blocking.
// Takes outMu to serialize with concurrent close paths (Stop, protocol-complete).
// Returns false if the channel is full, closed, or the handler has stopped.
func (h *Handler) safeSend(msg *Message) (sent bool) {
	h.outMu.RLock()
	defer h.outMu.RUnlock()
	if h.outClosed.Load() {
		return false
	}
	select {
	case h.out <- msg:
		sent = true
	default:
		sent = false
	}
	return
}

func (h *Handler) sendRoundMessage(msg *round.Message, r round.Session) {
	h.log.Debug("sendRoundMessage",
		log.String("from", string(r.SelfID())),
		log.String("to", string(msg.To)),
		log.Uint16("round", uint16(msg.Content.RoundNumber())),
		log.Bool("broadcast", msg.Broadcast))

	data, err := cbor.Marshal(msg.Content)
	if err != nil {
		h.handleError(err, r.SelfID())
		return
	}

	// Compress if large
	compressed := false
	if h.config.EnableCompression && len(data) > h.config.CompressionThreshold {
		data = h.compressData(data)
		compressed = true
	}

	protocolMsg := &Message{
		SSID:        r.SSID(),
		From:        r.SelfID(),
		To:          msg.To,
		Protocol:    r.ProtocolID(),
		RoundNumber: msg.Content.RoundNumber(),
		Data:        data,
		Broadcast:   msg.Broadcast,
		Compressed:  compressed,
	}

	if msg.Broadcast {
		h.storeMessage(protocolMsg)
	}

	// Take the read lock so Stop / protocol-complete close paths cannot close
	// h.out between the outClosed check and the chan send below.
	h.outMu.RLock()
	defer h.outMu.RUnlock()
	if h.stopped.Load() || h.outClosed.Load() {
		h.log.Debug("skipping send - handler stopped or channel closed")
		return
	}

	select {
	case h.out <- protocolMsg:
		h.log.Debug("sent message to output channel",
			log.String("from", string(protocolMsg.From)),
			log.String("to", string(protocolMsg.To)),
			log.Uint16("round", uint16(protocolMsg.RoundNumber)),
			log.Bool("broadcast", protocolMsg.Broadcast))
		if h.metrics != nil {
			h.metrics.messagesSent.Inc()
		}
	case <-h.ctx.Done():
		h.log.Debug("failed to send message - context canceled")
	}
}

func (h *Handler) handleAbort(msg *Message) {
	err := fmt.Errorf("aborted by %s: %s", msg.From, msg.Data)
	h.log.Warn("protocol aborted", log.String("from", string(msg.From)))
	h.handleError(err, msg.From)
}

func (h *Handler) handleError(err error, culprits ...party.ID) {
	if err == nil {
		return
	}

	protocolErr := &Error{
		Err:      err,
		Culprits: culprits,
	}

	// Try to set error atomically
	if h.err.CompareAndSwap(nil, protocolErr) {
		h.log.Error("protocol error - canceling context",
			log.Err(err),
			log.String("culprits", fmt.Sprintf("%v", culprits)))

		// Send abort message using safeSend to handle race with channel close
		if !h.outClosed.Load() {
			r := h.currentRound.Load().(*roundWrapper).round
			abortMsg := &Message{
				SSID:     r.SSID(),
				From:     r.SelfID(),
				Protocol: r.ProtocolID(),
				Data:     []byte(err.Error()),
			}
			h.safeSend(abortMsg)
		}

		h.cancel()

		// Close output channel after delay to signal protocol end
		go func() {
			time.Sleep(50 * time.Millisecond)
			h.outMu.Lock()
			h.outClosed.Store(true)
			h.closeOnce.Do(func() {
				close(h.out)
			})
			h.outMu.Unlock()
		}()
	}
}

func (h *Handler) finalizeRound(r round.Session) round.Session {
	// Check if we already have the next round stored (from initializeRound)
	nextRoundNum := r.Number() + 1
	if nextRoundObj, ok := h.rounds.Load(nextRoundNum); ok {
		h.log.Debug("found existing next round",
			log.Uint16("current", uint16(r.Number())),
			log.Uint16("next", uint16(nextRoundNum)))
		return nextRoundObj.(*roundWrapper).round
	}

	// We need to finalize this round
	out := make(chan *round.Message, r.N()+1)

	// Use goroutine like initializeRound does to allow async message generation
	var nextRound round.Session
	var err error
	done := make(chan struct{})

	go func() {
		defer close(out)
		defer close(done)
		// Hold roundMu so concurrent VerifyMessage / StoreMessage on the same
		// round (or its shared state — Pedersen params, etc.) does not race
		// with Finalize's read of those values.
		h.roundMu.Lock()
		defer h.roundMu.Unlock()
		nextRound, err = r.Finalize(out)
	}()

	// Count messages for logging
	messageCount := 0
	// Process generated messages
	for msg := range out {
		messageCount++
		h.sendRoundMessage(msg, r)
	}

	// Wait for Finalize to complete
	<-done

	if err != nil {
		h.handleError(err, r.SelfID())
		return nil
	}

	h.log.Debug("finalized round messages",
		log.Uint16("round", uint16(r.Number())),
		log.Int("messages", messageCount),
		log.Bool("returned_self", nextRound == r))

	// CRITICAL FIX: If the round returns itself, immediately attempt to advance again
	// in case inbound messages arrived while we were finalizing/sending
	if nextRound == r {
		h.log.Debug("round returned itself in finalize, re-driving advancement",
			log.Bool("returned_self_in_finalize", true))
		// Process any messages queued during finalize
		h.processQueuedMessages(r.Number())
		// Try to advance again with small delay for network propagation
		go func() {
			select {
			case <-time.After(10 * time.Millisecond):
				h.tryAdvanceRound()
			case <-h.ctx.Done():
				// Context canceled, don't try to advance
				return
			}
		}()
		return r
	}

	// Check for completion
	switch result := nextRound.(type) {
	case *round.Output:
		h.result.Store(result.Result)
		h.log.Info("protocol completed",
			log.String("self", string(r.SelfID())),
			log.Uint16("final_round", uint16(r.Number())))
		// Close done channel to signal completion to workers
		h.closeDoneOnce.Do(func() {
			close(h.done)
		})
		// Close output channel to signal HandlerLoop that protocol is complete
		// This is safe because we're done sending messages
		go func() {
			// Give a small delay to allow any final messages to be sent
			time.Sleep(10 * time.Millisecond)
			h.outMu.Lock()
			h.outClosed.Store(true)
			h.closeOnce.Do(func() {
				close(h.out)
			})
			h.outMu.Unlock()
			// Clean up all goroutines after closing the output channel
			time.Sleep(10 * time.Millisecond)
			h.cancel() // Cancel context to stop all workers
		}()
		return nil

	case *round.Abort:
		h.handleError(result.Err, result.Culprits...)
		return nil
	}

	if nextRound != nil {
		h.log.Debug("finalize returned next round",
			log.Uint16("current", uint16(r.Number())),
			log.Uint16("next", uint16(nextRound.Number())))
	} else {
		h.log.Debug("finalize returned nil")
	}

	return nextRound
}

func (h *Handler) verifyBroadcastForRound(msg *Message, roundNum round.Number) {
	// Prevent concurrent verification of the same message
	// This is critical because ZK proof verification is expensive
	key := fmt.Sprintf("%d:%s", roundNum, msg.From)
	if _, loaded := h.verifyingBroadcasts.LoadOrStore(key, true); loaded {
		return // Already being verified by another goroutine
	}
	defer h.verifyingBroadcasts.Delete(key)

	// Check if already processed (double-check after acquiring the verification lock)
	if _, processed := h.processedBroadcasts.Load(key); processed {
		return
	}

	// Verify a broadcast message for a specific round
	roundObj, ok := h.rounds.Load(roundNum)
	if !ok {
		return
	}

	r := roundObj.(*roundWrapper).round
	broadcastRound, ok := r.(round.BroadcastRound)
	if !ok {
		h.handleError(errors.New("unexpected broadcast message"), msg.From)
		return
	}

	// Unmarshal content
	content := broadcastRound.BroadcastContent()
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		h.handleError(err, msg.From)
		return
	}

	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: true,
	}

	h.roundMu.Lock()
	defer h.roundMu.Unlock()

	if err := broadcastRound.StoreBroadcastMessage(roundMsg); err != nil {
		// If the round is not ready, don't treat as error - message remains queued
		if err == round.ErrNotReady {
			h.log.Debug("round not ready for broadcast message, will retry later",
				log.String("from", string(msg.From)),
				log.Uint16("round", uint16(roundNum)))
			return
		}
		h.handleError(err, msg.From)
	} else {
		// Mark this broadcast as processed
		key := fmt.Sprintf("%d:%s", roundNum, msg.From)
		h.processedBroadcasts.Store(key, true)
	}
}

func (h *Handler) verifyNormalForRound(msg *Message, roundNum round.Number) {
	// Prevent concurrent verification of the same message
	key := fmt.Sprintf("%d:%s", roundNum, msg.From)
	if _, loaded := h.verifyingMessages.LoadOrStore(key, true); loaded {
		return // Already being verified by another goroutine
	}
	defer h.verifyingMessages.Delete(key)

	// Check if already processed (double-check after acquiring the verification lock)
	if _, processed := h.processedMessages.Load(key); processed {
		return
	}

	// Verify a normal message for a specific round
	roundObj, ok := h.rounds.Load(roundNum)
	if !ok {
		return
	}

	r := roundObj.(*roundWrapper).round

	// Check if we have required broadcast first
	// Only check if BroadcastContent() is non-nil (some rounds embed BroadcastRound but don't use it)
	// CRITICAL: We must check processedBroadcasts (set after StoreBroadcastMessage succeeds),
	// not just if the broadcast message is queued. StoreBroadcastMessage populates round state
	// (e.g., r.K[from]) that VerifyMessage depends on.
	if br, ok := r.(round.BroadcastRound); ok && br.BroadcastContent() != nil {
		key := fmt.Sprintf("%d:%s", r.Number(), msg.From)
		if _, processed := h.processedBroadcasts.Load(key); !processed {
			h.log.Debug("waiting for broadcast to be processed before normal message",
				log.String("from", string(msg.From)),
				log.Uint16("round", uint16(r.Number())))
			return
		}
	}

	// Unmarshal content
	content := r.MessageContent()
	if content == nil {
		return
	}

	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		h.handleError(err, msg.From)
		return
	}

	// Create round message
	roundMsg := round.Message{
		From:    msg.From,
		To:      msg.To,
		Content: content,
	}

	// Verify + Store under roundMu so concurrent verifications for different
	// (from) pairs in the same round don't race on shared round state.
	h.roundMu.Lock()
	defer h.roundMu.Unlock()

	if err := r.VerifyMessage(roundMsg); err != nil {
		h.handleError(err, msg.From)
		return
	}

	if err := r.StoreMessage(roundMsg); err != nil {
		// If the round is not ready, don't treat as error - message remains queued
		if err == round.ErrNotReady {
			h.log.Debug("round not ready for p2p message, will retry later",
				log.String("from", string(msg.From)),
				log.Uint16("round", uint16(roundNum)))
			return
		}
		h.handleError(err, msg.From)
	} else {
		// Mark this message as processed
		key := fmt.Sprintf("%d:%s", roundNum, msg.From)
		h.processedMessages.Store(key, true)
	}
}

func (h *Handler) verifyBroadcast(msg *Message) {
	// Only verify messages for the current round
	currentRound := h.currentRound.Load().(*roundWrapper).round
	if msg.RoundNumber != currentRound.Number() {
		h.log.Debug("skipping verification for different round",
			log.Uint16("msg_round", uint16(msg.RoundNumber)),
			log.Uint16("current_round", uint16(currentRound.Number())))
		return
	}

	roundObj, ok := h.rounds.Load(msg.RoundNumber)
	if !ok {
		return
	}

	r := roundObj.(*roundWrapper).round
	broadcastRound, ok := r.(round.BroadcastRound)
	if !ok {
		h.handleError(errors.New("unexpected broadcast message"), msg.From)
		return
	}

	// For now, skip broadcast hash verification (would implement properly)
	// This needs proper integration with the hash package

	// Unmarshal content
	content := broadcastRound.BroadcastContent()
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		h.handleError(err, msg.From)
		return
	}

	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: true,
	}

	h.roundMu.Lock()
	defer h.roundMu.Unlock()

	if err := broadcastRound.StoreBroadcastMessage(roundMsg); err != nil {
		// If the round is not ready, don't treat as error - just skip for now
		// The message will be retried when we process queued messages
		if err == round.ErrNotReady {
			h.log.Debug("round not ready for broadcast message, will retry later",
				log.String("from", string(msg.From)),
				log.Uint16("round", uint16(msg.RoundNumber)))
			return
		}
		h.handleError(err, msg.From)
	} else {
		// Mark this broadcast as processed
		key := fmt.Sprintf("%d:%s", msg.RoundNumber, msg.From)
		h.processedBroadcasts.Store(key, true)
	}
}

func (h *Handler) verifyNormal(msg *Message) {
	// Only verify messages for the current round
	currentRound := h.currentRound.Load().(*roundWrapper).round
	if msg.RoundNumber != currentRound.Number() {
		h.log.Debug("skipping verification for different round",
			log.Uint16("msg_round", uint16(msg.RoundNumber)),
			log.Uint16("current_round", uint16(currentRound.Number())))
		return
	}

	roundObj, ok := h.rounds.Load(msg.RoundNumber)
	if !ok {
		return
	}

	r := roundObj.(*roundWrapper).round

	// Check if we have required broadcast first
	// Only check if BroadcastContent() is non-nil (some rounds embed BroadcastRound but don't use it)
	// CRITICAL: We must check processedBroadcasts (set after StoreBroadcastMessage succeeds),
	// not just if the broadcast message is queued. StoreBroadcastMessage populates round state
	// (e.g., r.K[from]) that VerifyMessage depends on.
	if br, isBroadcast := r.(round.BroadcastRound); isBroadcast && br.BroadcastContent() != nil {
		key := fmt.Sprintf("%d:%s", msg.RoundNumber, msg.From)
		if _, processed := h.processedBroadcasts.Load(key); !processed {
			h.log.Debug("waiting for broadcast to be processed before normal message",
				log.String("from", string(msg.From)),
				log.Uint16("round", uint16(msg.RoundNumber)))
			return // Wait for broadcast to be processed first
		}
	}

	// Unmarshal content
	content := r.MessageContent()
	if content == nil {
		return // Round doesn't expect messages
	}

	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		h.handleError(err, msg.From)
		return
	}

	roundMsg := round.Message{
		From:    msg.From,
		To:      msg.To,
		Content: content,
	}

	h.roundMu.Lock()
	defer h.roundMu.Unlock()

	if err := r.VerifyMessage(roundMsg); err != nil {
		h.handleError(err, msg.From)
		return
	}

	if err := r.StoreMessage(roundMsg); err != nil {
		// If the round is not ready, don't treat as error - just skip for now
		// The message will be retried when we process queued messages
		if err == round.ErrNotReady {
			h.log.Debug("round not ready for p2p message, will retry later",
				log.String("from", string(msg.From)),
				log.Uint16("round", uint16(msg.RoundNumber)))
			return
		}
		h.handleError(err, msg.From)
	} else {
		// Mark this message as processed
		key := fmt.Sprintf("%d:%s", msg.RoundNumber, msg.From)
		h.processedMessages.Store(key, true)
	}
}

// retryUnprocessedMessages retries messages that may have returned ErrNotReady
func (h *Handler) retryUnprocessedMessages(roundNum round.Number) {
	// Process broadcasts that haven't been processed yet
	broadcasts := h.broadcast.LoadAll(roundNum)
	r := h.currentRound.Load().(*roundWrapper).round
	for from, msg := range broadcasts {
		if msg != nil && from != r.SelfID() {
			// Check if already processed
			key := fmt.Sprintf("%d:%s", roundNum, from)
			if _, processed := h.processedBroadcasts.Load(key); !processed {
				// Retry processing the broadcast message
				h.verifyBroadcastForRound(msg, roundNum)
			}
		}
	}

	// Process normal messages that haven't been processed yet
	messages := h.messages.LoadAll(roundNum)
	for from, msg := range messages {
		if msg != nil {
			// Check if already processed
			key := fmt.Sprintf("%d:%s", roundNum, from)
			if _, processed := h.processedMessages.Load(key); !processed {
				// Retry processing the normal message
				h.verifyNormalForRound(msg, roundNum)
			}
		}
	}
}

func (h *Handler) processQueuedMessages(roundNum round.Number) {
	h.log.Debug("processing queued messages", log.Uint16("round", uint16(roundNum)))

	// First process any messages from previous rounds to ensure we have all necessary data
	if roundNum > 1 {
		for prevRound := round.Number(1); prevRound < roundNum; prevRound++ {
			// Process broadcasts from previous rounds
			prevBroadcasts := h.broadcast.LoadAll(prevRound)
			for _, msg := range prevBroadcasts {
				if msg != nil && msg.From != h.currentRound.Load().(*roundWrapper).round.SelfID() {
					// Temporarily set h.processingPreviousRound to allow verification
					h.verifyBroadcastForRound(msg, prevRound)
				}
			}

			// Process normal messages from previous rounds
			prevMessages := h.messages.LoadAll(prevRound)
			for _, msg := range prevMessages {
				if msg != nil {
					h.verifyNormalForRound(msg, prevRound)
				}
			}
		}
	}

	// Now process messages for the current round with retry logic
	// Retry up to 3 times to handle ErrNotReady cases
	for retry := 0; retry < 3; retry++ {
		anyRetried := false

		// Process broadcasts first
		broadcasts := h.broadcast.LoadAll(roundNum)
		r := h.currentRound.Load().(*roundWrapper).round

		for from, msg := range broadcasts {
			if msg != nil && from != r.SelfID() {
				// Check if already processed
				key := fmt.Sprintf("%d:%s", roundNum, from)
				if _, processed := h.processedBroadcasts.Load(key); !processed {
					// Process the queued message directly since we know it's for the right round
					h.verifyBroadcastForRound(msg, roundNum)
					anyRetried = true
				}
			}
		}

		// Then process normal messages
		messages := h.messages.LoadAll(roundNum)
		for from, msg := range messages {
			if msg != nil {
				// Check if already processed
				key := fmt.Sprintf("%d:%s", roundNum, from)
				if _, processed := h.processedMessages.Load(key); !processed {
					// Process the queued message directly
					h.verifyNormalForRound(msg, roundNum)
					anyRetried = true
				}
			}
		}

		// If nothing was retried, we're done
		if !anyRetried {
			break
		}
	}
}

func (h *Handler) hasAllMessages(r round.Session) bool {
	number := r.Number()

	// Check broadcasts - but only if BroadcastContent() returns non-nil
	// Some rounds embed BroadcastRound but don't actually use broadcasts
	if br, ok := r.(round.BroadcastRound); ok && br.BroadcastContent() != nil {
		broadcasts := h.broadcast.LoadAll(number)
		missingBroadcasts := []party.ID{}
		unprocessedBroadcasts := []party.ID{}

		for _, id := range r.PartyIDs() {
			// Skip self - we send our own broadcast, we don't wait for it
			// CRITICAL: This must be checked BEFORE the nil check to prevent livelock
			// where a party waits for its own broadcast that hasn't been sent yet.
			if id == r.SelfID() {
				continue
			}
			if broadcasts[id] == nil {
				missingBroadcasts = append(missingBroadcasts, id)
			} else {
				// Check if this broadcast has been processed by StoreBroadcastMessage
				key := fmt.Sprintf("%d:%s", number, id)
				if _, processed := h.processedBroadcasts.Load(key); !processed {
					unprocessedBroadcasts = append(unprocessedBroadcasts, id)
				} else {
					h.log.Debug("have processed broadcast",
						log.Uint16("round", uint16(number)),
						log.String("from", string(id)),
						log.String("self", string(r.SelfID())))
				}
			}
		}

		if len(missingBroadcasts) > 0 {
			h.log.Debug("waiting for broadcasts",
				log.Uint16("round", uint16(number)),
				log.String("missing", fmt.Sprintf("%v", missingBroadcasts)),
				log.String("self", string(r.SelfID())))
			return false
		}

		if len(unprocessedBroadcasts) > 0 {
			h.log.Debug("waiting for broadcast processing",
				log.Uint16("round", uint16(number)),
				log.String("unprocessed", fmt.Sprintf("%v", unprocessedBroadcasts)),
				log.String("self", string(r.SelfID())))
			return false
		}
	}

	// Check normal messages
	if r.MessageContent() != nil {
		messages := h.messages.LoadAll(number)
		missingMessages := []party.ID{}
		unprocessedMessages := []party.ID{}

		for _, id := range r.OtherPartyIDs() {
			if messages[id] == nil {
				missingMessages = append(missingMessages, id)
			} else {
				// Check if this message has been processed by StoreMessage
				key := fmt.Sprintf("%d:%s", number, id)
				if _, processed := h.processedMessages.Load(key); !processed {
					unprocessedMessages = append(unprocessedMessages, id)
				}
			}
		}

		if len(missingMessages) > 0 {
			h.log.Debug("waiting for messages",
				log.Uint16("round", uint16(number)),
				log.String("missing", fmt.Sprintf("%v", missingMessages)))
			return false
		}

		if len(unprocessedMessages) > 0 {
			h.log.Debug("waiting for message processing",
				log.Uint16("round", uint16(number)),
				log.String("unprocessed", fmt.Sprintf("%v", unprocessedMessages)))
			return false
		}
	}

	h.log.Debug("have all messages and processed",
		log.Uint16("round", uint16(number)),
		log.String("self", string(r.SelfID())))
	return true
}

func (h *Handler) storeMessage(msg *Message) {
	if msg.Broadcast {
		h.log.Debug("storing broadcast",
			log.Uint16("round", uint16(msg.RoundNumber)),
			log.String("from", string(msg.From)))
		h.broadcast.Store(msg.RoundNumber, msg.From, msg)
	} else {
		h.log.Debug("storing message",
			log.Uint16("round", uint16(msg.RoundNumber)),
			log.String("from", string(msg.From)))
		h.messages.Store(msg.RoundNumber, msg.From, msg)
	}
}

// getBroadcastHash removed - not needed in optimized implementation

func (h *Handler) compressData(data []byte) []byte {
	// Simple compression placeholder - would use gzip/zstd in production
	return data
}

func (h *Handler) decompressMessage(msg *Message) *Message {
	// Simple decompression placeholder - would use gzip/zstd in production
	msg.Compressed = false
	return msg
}

// MessageStore provides zero-contention sharded message storage
type MessageStore struct {
	shards [256]*messageShard // 256-way sharding for zero contention
}

type messageShard struct {
	mu   sync.RWMutex
	data map[round.Number]map[party.ID]*Message
}

func newMessageStore() *MessageStore {
	ms := &MessageStore{}
	for i := range ms.shards {
		ms.shards[i] = &messageShard{
			data: make(map[round.Number]map[party.ID]*Message),
		}
	}
	return ms
}

func (ms *MessageStore) getShard(roundNum round.Number) *messageShard {
	// Perfect hash distribution
	hash := uint(roundNum) * 2654435761 // Knuth's multiplicative hash
	return ms.shards[hash%256]
}

func (ms *MessageStore) Store(roundNum round.Number, from party.ID, msg *Message) {
	shard := ms.getShard(roundNum)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if shard.data[roundNum] == nil {
		shard.data[roundNum] = make(map[party.ID]*Message)
	}
	shard.data[roundNum][from] = msg
}

func (ms *MessageStore) Load(roundNum round.Number, from party.ID) (*Message, bool) {
	shard := ms.getShard(roundNum)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	if msgs, ok := shard.data[roundNum]; ok {
		msg, exists := msgs[from]
		return msg, exists
	}
	return nil, false
}

func (ms *MessageStore) LoadAll(roundNum round.Number) map[party.ID]*Message {
	shard := ms.getShard(roundNum)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	msgs := shard.data[roundNum]
	if msgs == nil {
		return nil
	}

	// Return copy to avoid concurrent modification
	result := make(map[party.ID]*Message, len(msgs))
	for k, v := range msgs {
		result[k] = v
	}
	return result
}
