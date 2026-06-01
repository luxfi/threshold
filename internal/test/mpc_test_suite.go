package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	log "github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/stretchr/testify/require"
)

// MPCProtocolType identifies the type of MPC protocol being tested.
type MPCProtocolType string

const (
	ProtocolLSS     MPCProtocolType = "LSS"
	ProtocolFROST   MPCProtocolType = "FROST"
	ProtocolCMP     MPCProtocolType = "CMP"
	ProtocolDoerner MPCProtocolType = "Doerner"
	ProtocolCorona  MPCProtocolType = "Corona"
)

// MPCTestSuite provides a unified initialization + benchmark harness for the
// supported MPC protocols. Round-trip and message-routing happen via the
// PhaseHarness; this type only owns the pool, group, timeout, and labels.
type MPCTestSuite struct {
	t            testing.TB
	protocolType MPCProtocolType
	partyCount   int
	threshold    int
	group        curve.Curve
	pool         *pool.Pool
	timeout      time.Duration
	verbose      bool
}

// NewMPCTestSuite creates a suite with sensible defaults (Secp256k1, 30s timeout).
func NewMPCTestSuite(t testing.TB, protocolType MPCProtocolType, partyCount, threshold int) *MPCTestSuite {
	return &MPCTestSuite{
		t:            t,
		protocolType: protocolType,
		partyCount:   partyCount,
		threshold:    threshold,
		group:        curve.Secp256k1{},
		pool:         pool.NewPool(0),
		timeout:      30 * time.Second,
		verbose:      testing.Verbose(),
	}
}

// WithTimeout overrides the default suite timeout.
func (s *MPCTestSuite) WithTimeout(timeout time.Duration) *MPCTestSuite {
	s.timeout = timeout
	return s
}

// Cleanup tears down the underlying compute pool. Always defer this.
func (s *MPCTestSuite) Cleanup() {
	if s.pool != nil {
		s.pool.TearDown()
	}
}

// RunInitTest verifies the protocol's StartFunc + Handler construction path
// for all parties. It does NOT drive the protocol to completion; that's the
// PhaseHarness's job.
func (s *MPCTestSuite) RunInitTest(createStartFunc func(id party.ID, partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) protocol.StartFunc) {
	partyIDs := PartyIDs(s.partyCount)

	s.t.Logf("Testing %s protocol initialization with %d parties (threshold %d)",
		s.protocolType, s.partyCount, s.threshold)

	for _, id := range partyIDs {
		startFunc := createStartFunc(id, partyIDs, s.threshold, s.group, s.pool)
		require.NotNil(s.t, startFunc,
			"%s: Start function should not be nil for party %s", s.protocolType, id)
	}

	sessionID := []byte(fmt.Sprintf("test-%s-init", s.protocolType))
	handlers := make([]*protocol.Handler, 0, len(partyIDs))

	for _, id := range partyIDs {
		startFunc := createStartFunc(id, partyIDs, s.threshold, s.group, s.pool)

		logger := log.NewTestLogger(log.ErrorLevel)
		if s.verbose {
			logger = log.NewTestLogger(log.InfoLevel)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		config := protocol.DefaultConfig()
		h, err := protocol.NewHandler(ctx, logger, metric.NewRegistry(), startFunc, sessionID, config)
		require.NoError(s.t, err,
			"%s: Failed to create handler for party %s", s.protocolType, id)
		require.NotNil(s.t, h,
			"%s: Handler should not be nil for party %s", s.protocolType, id)

		handlers = append(handlers, h)
	}

	for _, h := range handlers {
		h.Stop()
	}

	s.t.Logf("%s initialization test passed", s.protocolType)
}

// RunBenchmark drives b.N iterations of the suite's protocol through the
// PhaseHarness. Errors are logged in verbose mode only — benchmarks shouldn't
// fail on protocol-level timeouts (they measure throughput, not correctness).
func (s *MPCTestSuite) RunBenchmark(b *testing.B, createStartFunc func(id party.ID, partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) protocol.StartFunc) {
	partyIDs := PartyIDs(s.partyCount)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		harness := NewPhaseHarness(b, partyIDs)

		_, err := harness.RunPhase(s.timeout, func(id party.ID) protocol.StartFunc {
			return createStartFunc(id, partyIDs, s.threshold, s.group, s.pool)
		})

		if err != nil && s.verbose {
			b.Logf("%s benchmark iteration %d: %v", s.protocolType, i, err)
		}
	}
}

// StandardMPCBenchmark runs the suite's standard benchmark sequence.
func StandardMPCBenchmark(b *testing.B, protocolType MPCProtocolType, partyCount, threshold int,
	createStartFunc func(id party.ID, partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) protocol.StartFunc) {
	suite := NewMPCTestSuite(b, protocolType, partyCount, threshold)
	defer suite.Cleanup()

	suite.RunBenchmark(b, createStartFunc)
}

// QuickMPCTest runs the init-only test sequence — suitable for CI/fast feedback
// when the full protocol is too expensive for the normal test budget.
func QuickMPCTest(t *testing.T, protocolType MPCProtocolType, partyCount, threshold int,
	createStartFunc func(id party.ID, partyIDs []party.ID, threshold int, group curve.Curve, pl *pool.Pool) protocol.StartFunc) {
	suite := NewMPCTestSuite(t, protocolType, partyCount, threshold).
		WithTimeout(5 * time.Second)
	defer suite.Cleanup()

	suite.RunInitTest(createStartFunc)
}
