package frost_test

import (
	"context"
	"testing"

	log "github.com/luxfi/log"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
)

func TestFrost(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "FROST Protocol Suite")
}

var (
	ctx      context.Context
	logger   log.Logger
	registry prometheus.Registerer
)

var _ = BeforeSuite(func() {
	ctx = context.Background()
	logger = log.NewTestLogger(log.InfoLevel)
	DeferCleanup(func() {
		// Cleanup after all tests
	})
})

var _ = BeforeEach(func() {
	// Create a new registry for each test to avoid conflicts
	registry = prometheus.NewRegistry()
})
