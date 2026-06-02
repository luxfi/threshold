package frost_test

import (
	"context"
	"testing"

	log "github.com/luxfi/log"
	"github.com/luxfi/metric"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestFrost(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "FROST Protocol Suite")
}

var (
	ctx      context.Context
	logger   log.Logger
	registry metric.Registerer
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
	registry = metric.NewRegistry()
})
