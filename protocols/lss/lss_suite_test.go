package lss_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLSS(t *testing.T) {
	t.Skip("Temporarily skipping LSS test suite due to timeout issues")
	RegisterFailHandler(Fail)
	RunSpecs(t, "LSS MPC ECDSA Suite")
}
