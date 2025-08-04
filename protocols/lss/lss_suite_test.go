package lss_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestLSS(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "LSS MPC ECDSA Suite")
}