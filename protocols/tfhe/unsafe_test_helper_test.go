// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause

package tfhe

import (
	"os"
	"testing"
)

// TestMain opts the existing fake-threshold tests into the UNSAFE
// implementation by setting ALLOW_FAKE_TFHE_FOR_TESTING_ONLY=1 for
// the duration of the test binary. Production paths are guarded by
// guardUnsafe() and panic when this env var is unset.
//
// The fake-threshold implementation is documented in tfhe.go and
// lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md. These tests verify the
// orchestration shape only — they do NOT verify any threshold security
// property because the underlying scheme has none.
func TestMain(m *testing.M) {
	if err := os.Setenv(unsafeTFHEEnvVar, "1"); err != nil {
		panic("tfhe test setup: cannot set " + unsafeTFHEEnvVar + ": " + err.Error())
	}
	os.Exit(m.Run())
}
