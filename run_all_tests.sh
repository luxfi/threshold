#!/bin/bash

# Test runner script to verify all tests pass
set -e

echo "========================================="
echo "Running Threshold Protocol Test Suite"
echo "========================================="
echo

# Track results
PASSED=0
FAILED=0

# Function to run tests and count results
run_test_group() {
    local name=$1
    local cmd=$2
    echo "Testing: $name"
    if eval "$cmd" > /dev/null 2>&1; then
        echo "✅ PASSED: $name"
        ((PASSED++))
    else
        echo "❌ FAILED: $name"
        ((FAILED++))
    fi
    echo
}

# Core package tests
run_test_group "Core Packages" "go test ./pkg/... -short -timeout 30s"

# Internal packages
run_test_group "Internal Packages" "go test ./internal/... -short -timeout 30s"

# Simple protocol tests
run_test_group "BLS Protocol" "go test ./protocols/bls -short -timeout 30s"
run_test_group "Doerner Protocol" "go test ./protocols/doerner -short -timeout 30s"
run_test_group "Ringtail Protocol" "go test ./protocols/ringtail -short -timeout 30s"

# Fast unit tests
run_test_group "FROST Fast Test" "go test ./protocols/frost -run TestFROSTProtocolCreation -timeout 10s"
run_test_group "LSS Fast Tests" "go test ./protocols/lss -run TestLSSFast -timeout 10s"
run_test_group "CMP Fast Test" "go test ./protocols/cmp -run TestCMPFast -timeout 10s"

# Protocol subpackages
run_test_group "FROST Keygen" "go test ./protocols/frost/keygen -short -timeout 30s"
run_test_group "FROST Sign" "go test ./protocols/frost/sign -short -timeout 30s"
run_test_group "LSS Config" "go test ./protocols/lss/config -short -timeout 30s"
run_test_group "LSS Dealer" "go test ./protocols/lss/dealer -short -timeout 30s"
run_test_group "LSS JVSS" "go test ./protocols/lss/jvss -short -timeout 30s"
run_test_group "LSS Keygen" "go test ./protocols/lss/keygen -short -timeout 30s"
run_test_group "LSS Sign" "go test ./protocols/lss/sign -short -timeout 30s"
run_test_group "LSS Reshare" "go test ./protocols/lss/reshare -short -timeout 30s"
run_test_group "CMP Sign" "go test ./protocols/cmp/sign -short -timeout 30s"

# Integration test
run_test_group "Integration Tests" "go test ./protocols/integration -short -timeout 30s"

echo "========================================="
echo "Test Results Summary"
echo "========================================="
echo "✅ PASSED: $PASSED"
echo "❌ FAILED: $FAILED"
echo

if [ $FAILED -eq 0 ]; then
    echo "🎉 All tests passed successfully!"
    exit 0
else
    echo "⚠️  Some tests failed. Please review the output above."
    exit 1
fi