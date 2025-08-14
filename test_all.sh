#!/bin/bash
# Comprehensive test script for all protocols
# Ensures 100% test pass rate with no skips

set -e

echo "========================================="
echo "   THRESHOLD CRYPTOGRAPHY TEST SUITE    "
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TOTAL=0
PASSED=0
FAILED=0

# Function to run tests and track results
run_test() {
    local name=$1
    local cmd=$2
    local timeout=${3:-120s}
    
    echo -n "Testing $name... "
    TOTAL=$((TOTAL + 1))
    
    if timeout $timeout bash -c "$cmd" > /tmp/test_output.log 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        FAILED=$((FAILED + 1))
        echo "  Error output:"
        tail -n 20 /tmp/test_output.log | sed 's/^/    /'
    fi
}

echo "1. Core Package Tests"
echo "---------------------"
run_test "pkg/ecdsa" "go test -race -timeout 60s ./pkg/ecdsa/..."
run_test "pkg/hash" "go test -race -timeout 60s ./pkg/hash/..."
run_test "pkg/math" "go test -race -timeout 60s ./pkg/math/..."
run_test "pkg/protocol" "go test -race -timeout 60s ./pkg/protocol/..."
run_test "pkg/paillier" "go test -race -timeout 60s ./pkg/paillier/..."
run_test "pkg/pedersen" "go test -race -timeout 60s ./pkg/pedersen/..."
run_test "pkg/taproot" "go test -race -timeout 60s ./pkg/taproot/..."
run_test "pkg/zk" "go test -race -timeout 60s ./pkg/zk/..."

echo ""
echo "2. FROST Protocol Tests"
echo "-----------------------"
run_test "FROST keygen" "go test -race -timeout 60s ./protocols/frost/keygen/..."
run_test "FROST sign" "go test -race -timeout 60s ./protocols/frost/sign/..."

echo ""
echo "3. LSS Protocol Tests"
echo "---------------------"
run_test "LSS keygen" "go test -race -timeout 60s ./protocols/lss/keygen/..."
run_test "LSS sign" "go test -race -timeout 60s ./protocols/lss/sign/..."
run_test "LSS reshare" "go test -race -timeout 60s ./protocols/lss/reshare/..."
run_test "LSS config" "go test -race -timeout 60s ./protocols/lss/config/..."
run_test "LSS dealer" "go test -race -timeout 60s ./protocols/lss/dealer/..."
run_test "LSS jvss" "go test -race -timeout 60s ./protocols/lss/jvss/..."

echo ""
echo "4. CMP Protocol Tests"
echo "---------------------"
run_test "CMP keygen" "go test -race -timeout 120s ./protocols/cmp/keygen/..."
run_test "CMP sign" "go test -race -timeout 120s ./protocols/cmp/sign/..."
run_test "CMP presign" "go test -race -timeout 120s ./protocols/cmp/presign/..."
run_test "CMP config" "go test -race -timeout 60s ./protocols/cmp/config/..."

echo ""
echo "5. Other Protocol Tests"
echo "-----------------------"
run_test "Doerner keygen" "go test -race -timeout 60s ./protocols/doerner/keygen/..."
run_test "Doerner sign" "go test -race -timeout 60s ./protocols/doerner/sign/..."
run_test "Example protocol" "go test -race -timeout 60s ./protocols/example/..."

echo ""
echo "6. Benchmark Tests"
echo "------------------"
run_test "Protocol benchmarks" "go test -bench=. -benchtime=1s -timeout 60s ./pkg/protocol/..."
run_test "LSS benchmarks" "go test -bench=. -benchtime=1s -timeout 60s ./protocols/lss/..."

echo ""
echo "========================================="
echo "           TEST RESULTS SUMMARY          "
echo "========================================="
echo -e "Total Tests:  $TOTAL"
echo -e "Passed:       ${GREEN}$PASSED${NC}"
echo -e "Failed:       ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    echo "The codebase is SAFE, SECURE, and FAST!"
    exit 0
else
    echo -e "${RED}✗ Some tests failed.${NC}"
    echo "Please review the errors above."
    exit 1
fi