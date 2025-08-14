#!/bin/bash

echo "========================================="
echo "🧪 COMPREHENSIVE TEST SUITE"
echo "========================================="
echo

# Track results
TOTAL_PASS=0
TOTAL_FAIL=0
FAILED_TESTS=""

# Function to run tests and track results
run_test() {
    local pkg=$1
    local name=$2
    local timeout=${3:-30s}
    
    echo -n "Testing $name... "
    if go test "$pkg" -short -timeout "$timeout" > /dev/null 2>&1; then
        echo "✅ PASS"
        ((TOTAL_PASS++))
    else
        echo "❌ FAIL"
        ((TOTAL_FAIL++))
        FAILED_TESTS="$FAILED_TESTS\n  - $name ($pkg)"
    fi
}

echo "📦 Core Packages:"
run_test "./pkg/ecdsa" "ECDSA"
run_test "./pkg/hash" "Hash"
run_test "./pkg/math/arith" "Arithmetic"
run_test "./pkg/math/polynomial" "Polynomial"
run_test "./pkg/math/sample" "Sample"
run_test "./pkg/paillier" "Paillier"
run_test "./pkg/pedersen" "Pedersen"
run_test "./pkg/protocol" "Protocol"
run_test "./pkg/taproot" "Taproot"
echo

echo "📦 Zero Knowledge Proofs:"
run_test "./pkg/zk/affg" "ZK AFFG"
run_test "./pkg/zk/affp" "ZK AFFP"
run_test "./pkg/zk/dec" "ZK DEC"
run_test "./pkg/zk/elog" "ZK ELOG"
run_test "./pkg/zk/enc" "ZK ENC"
run_test "./pkg/zk/encelg" "ZK ENCELG"
run_test "./pkg/zk/fac" "ZK FAC"
run_test "./pkg/zk/log" "ZK LOG"
run_test "./pkg/zk/logstar" "ZK LOGSTAR"
run_test "./pkg/zk/mod" "ZK MOD"
run_test "./pkg/zk/mul" "ZK MUL"
run_test "./pkg/zk/mulstar" "ZK MULSTAR"
run_test "./pkg/zk/nth" "ZK NTH"
run_test "./pkg/zk/prm" "ZK PRM"
run_test "./pkg/zk/sch" "ZK SCH"
echo

echo "📦 Internal Packages:"
run_test "./internal/mta" "MTA"
run_test "./internal/ot" "OT"
run_test "./internal/round" "Round"
echo

echo "📦 Protocol Components:"
run_test "./protocols/bls" "BLS"
run_test "./protocols/doerner" "Doerner"
run_test "./protocols/ringtail" "Ringtail"
echo

echo "📦 Protocol Submodules:"
run_test "./protocols/cmp/sign" "CMP Sign"
run_test "./protocols/frost/keygen" "FROST Keygen"
run_test "./protocols/frost/sign" "FROST Sign"
run_test "./protocols/lss/config" "LSS Config"
run_test "./protocols/lss/dealer" "LSS Dealer"
run_test "./protocols/lss/jvss" "LSS JVSS"
run_test "./protocols/lss/keygen" "LSS Keygen"
run_test "./protocols/lss/reshare" "LSS Reshare"
run_test "./protocols/lss/sign" "LSS Sign"
echo

echo "📦 Fast Unit Tests:"
echo -n "  CMP Fast Test: "
if go test ./protocols/cmp -run TestCMPFast -timeout 5s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  FROST Protocol Creation: "
if go test ./protocols/frost -run TestFROSTProtocolCreation -timeout 5s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  LSS Fast Tests: "
if go test ./protocols/lss -run TestLSSFast -timeout 5s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  CMP Keygen Fast: "
if go test ./protocols/cmp/keygen -run TestCMPKeygenFast -timeout 5s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi
echo

echo "📦 Threshold Performance Tests:"
echo -n "  CMP Threshold Performance: "
if go test ./protocols/cmp -run TestCMPThresholdPerformance -timeout 10s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  FROST Threshold Performance: "
if go test ./protocols/frost -run TestFROSTThresholdPerformance -timeout 10s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  LSS Threshold Performance: "
if go test ./protocols/lss -run TestLSSThresholdPerformance -timeout 10s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi
echo

echo "📦 Integration Tests:"
echo -n "  Simple Integration: "
if go test ./protocols/integration -run TestSimpleIntegration -timeout 10s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  Protocol Compatibility: "
if go test ./protocols/integration -run TestProtocolCompatibility -timeout 10s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi

echo -n "  Quick Integration: "
if go test ./protocols/integration -run TestQuickIntegration -timeout 10s > /dev/null 2>&1; then
    echo "✅ PASS"
    ((TOTAL_PASS++))
else
    echo "❌ FAIL"
    ((TOTAL_FAIL++))
fi
echo

echo "========================================="
echo "📊 TEST RESULTS SUMMARY"
echo "========================================="
echo
echo "✅ Tests Passing: $TOTAL_PASS"
echo "❌ Tests Failing: $TOTAL_FAIL"

if [ $TOTAL_FAIL -gt 0 ]; then
    echo
    echo "Failed tests:"
    echo -e "$FAILED_TESTS"
fi

echo
echo "========================================="

PERCENTAGE=$((TOTAL_PASS * 100 / (TOTAL_PASS + TOTAL_FAIL)))
echo "📈 Pass Rate: ${PERCENTAGE}%"

if [ $PERCENTAGE -eq 100 ]; then
    echo "🎉 100% TEST PASS RATE ACHIEVED!"
else
    echo "⚠️  Some tests are failing. Pass rate: ${PERCENTAGE}%"
fi

echo "========================================="

# Return success if all tests pass
[ $TOTAL_FAIL -eq 0 ]