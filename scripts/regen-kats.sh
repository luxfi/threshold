#!/usr/bin/env bash
# regen-kats.sh — runs the LSS-Pulsar and LSS-Lens adapter test suites
# under deterministic conditions and writes a sha256 manifest of the
# coverage-relevant test outputs.
#
# Threshold/LSS produces no JSON KAT vectors of its own (the wire-level
# vectors live in pulsar/, lens/, warp/). What this script verifies:
#
#   1. Both adapters' lineage / set-rotation / signing / pairwise /
#      rollback / activation-transcript tests pass (deterministic).
#   2. The deterministic KAT-style regen for corona vectors that
#      lss_pulsar_test.go pulls in via pulsarThreshold also passes.
#
# Output:
#   scripts/kat/lss_pulsar.testlog
#   scripts/kat/lss_lens.testlog
#
# These logs are NOT raw test output — they are deterministic
# fingerprints (test names + pass/fail count) so the manifest stays
# byte-stable across runs.

set -euo pipefail

THRESHOLD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KAT_DIR="${THRESHOLD_DIR}/scripts/kat"
MANIFEST="${THRESHOLD_DIR}/scripts/regen-kats.manifest.sha256"

VERIFY=0
if [[ "${1:-}" == "--verify" ]]; then
  VERIFY=1
fi

cd "${THRESHOLD_DIR}"
mkdir -p "${KAT_DIR}"

# Run a focused test suite and fingerprint it. We capture only the
# names of passing tests + the count, so the manifest is byte-stable
# regardless of timing or ordering reported by `go test -v`.
fingerprint() {
  local label="$1"
  shift
  local pattern="$1"
  shift
  local out="${KAT_DIR}/${label}.testlog"
  local raw
  raw="$(go test -count=1 -v -run "${pattern}" ./protocols/lss 2>&1)"
  # Pass/fail summary lines start with "--- PASS:" or "--- FAIL:".
  # Strip the timing (parenthesised seconds) so the fingerprint is
  # stable across machines, and sort + uniq for order stability.
  printf '%s\n' "${raw}" \
    | grep -E '^--- (PASS|FAIL):' \
    | sed -E 's/[[:space:]]*\([0-9.]+s\)[[:space:]]*$//' \
    | sort -u > "${out}"
  if grep -q '^--- FAIL:' "${out}"; then
    echo "FAIL: ${label} has failing tests:" >&2
    grep '^--- FAIL:' "${out}" >&2
    return 1
  fi
  local n
  n="$(grep -c '^--- PASS:' "${out}" || true)"
  echo "  ${label}: ${n} passing tests"
}

echo "[1/2] LSS-Pulsar adapter test suite"
fingerprint "lss_pulsar" "TestPulsarAdapter_"

echo "[2/2] LSS-Lens adapter test suite"
fingerprint "lss_lens" "TestLensAdapter_"

# Build sha256 manifest deterministically.
TMP_MANIFEST="$(mktemp)"
trap 'rm -f "${TMP_MANIFEST}"' EXIT

find "${KAT_DIR}" -maxdepth 1 -name "*.testlog" -type f | sort | while read -r f; do
  rel="${f#${THRESHOLD_DIR}/}"
  shasum -a 256 "$f" | awk -v p="${rel}" '{print $1"  "p}'
done > "${TMP_MANIFEST}"

if [[ "${VERIFY}" == "1" ]]; then
  if [[ ! -f "${MANIFEST}" ]]; then
    echo "ERROR: --verify requested but no prior manifest at ${MANIFEST}"
    exit 2
  fi
  if ! diff -u "${MANIFEST}" "${TMP_MANIFEST}"; then
    echo "FAIL: manifest mismatch — Threshold KAT regeneration is non-deterministic" >&2
    exit 3
  fi
  echo "OK: Threshold KAT regeneration is byte-equal across runs ($(wc -l < "${MANIFEST}") files)"
else
  cp "${TMP_MANIFEST}" "${MANIFEST}"
  echo "wrote manifest: ${MANIFEST}"
  cat "${MANIFEST}"
fi
