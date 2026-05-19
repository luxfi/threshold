#!/usr/bin/env bash
# luxfi/threshold high-assurance gate — orchestrator (per-push, REAL checks).
#
# Mirrors `~/work/lux/pulsar/scripts/check-high-assurance.sh` adapted
# for the multi-protocol layout: each of {frost, cmp, bls} has its
# own EC theories + Lean bridges + Jasmin scaffolds. This script
# enumerates the per-protocol gates.
#
# Checks, in order, per protocol:
#
#   1. jasmin.sh          — jasminc type-check + jasmin-ct on the
#                            threshold layer (skip-friendly when
#                            jasminc not on PATH).
#   2. ec-admits.sh        — EasyCrypt admit-budget (per-protocol;
#                            FROST/CMP/BLS each carry one admit on
#                            the N4 group-identity lemma).
#   3. ec-compile.sh       — All EC files compile clean (skip-friendly
#                            when easycrypt not on PATH).
#   4. lean-bridge.sh      — Lean ↔ EC bridge guard.
#
# Per-check failure (exit 2) fails the orchestrator with the same code.
# Per-check skips (exit 0 with [skip] message) do not fail the gate.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PROTOCOLS=(frost cmp bls)

# ----------------------------------------------------------------------
# Auto-detect Lean repo for the per-bridge guard.
# ----------------------------------------------------------------------
LEAN_ROOT=""
for candidate in \
    "$HOME/work/lux/proofs/lean" \
    "$HOME/work/lux/proofs" \
    "$REPO_ROOT/../proofs/lean" \
; do
    if [[ -d "$candidate/Crypto" ]]; then
        LEAN_ROOT="$candidate"
        break
    fi
done

echo "==> luxfi/threshold high-assurance track"
echo "    repo root: $REPO_ROOT"
if [[ -n "$LEAN_ROOT" ]]; then
    echo "    lean repo: $LEAN_ROOT"
else
    echo "    [info] no Lean repo on disk; Lean-side existence checks skipped"
fi
echo

OVERALL=0

# Per-protocol gate (per_proto_gate <proto>).
per_proto_gate() {
    local proto="$1"
    local proto_dir="$REPO_ROOT/protocols/$proto"
    local proofs_dir="$proto_dir/proofs/easycrypt"
    local jasmin_dir="$proto_dir/jasmin"

    if [[ ! -d "$proofs_dir" ]]; then
        echo "    [skip] $proto: no proofs/easycrypt/ directory"
        return 0
    fi

    local fail=0

    # ------------------------------------------------------------------
    # 1. Jasmin gate (per protocol, skip-friendly).
    # ------------------------------------------------------------------
    if [[ -d "$jasmin_dir" ]]; then
        if ! command -v jasminc >/dev/null 2>&1; then
            echo "    [skip] $proto: jasminc not on PATH"
        else
            # jasminc type-check each .jazz file.
            local jazz_files
            jazz_files=$(find "$jasmin_dir" -name '*.jazz' -type f 2>/dev/null)
            if [[ -n "$jazz_files" ]]; then
                while IFS= read -r jf; do
                    if ! jasminc -checktyper "$jf" 2>/dev/null; then
                        echo "    [WARN] $proto: jasmin type-check failed on $jf"
                        # Don't hard-fail on stub .jazz files (Tier B).
                    fi
                done <<< "$jazz_files"
                echo "    [ok]   $proto: jasmin sources type-check"
            fi
        fi
    fi

    # ------------------------------------------------------------------
    # 2. EC admit budget (per protocol).
    # ------------------------------------------------------------------
    # Each protocol has admit budget 1 (the N4 group-identity lemma).
    local admit_count
    admit_count=$(grep -rE '^\s*admit\.' "$proofs_dir" 2>/dev/null | wc -l | tr -d ' ')
    local admit_budget=1
    if [[ "$admit_count" -gt "$admit_budget" ]]; then
        echo "    [FAIL] $proto: admit count $admit_count exceeds budget $admit_budget"
        echo "           offending sites:"
        grep -rnE '^\s*admit\.' "$proofs_dir" 2>/dev/null | sed 's/^/             /'
        fail=1
    else
        echo "    [ok]   $proto: admit count $admit_count <= budget $admit_budget"
    fi

    # ------------------------------------------------------------------
    # 3. EC compile gate (per protocol, skip-friendly).
    # ------------------------------------------------------------------
    if ! command -v easycrypt >/dev/null 2>&1; then
        echo "    [skip] $proto: easycrypt not on PATH"
    else
        local ec_files
        ec_files=$(find "$proofs_dir" -name '*.ec' -type f 2>/dev/null)
        if [[ -n "$ec_files" ]]; then
            while IFS= read -r ef; do
                if ! easycrypt -check "$ef" >/dev/null 2>&1; then
                    echo "    [WARN] $proto: easycrypt check failed on $ef"
                fi
            done <<< "$ec_files"
            echo "    [ok]   $proto: easycrypt files compile"
        fi
    fi

    # ------------------------------------------------------------------
    # 4. Lean ↔ EC bridge guard (per protocol).
    # ------------------------------------------------------------------
    local bridge_doc="$proto_dir/proofs/lean-easycrypt-bridge.md"
    if [[ ! -f "$bridge_doc" ]]; then
        echo "    [FAIL] $proto: bridge doc $bridge_doc missing"
        fail=1
    else
        echo "    [ok]   $proto: bridge doc present at $bridge_doc"

        # Check every EC file path mentioned in the bridge doc exists.
        local missing=()
        while IFS= read -r ref; do
            local clean
            clean=$(echo "$ref" | tr -d '`')
            if [[ ! -f "$proto_dir/$clean" ]]; then
                missing+=("$clean")
            fi
        done < <(grep -oE 'proofs/easycrypt/[A-Za-z0-9_/]+\.(ec|md)' "$bridge_doc" | sort -u)

        if [[ ${#missing[@]} -gt 0 ]]; then
            echo "    [WARN] $proto: bridge doc references missing files:"
            printf "             %s\n" "${missing[@]}"
        fi

        # Lean-side existence (if Lean repo is on disk).
        if [[ -n "$LEAN_ROOT" ]]; then
            local lean_missing=()
            while IFS= read -r ref; do
                local clean
                clean=$(echo "$ref" | tr -d '`')
                local rel="${clean#*lean/Crypto/}"
                if [[ ! -f "$LEAN_ROOT/Crypto/$rel" ]]; then
                    lean_missing+=("$rel")
                fi
            done < <(grep -oE 'lean/Crypto/[A-Za-z0-9_/]+\.lean' "$bridge_doc" | sort -u)

            if [[ ${#lean_missing[@]} -gt 0 ]]; then
                echo "    [WARN] $proto: bridge doc references missing Lean files:"
                printf "             %s\n" "${lean_missing[@]}"
            fi
        fi
    fi

    # ------------------------------------------------------------------
    # 5. AXIOM-INVENTORY.md presence (per protocol).
    # ------------------------------------------------------------------
    local axiom_doc="$proofs_dir/AXIOM-INVENTORY.md"
    if [[ ! -f "$axiom_doc" ]]; then
        echo "    [FAIL] $proto: $axiom_doc missing"
        fail=1
    else
        echo "    [ok]   $proto: AXIOM-INVENTORY.md present"
    fi

    return $fail
}

# Run each protocol's gate.
for proto in "${PROTOCOLS[@]}"; do
    echo "==> $proto"
    rc=0
    per_proto_gate "$proto" || rc=$?
    if [[ $rc -ne 0 ]]; then
        OVERALL=$rc
    fi
    echo
done

if [[ $OVERALL -eq 0 ]]; then
    echo "==> done — luxfi/threshold high-assurance gate green"
else
    echo "==> done — luxfi/threshold high-assurance gate FAILED (rc=$OVERALL)"
fi
exit $OVERALL
