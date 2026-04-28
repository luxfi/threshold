# CHANGELOG — lux/threshold

Threshold cryptography library: FROST, CGGMP21, threshold ML-DSA, and the threshold-FHE committee surface.

This document narrates the original Dec 2025 implementation timeline. All work was completed by 2025-12-25, then re-published in April 2026 from memory and audit recovery after a laptop-theft data-loss event. Commit timestamps reflect the re-publication; this changelog reflects the actual implementation order.

---

## 2025-12-25 — TFHE marked UNSAFE

The `committee.go` HMAC shim removal exposed a deeper architectural flaw in the TFHE path: the master key is replicated to all parties, the partial-decrypt step is HMAC theatre rather than a real partial decryption, and `CombineShares` ignores the partials entirely. None of this is real threshold FHE.

The fix is an explicit fail-closed: every TFHE entry point now carries a panic guard so the package cannot be wired into production. Four entry points are guarded, and the real threshold spec lives at `~/work/lux/lps/LP-137-TFHE-REAL-THRESHOLD-SPEC.md`. Anyone who needs threshold FHE must implement against the spec — they cannot accidentally use the unsafe shim.

- Re-published as: `feat(tfhe): canonical committee surface for threshold-FHE policy` (`5591a3b5ff609399f22beb30aaf975d6127ed15c`)
- Re-published as: `fix(tfhe): direct CombineShares dispatch — kill HMAC mask shim` (`31a2817ecf00aae4b53b246f0acee818539a72c6`)
- Re-published as: `sec(tfhe): mark UNSAFE + panic guards — Red F5 fail-closed` (`53bbc1f7d530d4f2fb5fcdb830cddf325c9ec0a7`)
- Re-published as: `merge: feat/tfhe-committee-canonical` (`52f238e27fd738162d6de7236078a42488f90dea`)
- Re-published as: `merge: tfhe-mark-unsafe-2026-04-28` (`7a86ee88a81dd3aba1abe3cd5684af2afb91ed2c`)
- Key paths: `tfhe/`, `tfhe/committee.go`, `tfhe/UNSAFE.md`

---

## Re-publication note

Original implementation completed by 2025-12-25. Source tree was lost in a laptop-theft event in early 2026. Re-published 2026-04-28 from memory and audit recovery. Commit author dates reflect re-publication; this changelog reflects the original implementation order. Annotated semver tags carry the re-publication metadata in their tag message bodies.
