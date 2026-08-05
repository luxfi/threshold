#!/usr/bin/env bash
# Mutation harness: for each security claim, remove the code that defends it and
# require the claim's test to go RED. A suite that stays green under mutation is
# decoration. Every mutation is reverted with git checkout before the next runs.
set -uo pipefail
cd "$(dirname "$0")/../.."
K=protocols/tkem/tkem.go
R=protocols/frost/keygen/round1.go
pass=0; fail=0

mutate() { # <name> <test> <file> <python-edit>
  local name=$1 test=$2 file=$3 edit=$4
  cp "$file" "$file.orig"
  python3 - "$file" <<PY
import sys
p = sys.argv[1]; s = open(p).read()
$edit
open(p, 'w').write(s)
PY
  if ! GOWORK=off go build ./protocols/tkem/ >/dev/null 2>&1; then
    echo "  BUILD-BROKEN  $name"; cp "$file.orig" "$file"; fail=$((fail+1)); return
  fi
  if GOWORK=off go test ./protocols/tkem/ -count=1 -run "$test" >/dev/null 2>&1; then
    echo "  SURVIVED      $name  ($test still passes — the test does not defend this)"
    fail=$((fail+1))
  else
    echo "  KILLED        $name  -> $test went red"
    pass=$((pass+1))
  fi
  cp "$file.orig" "$file"
}

echo "=== mutation testing protocols/tkem ==="

mutate "Combine: drop the partial-decapsulation proof check" \
  TestClaim3_ForgedPartial "$K" \
  's = s.replace("""		if !p.Verify(ct, V) {
			return nil, ErrBadPartial{Culprit: p.ID}
		}
""", "").replace("V, ok := g.VerificationShares[p.ID]", "_, ok := g.VerificationShares[p.ID]")'

mutate "PartialDecapsulate: drop the ciphertext well-formedness check" \
  TestClaim7_MalleatedCiphertextRefused "$K" \
  's = s.replace("""	if err := ct.Verify(); err != nil {
		return nil, err
	}
	k, err := randScalar(rand)""", """	k, err := randScalar(rand)""")'

mutate "deriveKey: drop the label from the KDF" \
  TestClaim5_LabelBinding "$K" \
  's = s.replace("info := append([]byte(domainKey), lengthPrefixed(label)...)", "info := []byte(domainKey)")'

mutate "deriveKey: drop R from the key material" \
  TestClaim5_CiphertextBinding "$K" \
  's = s.replace("ikm := append(enc(R), enc(S)...)", "ikm := enc(S)")'

mutate "Combine: replace Lagrange coefficients with 1" \
  TestClaim1_QuorumAgreement "$K" \
  's = s.replace("lambda := polynomial.Lagrange(group, ids)", "_ = polynomial.Lagrange(group, ids)").replace("S = S.Add(lambda[p.ID].Act(p.D))", "S = S.Add(p.D)")'

mutate "Ciphertext.Verify: drop the label from the challenge" \
  TestClaim5_LabelBinding "$K" \
  's = s.replace("""	if !challenge(domainWellFormed, c.Label, enc(c.R), enc(c.RBar), enc(W), enc(wBar)).Equal(c.E) {""", """	if !challenge(domainWellFormed, nil, enc(c.R), enc(c.RBar), enc(W), enc(wBar)).Equal(c.E) {""")'

mutate "Combine: drop the duplicate-party check" \
  TestCombineRejectsDuplicateAndUnknownParties "$K" \
  's = s.replace("""		if _, dup := seen[p.ID]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateParty, p.ID)
		}
""", "")'

mutate "generatorH: use the base point (known discrete log)" \
  TestGeneratorHIsNotABaseMultipleAnyoneKnows "$K" \
  's = s.replace("""	d := sha512.Sum512([]byte(domainGenerator))
	p := group.NewPoint().(*curve.Ristretto255Point)
	return p.FromUniformBytes(d[:])""", """	_ = sha512.Sum512([]byte(domainGenerator))
	return group.NewBasePoint()""")'

mutate "FromKeygen: forget the degree-to-parties conversion" \
  TestClaim1_QuorumAgreement "$K" \
  's = s.replace("g := Group{Threshold: cfg.Threshold + 1,", "g := Group{Threshold: cfg.Threshold,")'

mutate "reintroduce assembly: export a function returning the private scalar" \
  TestClaim4_NoReconstructionInSource "$K" \
  's += """

// Reconstruct is the mutation Claim 4 forbids.
func Reconstruct(shares []Share) curve.Scalar { return shares[0].Secret }
"""'

mutate "frost refresh: contribute a fresh secret instead of zero" \
  TestRefreshPreservesGroupPublicKey "$R" \
  's = s.replace("""	if !r.refresh {
		aI0 = sample.Scalar(rand.Reader, r.Group())
		aI0TimesG = aI0.ActOnBase()
	}""", """	aI0 = sample.Scalar(rand.Reader, r.Group())
	aI0TimesG = aI0.ActOnBase()""")'

echo
rm -f "$K.orig" "$R.orig"
echo "killed=$pass survived/broken=$fail"
[ "$fail" -eq 0 ]
