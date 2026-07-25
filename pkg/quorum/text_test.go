package quorum_test

import (
	"encoding/json"
	"testing"

	"github.com/luxfi/threshold/pkg/quorum"
)

// A Policy in a config file must round-trip through the operator form. This is
// the property that lets genesis and node config state a quorum in a way that
// cannot be misread as a polynomial degree.
func TestPolicyJSONRoundTrip(t *testing.T) {
	type cfg struct {
		Policy quorum.Policy `json:"policy"`
	}

	in := cfg{Policy: quorum.MustNew(3, 5)}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(b), `{"policy":"3-of-5"}`; got != want {
		t.Fatalf("marshal = %s, want %s", got, want)
	}

	var out cfg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Policy != in.Policy {
		t.Fatalf("round-trip = %s, want %s", out.Policy, in.Policy)
	}
	if out.Policy.Degree() != 2 {
		t.Fatalf("decoded 3-of-5 has degree %d, want 2", out.Policy.Degree())
	}
}

// An undeployable or unparseable policy must fail loudly at decode. A Policy
// that silently decoded to the zero value would reach cmp.Keygen as degree -1.
func TestPolicyUnmarshalRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		`{"policy":"6-of-5"}`, // unsatisfiable
		`{"policy":"1-of-5"}`, // not a threshold policy
		`{"policy":"3/5"}`,    // wrong separator
		`{"policy":""}`,       // empty
		`{"policy":"0-of-0"}`, // zero
	} {
		var out struct {
			Policy quorum.Policy `json:"policy"`
		}
		if err := json.Unmarshal([]byte(in), &out); err == nil {
			t.Errorf("Unmarshal(%s) succeeded as %s, want error", in, out.Policy)
		}
	}
}

// Encoding an invalid policy must fail rather than emit a string that would
// decode back to something different (or fail asymmetrically).
func TestPolicyMarshalRejectsInvalid(t *testing.T) {
	if _, err := (quorum.Policy{K: 0, N: 0}).MarshalText(); err == nil {
		t.Fatal("marshalling the zero policy succeeded, want error")
	}
	if _, err := (quorum.Policy{K: 9, N: 5}).MarshalText(); err == nil {
		t.Fatal("marshalling 9-of-5 succeeded, want error")
	}
}
