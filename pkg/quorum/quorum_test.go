package quorum_test

import (
	"testing"

	"github.com/luxfi/threshold/pkg/quorum"
)

// The whole point of this package is that "3-of-5" means three signers, and
// the protocol degree for it is 2. If this test ever fails, every k-of-n
// wallet provisioned through the stack is off by one.
func TestPolicyDegreeIsKMinusOne(t *testing.T) {
	for _, tc := range []struct {
		k, n          int
		wantDegree    int
		wantTolerance int
		wantString    string
	}{
		{2, 3, 1, 1, "2-of-3"},
		{3, 5, 2, 2, "3-of-5"},
		{4, 5, 3, 1, "4-of-5"},
		{4, 7, 3, 3, "4-of-7"},
		{5, 5, 4, 0, "5-of-5"},
	} {
		p := quorum.MustNew(tc.k, tc.n)
		if got := p.Degree(); got != tc.wantDegree {
			t.Errorf("%s: Degree() = %d, want %d", p, got, tc.wantDegree)
		}
		if got := p.Tolerance(); got != tc.wantTolerance {
			t.Errorf("%s: Tolerance() = %d, want %d", p, got, tc.wantTolerance)
		}
		if got := p.String(); got != tc.wantString {
			t.Errorf("String() = %q, want %q", got, tc.wantString)
		}
	}
}

// The 3-of-5 case specifically, spelled out, because it is the policy the
// treasury migration is designed around.
func TestPolicy3of5(t *testing.T) {
	p := quorum.MustNew(3, 5)
	if p.Degree() != 2 {
		t.Fatalf("3-of-5 degree = %d, want 2 (a degree-3 key would need 4 signers)", p.Degree())
	}
	if p.Tolerance() != 2 {
		t.Fatalf("3-of-5 tolerance = %d, want 2", p.Tolerance())
	}
}

func TestNewRejectsUndeployablePolicies(t *testing.T) {
	for _, tc := range []struct {
		name string
		k, n int
	}{
		{"k exceeds n", 6, 5},
		{"k=1 is not a threshold policy", 1, 5},
		{"k=0", 0, 5},
		{"negative k", -1, 5},
		{"n too small", 2, 1},
		{"zero policy", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := quorum.New(tc.k, tc.n); err == nil {
				t.Fatalf("New(%d, %d) succeeded, want error", tc.k, tc.n)
			}
			if (quorum.Policy{K: tc.k, N: tc.n}).Valid() {
				t.Fatalf("Policy{%d,%d}.Valid() = true, want false", tc.k, tc.n)
			}
		})
	}
}

// FromDegree is how an already-generated cmp/frost config reports its policy.
// It must round-trip with Degree so a stored key reads back as the policy it
// was created with.
func TestFromDegreeRoundTrips(t *testing.T) {
	for n := 2; n <= 9; n++ {
		for k := 2; k <= n; k++ {
			p := quorum.MustNew(k, n)
			back, err := quorum.FromDegree(p.Degree(), p.N)
			if err != nil {
				t.Fatalf("FromDegree(%d, %d): %v", p.Degree(), p.N, err)
			}
			if back != p {
				t.Fatalf("round-trip: got %s, want %s", back, p)
			}
		}
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    quorum.Policy
		wantErr bool
	}{
		{in: "3-of-5", want: quorum.MustNew(3, 5)},
		{in: " 3-of-5 ", want: quorum.MustNew(3, 5)},
		{in: "3 of 5", want: quorum.MustNew(3, 5)},
		{in: "3-OF-5", want: quorum.MustNew(3, 5)},
		{in: "2-of-3", want: quorum.MustNew(2, 3)},
		{in: "6-of-5", wantErr: true},
		{in: "1-of-5", wantErr: true},
		{in: "3/5", wantErr: true},
		{in: "three-of-five", wantErr: true},
		{in: "", wantErr: true},
	} {
		got, err := quorum.Parse(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %s, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// Parse and String are inverses, so a policy can survive a round trip through
// a config file or a dashboard string.
func TestParseStringRoundTrip(t *testing.T) {
	for n := 2; n <= 9; n++ {
		for k := 2; k <= n; k++ {
			p := quorum.MustNew(k, n)
			back, err := quorum.Parse(p.String())
			if err != nil {
				t.Fatalf("Parse(%q): %v", p.String(), err)
			}
			if back != p {
				t.Fatalf("round-trip: %s -> %q -> %s", p, p.String(), back)
			}
		}
	}
}
