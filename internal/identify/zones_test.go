package identify

import (
	"strings"
	"testing"
)

func mustPolicy(t *testing.T, text string) *Policy {
	t.Helper()
	p, err := ParsePolicy(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	return p
}

const samplePolicy = `
# the segments this network is supposed to have
zone office 10.0.1.0/24 10.0.2.0/24
zone card   10.0.5.0/24
zone mgmt   10.0.1.240/28
zone ot     10.0.20.0/24

allow office -> mgmt
allow card <-> mgmt
`

// The management range sits inside the office range. Whichever is more specific
// has to win, or a policy cannot carve a subnet out without describing the
// larger zone as a list of holes.
func TestMostSpecificZoneWins(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	for _, tc := range []struct{ ip, want string }{
		{"10.0.1.10", "office"},
		{"10.0.1.245", "mgmt"},
		{"10.0.5.9", "card"},
		{"10.0.20.9", "ot"},
		{"10.0.99.1", ""}, // declared nowhere
		{"not an ip", ""},
	} {
		if got := p.ZoneOf(tc.ip); got != tc.want {
			t.Errorf("ZoneOf(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestPermits(t *testing.T) {
	p := mustPolicy(t, samplePolicy)
	for _, tc := range []struct {
		src, dst string
		want     bool
		why      string
	}{
		{"10.0.1.10", "10.0.1.11", true, "same zone is always fine"},
		{"10.0.1.10", "10.0.1.245", true, "office -> mgmt is allowed"},
		{"10.0.1.245", "10.0.1.10", false, "the reverse was never allowed"},
		{"10.0.5.9", "10.0.1.245", true, "card <-> mgmt allows both ways"},
		{"10.0.1.245", "10.0.5.9", true, "and the other way"},
		{"10.0.5.9", "10.0.1.10", false, "card -> office is the breach we exist to find"},
		{"10.0.20.9", "10.0.1.10", false, "ot -> office is not allowed"},
		{"10.0.99.1", "10.0.5.9", true, "an address in no zone says nothing"},
		{"10.0.5.9", "10.0.99.1", true, "and neither does the other end"},
	} {
		if got, _, _ := p.Permits(tc.src, tc.dst); got != tc.want {
			t.Errorf("Permits(%s, %s) = %v, want %v — %s", tc.src, tc.dst, got, tc.want, tc.why)
		}
	}
}

// A typo in a policy file fails open: the rule never matches and the crossing it
// was meant to permit is reported forever. Better to refuse to load.
func TestRejectsPolicyMistakes(t *testing.T) {
	for _, tc := range []struct{ name, text string }{
		{"unknown zone in allow", "zone a 10.0.0.0/24\nallow a -> typo\n"},
		{"no zones at all", "# nothing here\n"},
		{"bad cidr", "zone a 10.0.0.0\n"},
		{"missing arrow", "zone a 10.0.0.0/24\nzone b 10.0.1.0/24\nallow a b\n"},
		{"unknown directive", "zone a 10.0.0.0/24\ndeny a -> b\n"},
	} {
		if _, err := ParsePolicy(strings.NewReader(tc.text)); err == nil {
			t.Errorf("%s: accepted a policy it should have refused", tc.name)
		}
	}
}

// The headline claim: a flow across a boundary the policy forbids becomes a
// finding, and one that is permitted does not.
func TestSegmentationFindings(t *testing.T) {
	r := NewResolver()
	r.SetPolicy(mustPolicy(t, samplePolicy))

	feed(t, r,
		// Card data reaching the office network. This is the finding.
		`{"timestamp":"2026-07-28T09:00:00.000000+0000","event_type":"flow","src_ip":"10.0.5.9",`+
			`"dest_ip":"10.0.1.10","dest_port":445,"proto":"TCP"}`,
		// Office to management, which the policy allows.
		`{"timestamp":"2026-07-28T09:01:00.000000+0000","event_type":"flow","src_ip":"10.0.1.10",`+
			`"dest_ip":"10.0.1.245","dest_port":22,"proto":"TCP"}`,
		// Inside one zone.
		`{"timestamp":"2026-07-28T09:02:00.000000+0000","event_type":"flow","src_ip":"10.0.1.10",`+
			`"dest_ip":"10.0.1.11","dest_port":445,"proto":"TCP"}`,
		// An address the policy never mentions.
		`{"timestamp":"2026-07-28T09:03:00.000000+0000","event_type":"flow","src_ip":"10.0.99.1",`+
			`"dest_ip":"10.0.5.9","dest_port":443,"proto":"TCP"}`,
	)

	var crossings []Finding
	for _, f := range r.Findings() {
		if strings.HasPrefix(f.Kind, "segmentation-") {
			crossings = append(crossings, f)
		}
	}
	if len(crossings) != 1 {
		t.Fatalf("got %d segmentation findings, want exactly 1: %+v", len(crossings), crossings)
	}
	if crossings[0].Device != "10.0.5.9" {
		t.Errorf("reported against %s, want the source 10.0.5.9", crossings[0].Device)
	}
	if !strings.Contains(crossings[0].Title, "card") || !strings.Contains(crossings[0].Title, "office") {
		t.Errorf("title does not name both zones: %q", crossings[0].Title)
	}
}

// One chatty host must not file the same breach a thousand times.
func TestOneFindingPerBoundary(t *testing.T) {
	r := NewResolver()
	r.SetPolicy(mustPolicy(t, samplePolicy))

	for _, port := range []string{"445", "3389", "22", "80"} {
		feed(t, r, `{"timestamp":"2026-07-28T09:00:00.000000+0000","event_type":"flow",`+
			`"src_ip":"10.0.5.9","dest_ip":"10.0.1.10","dest_port":`+port+`,"proto":"TCP"}`)
	}

	n := 0
	for _, f := range r.Findings() {
		if strings.HasPrefix(f.Kind, "segmentation-") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d findings for one boundary, want 1", n)
	}
}

// Without a policy the feature costs nothing and says nothing.
func TestNoPolicyNoFindings(t *testing.T) {
	r := NewResolver()
	feed(t, r, `{"timestamp":"2026-07-28T09:00:00.000000+0000","event_type":"flow",`+
		`"src_ip":"10.0.5.9","dest_ip":"10.0.1.10","dest_port":445,"proto":"TCP"}`)

	for _, f := range r.Findings() {
		if strings.HasPrefix(f.Kind, "segmentation-") {
			t.Fatal("reported a segmentation finding with no policy loaded")
		}
	}
}
