package identify

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"tarsier/internal/eve"
)

// summarise renders everything a report or a diff would show, so the comparison
// below fails on any drift rather than only on the fields a test remembered to
// check.
func summarise(t *testing.T, r *Resolver) string {
	t.Helper()
	var b strings.Builder
	for _, d := range r.Devices() {
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s|%s|%s|%.4f|%v|%v|%v|%v|%d|%d|%v|%v\n",
			d.IP, d.MAC, d.Class, d.OS, d.Vendor, d.Model, d.Firmware,
			d.Confidence(), d.SortedHostnames(), d.SortedUsers(),
			d.SortedProtocols(), d.SortedVLANs(), d.Alerts, len(d.Evidence),
			// Normalised to UTC: a JSON round-trip keeps the instant but not the
			// Location object, and comparing zone names would fail the test over
			// a difference nothing can observe.
			d.FirstSeen.UTC().Format(time.RFC3339Nano),
			d.LastSeen.UTC().Format(time.RFC3339Nano))
		for _, e := range d.Evidence {
			fmt.Fprintf(&b, "  ev %s|%s|%s|%.4f\n", e.Signal, e.Value, e.Conclusion, e.Weight)
		}
	}
	for _, f := range r.Findings() {
		fmt.Fprintf(&b, "finding %s|%s|%s\n", f.Severity, f.Kind, f.Device)
	}
	counts := r.EventCounts()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys) // map order is random; the comparison must not be
	for _, k := range keys {
		fmt.Fprintf(&b, "count %s=%d\n", k, counts[k])
	}
	return b.String()
}

func loadDemo(t *testing.T, r *Resolver) {
	t.Helper()
	f, err := os.Open("../../testdata/demo-week.json")
	if err != nil {
		t.Skipf("sample data not available: %v", err)
	}
	defer f.Close()
	rd := eve.NewReader(f)
	for rec := rd.Next(); rec != nil; rec = rd.Next() {
		r.Add(rec)
	}
}

// A restored model has to be indistinguishable from the one that was saved.
// Anything less drifts quietly: the report still renders, the numbers are just
// wrong, and nobody finds out.
func TestStateRoundTrip(t *testing.T) {
	original := NewResolver()
	loadDemo(t, original)

	var buf bytes.Buffer
	if err := original.Save(&buf, Position{Source: "eve.json", Offset: 4096, Sig: "abc"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	restored := NewResolver()
	pos, err := restored.Load(&buf)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if pos.Source != "eve.json" || pos.Offset != 4096 || pos.Sig != "abc" {
		t.Errorf("position = %+v, want the one that was saved", pos)
	}

	want, got := summarise(t, original), summarise(t, restored)
	if want != got {
		// Show the first line that differs rather than two walls of text.
		wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
		for i := range wl {
			if i >= len(gl) || wl[i] != gl[i] {
				t.Fatalf("restored model differs at line %d:\n saved:    %s\n restored: %s", i, wl[i], gl[i])
			}
		}
		t.Fatalf("restored model differs in length: %d vs %d lines", len(wl), len(gl))
	}
}

// Continuing to add events after a restore must behave as though the restart
// never happened. This is the property that makes persistence worth having:
// evidence already counted must not be counted again and inflate confidence.
func TestRestoredModelKeepsAccumulating(t *testing.T) {
	const dhcp = `{"timestamp":"2026-07-28T09:00:00.000000+0000","event_type":"dhcp","src_ip":"10.0.1.20",` +
		`"dest_ip":"10.0.0.1","dhcp":{"assigned_ip":"10.0.1.20","client_mac":"00:1b:21:aa:bb:cc",` +
		`"hostname":"ACCTS-PC","dhcp_type":"ack"}}`

	// One resolver that sees the record twice, without a restart in between.
	straight := NewResolver()
	feed(t, straight, dhcp, dhcp)

	// Another that sees it, is saved and restored, then sees it again.
	first := NewResolver()
	feed(t, first, dhcp)
	var buf bytes.Buffer
	if err := first.Save(&buf, Position{}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	second := NewResolver()
	if _, err := second.Load(&buf); err != nil {
		t.Fatalf("Load: %v", err)
	}
	feed(t, second, dhcp)

	a, b := summarise(t, straight), summarise(t, second)
	if a != b {
		t.Errorf("a restart changed the outcome:\n without restart:\n%s\n with restart:\n%s", a, b)
	}
}

// State written by a different model is refused rather than half-understood.
// Rebuilding from the logs on disk is a known-good fallback; a silently wrong
// inventory is not.
func TestRejectsForeignState(t *testing.T) {
	for _, text := range []string{
		`{"version":99,"devices":[]}`,
		`not json at all`,
	} {
		r := NewResolver()
		if _, err := r.Load(strings.NewReader(text)); err == nil {
			t.Errorf("accepted state it should have refused: %s", text)
		}
	}
}

// TestIdentificationIsDeterministic pins the bug that persistence exposed.
//
// resolve() used to range over a map and break ties with a bare >, so two
// conclusions of exactly equal weight were separated by Go's randomised map
// order. The same capture could come back as a server one run and a workstation
// the next. In a single report that is invisible; underneath it poisons
// everything — a diff between two identical scans announces a change that never
// happened, and a watcher wakes somebody up to tell them about it.
func TestIdentificationIsDeterministic(t *testing.T) {
	var first string
	for i := 0; i < 12; i++ {
		r := NewResolver()
		loadDemo(t, r)
		got := summarise(t, r)
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			fl, gl := strings.Split(first, "\n"), strings.Split(got, "\n")
			for j := range fl {
				if j >= len(gl) || fl[j] != gl[j] {
					t.Fatalf("run %d identified the same capture differently:\n first: %s\n now:   %s",
						i, fl[j], gl[j])
				}
			}
			t.Fatalf("run %d differed in length", i)
		}
	}
}
