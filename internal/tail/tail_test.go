package tail

import (
	"os"
	"path/filepath"
	"testing"
)

// collect polls once and returns the lines that came out.
func collect(t *testing.T, f *Follower) []string {
	t.Helper()
	var got []string
	if _, err := f.Poll(func(line []byte) {
		got = append(got, string(line))
	}); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	return got
}

func write(t *testing.T, path, s string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if _, err := fh.WriteString(s); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	fh.Close()
}

func TestFollowsAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	write(t, path, "one\ntwo\n")

	f := New(path)
	defer f.Close()

	if got := collect(t, f); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("first poll = %q, want [one two]", got)
	}
	// Nothing new: a second poll must not repeat what it already delivered.
	if got := collect(t, f); len(got) != 0 {
		t.Fatalf("second poll = %q, want nothing", got)
	}
	write(t, path, "three\n")
	if got := collect(t, f); len(got) != 1 || got[0] != "three" {
		t.Fatalf("after append = %q, want [three]", got)
	}
}

// A writer is routinely caught mid-line. Emitting that would hand the parser
// half a JSON object, so it has to wait for the newline.
func TestHoldsPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	write(t, path, `{"event_type":"dns"`)

	f := New(path)
	defer f.Close()

	if got := collect(t, f); len(got) != 0 {
		t.Fatalf("partial line was emitted: %q", got)
	}
	write(t, path, "}\n")
	got := collect(t, f)
	if len(got) != 1 || got[0] != `{"event_type":"dns"}` {
		t.Fatalf("after completion = %q, want the whole line once", got)
	}
}

// logrotate's default: the file we hold is renamed and a new one takes its
// place. The handle stays valid and usually still has unread bytes, so the old
// file has to be drained before the switch.
func TestRenameRotationLosesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	write(t, path, "before-1\n")

	f := New(path)
	defer f.Close()

	if got := collect(t, f); len(got) != 1 || got[0] != "before-1" {
		t.Fatalf("initial = %q", got)
	}

	// Written after our last poll but before the rename: these bytes exist only
	// in the rotated file, and a tailer watching the path alone drops them.
	write(t, path, "before-2\n")
	if err := os.Rename(path, filepath.Join(dir, "eve.json.1")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	write(t, path, "after-1\n")

	got := collect(t, f)
	want := []string{"before-2", "after-1"}
	if len(got) != len(want) {
		t.Fatalf("across rotation = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("across rotation = %q, want %q", got, want)
		}
	}
	if f.Rotations != 1 {
		t.Errorf("Rotations = %d, want 1", f.Rotations)
	}
}

// The other mechanism: same file, copied away and truncated in place. Identity
// never changes, so the only evidence is that the file shrank.
func TestCopyTruncateLosesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	write(t, path, "before-1\nbefore-2\n")

	f := New(path)
	defer f.Close()

	if got := collect(t, f); len(got) != 2 {
		t.Fatalf("initial = %q, want two lines", got)
	}

	if err := os.Truncate(path, 0); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	write(t, path, "after-1\n")

	got := collect(t, f)
	if len(got) != 1 || got[0] != "after-1" {
		t.Fatalf("after truncate = %q, want [after-1]", got)
	}
	if f.Truncations != 1 {
		t.Errorf("Truncations = %d, want 1", f.Truncations)
	}
}

// A sensor is often configured before Suricata has written anything. That is
// not an error, and the file has to be picked up when it turns up.
func TestWaitsForFileToAppear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")

	f := New(path)
	defer f.Close()

	if got := collect(t, f); len(got) != 0 {
		t.Fatalf("missing file produced %q", got)
	}
	write(t, path, "first\n")
	if got := collect(t, f); len(got) != 1 || got[0] != "first" {
		t.Fatalf("after creation = %q, want [first]", got)
	}
}

// Suricata's own rotate-interval renames without immediately creating a
// replacement, so for a moment there is nothing at the path at all.
func TestSurvivesGapWithNoFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	write(t, path, "old\n")

	f := New(path)
	defer f.Close()
	collect(t, f)

	if err := os.Rename(path, filepath.Join(dir, "eve.json.1754179200")); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := collect(t, f); len(got) != 0 {
		t.Fatalf("gap produced %q", got)
	}
	write(t, path, "new\n")
	if got := collect(t, f); len(got) != 1 || got[0] != "new" {
		t.Fatalf("after replacement = %q, want [new]", got)
	}
}

func TestTrimsCarriageReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eve.json")
	write(t, path, "line\r\n")

	f := New(path)
	defer f.Close()

	got := collect(t, f)
	if len(got) != 1 || got[0] != "line" {
		t.Fatalf("= %q, want [line]", got)
	}
}
