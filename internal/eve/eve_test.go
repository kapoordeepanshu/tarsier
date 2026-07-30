package eve

import (
	"strings"
	"testing"
)

// The parser's central promise is that it never fails on input it did not
// expect. Suricata adds fields and event types in most releases and
// distributions patch independently, so these tests are less about correctness
// on known input than about refusing to break on unknown input.

func TestUnknownFieldsAndTypesAreNotFatal(t *testing.T) {
	// A future Suricata emitting an event type and fields that did not exist
	// when this parser was written must still be read, not dropped.
	in := `{"timestamp":"2026-07-30T09:14:02.113422+0000","event_type":"quantum_tunnel",` +
		`"src_ip":"10.0.0.1","dest_ip":"10.0.0.2","future_field":{"nested":[1,2,3]}}`

	r := NewReader(strings.NewReader(in))
	rec := r.Next()
	if rec == nil {
		t.Fatal("record was dropped; unknown event types must still parse")
	}
	if got := rec.Type(); got != "quantum_tunnel" {
		t.Errorf("Type() = %q, want %q", got, "quantum_tunnel")
	}
	if got := rec.Str("src_ip"); got != "10.0.0.1" {
		t.Errorf("known field lost alongside unknown ones: %q", got)
	}
	if rec.Str("field.that.does.not.exist") != "" {
		t.Error("missing path should return empty, not panic or invent a value")
	}
}

func TestMalformedLinesAreSkippedNotFatal(t *testing.T) {
	// Log rotation regularly leaves a half-written final line. Losing the whole
	// file because of it would be a far worse failure than losing one event.
	in := strings.Join([]string{
		`{"event_type":"dns","src_ip":"10.0.0.1"}`,
		`{"event_type":"tls","src_ip":`, // truncated mid-write
		``,                              // blank line
		`not json at all`,
		`{"event_type":"http","src_ip":"10.0.0.3"}`,
	}, "\n")

	r := NewReader(strings.NewReader(in))
	var got []string
	for rec := r.Next(); rec != nil; rec = r.Next() {
		got = append(got, rec.Type())
	}
	if err := r.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil: a bad line is not a read failure", err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d records (%v), want the 2 valid ones", len(got), got)
	}
	total, skipped := r.Stats()
	if skipped != 2 {
		t.Errorf("skipped = %d, want 2 (truncated + non-JSON)", skipped)
	}
	if total != 4 {
		t.Errorf("total = %d, want 4 non-blank lines seen", total)
	}
}

func TestFirstStrHandlesRenamedFields(t *testing.T) {
	// Fields have moved between Suricata versions. FirstStr is how the parser
	// survives that without version sniffing.
	in := `{"event_type":"dhcp","dhcp":{"vendor_class":"MSFT 5.0"}}`
	rec := NewReader(strings.NewReader(in)).Next()
	if rec == nil {
		t.Fatal("no record")
	}
	got := rec.FirstStr("dhcp.vendor_class_identifier", "dhcp.vendor_class")
	if got != "MSFT 5.0" {
		t.Errorf("FirstStr fell through to nothing: %q", got)
	}
}

func TestHasIsPresenceNotVersion(t *testing.T) {
	// Distributions backport features, so presence of a field is the only
	// trustworthy signal that it is available.
	withJA4 := NewReader(strings.NewReader(`{"event_type":"tls","tls":{"ja4":"t13d1516h2"}}`)).Next()
	if !withJA4.Has("tls.ja4") {
		t.Error("Has() missed a field that is present")
	}
	without := NewReader(strings.NewReader(`{"event_type":"tls","tls":{"sni":"x.com"}}`)).Next()
	if without.Has("tls.ja4") {
		t.Error("Has() reported a field that is absent")
	}
}

func TestTimestampFormats(t *testing.T) {
	// Suricata's numeric-offset format is not RFC3339; both must parse.
	for _, ts := range []string{
		"2026-07-30T09:14:02.113422+0000",
		"2026-07-30T09:14:02.113422Z",
	} {
		rec := NewReader(strings.NewReader(`{"timestamp":"` + ts + `"}`)).Next()
		if rec.Timestamp().IsZero() {
			t.Errorf("timestamp %q did not parse", ts)
		}
	}
	rec := NewReader(strings.NewReader(`{"timestamp":"not a time"}`)).Next()
	if !rec.Timestamp().IsZero() {
		t.Error("unparseable timestamp should be zero, not a guess")
	}
}

func TestIntToleratesStringNumbers(t *testing.T) {
	// Some numeric fields have been emitted as strings depending on version.
	rec := NewReader(strings.NewReader(`{"dest_port":443,"src_port":"8080"}`)).Next()
	if got := rec.Int("dest_port"); got != 443 {
		t.Errorf("Int(number) = %d, want 443", got)
	}
	if got := rec.Int("src_port"); got != 8080 {
		t.Errorf("Int(string) = %d, want 8080", got)
	}
}

func TestLongLinesAreNotTruncated(t *testing.T) {
	// TLS records carrying full certificate chains routinely exceed the default
	// scanner buffer. Silently truncating them would corrupt parsing.
	long := `{"event_type":"tls","tls":{"subject":"` + strings.Repeat("A", 200_000) + `"}}`
	rec := NewReader(strings.NewReader(long)).Next()
	if rec == nil {
		t.Fatal("long line dropped")
	}
	if len(rec.Str("tls.subject")) != 200_000 {
		t.Errorf("long value truncated to %d bytes", len(rec.Str("tls.subject")))
	}
}
