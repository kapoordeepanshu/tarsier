// Package eve reads Suricata EVE JSON records.
//
// The parser is deliberately schema-tolerant. Suricata adds fields and event
// types in most releases, and the field set differs between 6.x, 7.x and 8.x as
// well as between distributions. Nothing here unmarshals into a fixed struct:
// records are decoded into a generic map and read by path, so an unknown field
// or a brand new event type is a no-op rather than an error.
//
// Rule of thumb for anything added here: never fail on a field you did not
// expect, and never drop a record you did not understand.
package eve

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// Record is one decoded EVE line. Raw is retained so that fields we do not read
// today can still be recovered later without re-ingesting anything.
type Record struct {
	Raw    []byte
	fields map[string]any
}

// Reader streams Records from an EVE JSON stream (one object per line).
type Reader struct {
	sc      *bufio.Scanner
	err     error
	skipped int
	total   int
}

// NewReader wraps r. Lines are allowed to be large: full HTTP or TLS records
// with certificate chains can comfortably exceed the default scanner limit.
func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &Reader{sc: sc}
}

// Next returns the next record, or nil when the stream is exhausted.
// Malformed lines are counted and skipped, never fatal: a truncated final line
// during log rotation is normal and must not stop ingestion.
func (r *Reader) Next() *Record {
	for r.sc.Scan() {
		line := strings.TrimSpace(r.sc.Text())
		if line == "" {
			continue
		}
		r.total++
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			r.skipped++
			continue
		}
		raw := make([]byte, len(line))
		copy(raw, line)
		return &Record{Raw: raw, fields: m}
	}
	r.err = r.sc.Err()
	return nil
}

// Err reports a read failure, if any. A malformed line is not a read failure.
func (r *Reader) Err() error { return r.err }

// Stats reports how many lines were seen and how many could not be decoded.
func (r *Reader) Stats() (total, skipped int) { return r.total, r.skipped }

// Type returns the EVE event_type ("alert", "dns", "dhcp", ...), or "".
func (rec *Record) Type() string { return rec.Str("event_type") }

// Timestamp parses the EVE timestamp. Zero time if absent or unparseable.
func (rec *Record) Timestamp() time.Time {
	s := rec.Str("timestamp")
	if s == "" {
		return time.Time{}
	}
	// Suricata emits RFC3339 with microseconds and a numeric zone offset.
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999-0700",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Get walks a dotted path ("tls.ja3.hash") and returns the raw value.
// A missing path returns nil rather than an error; callers treat absence as
// "this Suricata build does not emit that field" and carry on.
func (rec *Record) Get(path string) any {
	var cur any = rec.fields
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[part]
		if !ok {
			return nil
		}
	}
	return cur
}

// Str returns a string value at path, or "".
func (rec *Record) Str(path string) string {
	s, _ := rec.Get(path).(string)
	return s
}

// Int returns an integer value at path, or 0. JSON numbers decode as float64,
// and Suricata emits some numeric fields as strings depending on version.
func (rec *Record) Int(path string) int {
	switch v := rec.Get(path).(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n := 0
		for _, c := range v {
			if c < '0' || c > '9' {
				return 0
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 0
}

// Strings returns a []string at path, tolerating a bare string.
func (rec *Record) Strings(path string) []string {
	switch v := rec.Get(path).(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	}
	return nil
}

// Has reports whether a path is present. Preferred over comparing against a
// Suricata version number: distributions backport features, so the presence of
// the field is the only trustworthy signal that it is available.
func (rec *Record) Has(path string) bool { return rec.Get(path) != nil }

// FirstStr returns the first non-empty value among several candidate paths.
// Used where a field moved between Suricata versions.
func (rec *Record) FirstStr(paths ...string) string {
	for _, p := range paths {
		if s := rec.Str(p); s != "" {
			return s
		}
	}
	return ""
}

// FirstInt returns the first non-zero value among several candidate paths.
//
// The industrial loggers nest their fields under "request" or "response"
// depending on the direction of the exchange, so the same fact lives at two or
// three paths. Zero is not a distinguishable value here, but none of the fields
// this is used for — vendor IDs, unit IDs, station addresses — treat zero as
// meaningful: unit 0 is the Modbus broadcast address, not a device.
func (rec *Record) FirstInt(paths ...string) int {
	for _, p := range paths {
		if n := rec.Int(p); n != 0 {
			return n
		}
	}
	return 0
}
