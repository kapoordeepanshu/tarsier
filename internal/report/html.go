// Package report renders a survey of the network as a single self-contained
// HTML file.
//
// Design note. Cards on a tinted canvas, separated by elevation and space
// rather than by a hairline around every element — the latter is what makes an
// interface read as a decade-old admin panel.
//
// Three rules carry through the document:
//
//   - Proportional type with tabular numerals throughout. Monospace is reserved
//     for machine identifiers — addresses, MAC addresses, hashes. Setting
//     everything in monospace makes a product look like a terminal dump.
//   - Colour is used as fill, never only as a 1px rule. A severity is a tinted
//     pill; it reads at a glance in a way a coloured hairline never does.
//   - Every identification is drawn inside a ring that fills to its confidence.
//     Identity and certainty are one object, because the only real claim this
//     report makes is that it admits what it does not know.
//
// The file has no external references of any kind. It opens from a USB stick on
// a machine with no network, which is often where this sort of work happens.
package report

import (
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"tarsier/internal/identify"
)

// Report is everything the template needs, precomputed so the template stays
// declarative.
type Report struct {
	Source      string
	Generated   string
	TotalEvents int
	Skipped     int

	Devices  []DeviceView
	Findings []FindingView
	Classes  []ClassCount
	Coverage []CoverageRow

	CountDevices    int
	CountIdentified int
	CountNamed      int
	CountFindings   int
	CountCritical   int
	MissingTypes    int

	// Timeline of the whole capture, one bar per bucket. Doubles as the range
	// selector: drag across it and the inventory below filters to match.
	Timeline   []Bar
	HasTime    bool
	SpanLabel  string
	FirstLabel string
	LastLabel  string
	BucketMins int
}

// Bar is one column of the activity timeline.
type Bar struct {
	X     float64 // left edge, percent
	W     float64 // width, percent
	H     float64 // height, percent of tallest
	Label string  // shown on hover
	Hour  int64   // Unix hour, for range selection
}

type DeviceView struct {
	IP         string
	Hostname   string
	Identity   string
	Class      string
	Icon       template.HTML // inline SVG glyph for the device class
	MAC        string
	Vendor     string
	Users      string
	Services   string
	Protocols  string
	Shares     string
	External   int
	Alerts     int
	Confidence float64
	ConfPct    string
	// RingDash draws the confidence arc around the device glyph — the one place
	// this report says something no other dashboard in the category says: how
	// sure it is. Circumference of r=14 is 87.96.
	RingDash string
	Evidence []EvidenceView
	Unknown  bool

	// Spark is this device's own activity across the same buckets as the
	// timeline, as an SVG polyline. The shape carries information a table
	// cannot: a device that woke up once at 3am looks nothing like one that
	// hums along all day.
	Spark     string
	FirstSeen string
	LastSeen  string
	Severity  string // worst finding on this device, for the row marker

	// Buckets is one character per timeline bucket, '0' (silent) to '9' (peak).
	//
	// Filtering has to test real activity per bucket, not the span between
	// first and last seen: a device that ran all week overlaps every window, so
	// span-based filtering leaves the list essentially unchanged. This is what
	// makes the time selector actually select something.
	Buckets string
	Events  int // total events, for ranking top talkers
}

type EvidenceView struct {
	Signal     string
	Value      string
	Conclusion string
	Weight     string
}

type FindingView struct {
	Severity string
	Class    string
	Device   string
	Title    string
	Detail   string
	Fix      string
	Command  string
	Count    int
}

type ClassCount struct {
	Class string
	Count int
	Pct   float64
}

type CoverageRow struct {
	Type    string
	Count   string
	Present bool
	Why     string
}

// wanted lists the event types that carry identity, with what each one buys.
// Shown to the user because the commonest reason this tool underperforms is a
// Suricata logging only alerts — and there is no way for them to discover that
// on their own.
var wanted = []struct{ Type, Why string }{
	{"dhcp", "device names, MAC addresses, vendor and OS"},
	{"arp", "statically-addressed devices that never use DHCP"},
	{"dns", "friendly device names"},
	{"tls", "certificates, fingerprints, shadow IT"},
	{"http", "operating systems, browsers, embedded devices"},
	{"flow", "which device serves which port"},
	{"smb", "Windows hostnames and usernames"},
	{"krb5", "usernames and Active Directory realm"},
	{"ssh", "operating system detail"},
	{"snmp", "exact model and firmware of network gear"},
}

// Build assembles the view model from resolver output.
func Build(source string, total, skipped int, devices []*identify.Device,
	findings []identify.Finding, counts map[string]int, first, last time.Time) *Report {

	r := &Report{
		Source:      source,
		Generated:   time.Now().Format("2 January 2006, 15:04"),
		TotalEvents: total,
		Skipped:     skipped,
	}

	// Worst finding per device, so a row can be marked without opening it.
	worst := map[string]identify.Severity{}
	for _, f := range findings {
		if s, ok := worst[f.Device]; !ok || f.Severity > s {
			worst[f.Device] = f.Severity
		}
	}

	hFrom, hTo, step, nb := buildTimeline(r, devices, first, last)

	classCount := map[string]int{}
	for _, d := range devices {
		dv := DeviceView{
			IP:         d.IP,
			Hostname:   d.BestHostname(),
			MAC:        d.MAC,
			Vendor:     d.Vendor,
			Class:      string(d.Class),
			Users:      strings.Join(d.SortedUsers(), ", "),
			Protocols:  strings.Join(d.SortedProtocols(), " "),
			Shares:     strings.Join(d.SortedShares(), " "),
			External:   len(d.ExternalDsts),
			Alerts:     d.Alerts,
			Confidence: d.Confidence(),
			ConfPct:    pct(d.Confidence()),
		}

		var id []string
		if d.Vendor != "" {
			id = append(id, d.Vendor)
		}
		if d.OS != "" {
			id = append(id, d.OS)
		}
		if d.Class != identify.ClassUnknown {
			id = append(id, string(d.Class))
		}
		if len(id) == 0 {
			dv.Identity = "unidentified"
			dv.Unknown = true
			dv.Class = "unknown"
		} else {
			dv.Identity = strings.Join(id, " · ")
		}

		var svc []string
		for _, s := range d.SortedServices() {
			label := itoa(s.Port)
			if s.AppProto != "" {
				label += "/" + s.AppProto
			}
			svc = append(svc, label)
		}
		dv.Services = strings.Join(svc, " ")

		seen := map[string]bool{}
		for _, e := range d.Evidence {
			k := e.Signal + e.Value + e.Conclusion
			if seen[k] {
				continue
			}
			seen[k] = true
			dv.Evidence = append(dv.Evidence, EvidenceView{
				Signal: e.Signal, Value: e.Value,
				Conclusion: e.Conclusion, Weight: pct(e.Weight),
			})
		}

		dv.Icon = classIcon(dv.Class)
		{
			const circumference = 87.96
			filled := d.Confidence() * circumference
			dv.RingDash = ftoa(filled) + " " + ftoa(circumference-filled)
		}
		if s, ok := worst[d.IP]; ok {
			dv.Severity = strings.ToLower(s.String())
		}
		if !d.FirstSeen.IsZero() {
			dv.FirstSeen = d.FirstSeen.Format("2 Jan 15:04")
			dv.LastSeen = d.LastSeen.Format("2 Jan 15:04")
		}
		for _, n := range d.Activity {
			dv.Events += n
		}
		dv.Buckets = bucketString(d.Activity, hFrom, step, nb)
		dv.Spark = sparkline(d.Activity, hFrom, hTo)

		classCount[dv.Class]++
		if !dv.Unknown {
			r.CountIdentified++
		}
		if dv.Hostname != "" {
			r.CountNamed++
		}
		r.Devices = append(r.Devices, dv)
	}
	r.CountDevices = len(devices)

	for _, f := range findings {
		if f.Severity == identify.SevCritical {
			r.CountCritical++
		}
		r.Findings = append(r.Findings, FindingView{
			Severity: f.Severity.String(),
			Class:    strings.ToLower(f.Severity.String()),
			Device:   f.Device, Title: f.Title, Detail: f.Detail,
			Fix: f.Fix, Command: f.Command, Count: f.Count,
		})
	}
	r.CountFindings = len(findings)

	for c, n := range classCount {
		p := 0.0
		if r.CountDevices > 0 {
			p = float64(n) / float64(r.CountDevices) * 100
		}
		r.Classes = append(r.Classes, ClassCount{Class: c, Count: n, Pct: p})
	}
	sort.Slice(r.Classes, func(i, j int) bool { return r.Classes[i].Count > r.Classes[j].Count })

	for _, w := range wanted {
		n := counts[w.Type]
		if n == 0 {
			r.MissingTypes++
		}
		r.Coverage = append(r.Coverage, CoverageRow{
			Type: w.Type, Count: comma(n), Present: n > 0, Why: w.Why,
		})
	}
	return r
}

// Write renders the report. html/template escapes everything, which matters
// here: hostnames, banners and certificate subjects are attacker-controllable
// strings lifted straight off the wire.
func Write(w io.Writer, r *Report) error {
	t, err := template.New("report").Funcs(template.FuncMap{
		"comma": comma,
	}).Parse(page)
	if err != nil {
		return err
	}
	return t.Execute(w, r)
}

// buildTimeline lays out the activity histogram and returns the hour range it
// covers, which the per-device sparklines are drawn against so every trace
// shares one horizontal scale. Comparing shapes only means something if the
// axes match.
func buildTimeline(r *Report, devices []*identify.Device, first, last time.Time) (int64, int64, int64, int) {
	if first.IsZero() || last.IsZero() || !last.After(first) {
		// A capture confined to a single hour still deserves a device list;
		// it just has no meaningful timeline.
		if !first.IsZero() {
			r.FirstLabel = first.Format("2 Jan 15:04")
			r.LastLabel = last.Format("2 Jan 15:04")
		}
		return 0, 0, 1, 0
	}
	hFrom, hTo := first.Unix()/3600, last.Unix()/3600
	if hTo < hFrom {
		hTo = hFrom
	}

	totals := map[int64]int{}
	for _, d := range devices {
		for h, n := range d.Activity {
			if h >= hFrom && h <= hTo {
				totals[h] += n
			}
		}
	}

	// Aim for roughly 90 bars: hourly for short captures, wider for long ones.
	span := hTo - hFrom + 1
	step := int64(1)
	for span/step > 90 {
		step *= 2
	}
	nb := (span + step - 1) / step

	peak := 0
	buckets := make([]int, nb)
	for h, n := range totals {
		i := (h - hFrom) / step
		if i >= 0 && i < nb {
			buckets[i] += n
			if buckets[i] > peak {
				peak = buckets[i]
			}
		}
	}
	if peak == 0 {
		peak = 1
	}

	w := 100.0 / float64(nb)
	for i, n := range buckets {
		t := first.Add(time.Duration(int64(i)*step) * time.Hour)
		r.Timeline = append(r.Timeline, Bar{
			X: float64(i) * w, W: w,
			// Square root keeps a quiet hour visible next to a busy one. Linear
			// scaling on network data hides everything but the peak.
			H:     sqrtScale(n, peak),
			Label: t.Format("2 Jan 15:04") + " · " + comma(n),
			Hour:  hFrom + int64(i)*step,
		})
	}

	r.HasTime = true
	r.BucketMins = int(step * 60)
	r.FirstLabel = first.Format("2 Jan 2006, 15:04")
	r.LastLabel = last.Format("2 Jan 2006, 15:04")
	r.SpanLabel = humanSpan(last.Sub(first))
	return hFrom, hTo, step, int(nb)
}

// bucketString encodes a device's activity as one character per timeline
// bucket, '0' for silent through '9' for its own peak. Compact enough to sit in
// an attribute on every row, and precise enough to filter on.
func bucketString(activity map[int64]int, hFrom, step int64, nb int) string {
	if nb <= 0 {
		return ""
	}
	vals := make([]int, nb)
	peak := 0
	for h, n := range activity {
		i := int((h - hFrom) / step)
		if i >= 0 && i < nb {
			vals[i] += n
			if vals[i] > peak {
				peak = vals[i]
			}
		}
	}
	b := make([]byte, nb)
	for i, v := range vals {
		switch {
		case v == 0:
			b[i] = '0'
		case peak <= 1:
			b[i] = '9'
		default:
			// 1..9, so any activity at all is distinguishable from silence.
			b[i] = byte('1' + int(float64(v-1)/float64(peak)*8))
		}
	}
	return string(b)
}

// sparkline renders one device's activity as an SVG polyline over a 100x20 box.
func sparkline(activity map[int64]int, hFrom, hTo int64) string {
	if hTo <= hFrom || len(activity) == 0 {
		return ""
	}
	span := hTo - hFrom + 1
	n := int(span)
	if n > 60 {
		n = 60
	}
	step := span / int64(n)
	if step < 1 {
		step = 1
	}

	vals := make([]int, n)
	peak := 0
	for h, c := range activity {
		i := int((h - hFrom) / step)
		if i >= 0 && i < n {
			vals[i] += c
			if vals[i] > peak {
				peak = vals[i]
			}
		}
	}
	if peak == 0 {
		return ""
	}

	var b strings.Builder
	for i, v := range vals {
		if i > 0 {
			b.WriteByte(' ')
		}
		x := float64(i) * (100.0 / float64(n-1))
		if n == 1 {
			x = 50
		}
		y := 19.0 - sqrtScale(v, peak)/100*18
		b.WriteString(ftoa(x))
		b.WriteByte(',')
		b.WriteString(ftoa(y))
	}
	return b.String()
}

// sqrtScale compresses the range so quiet periods stay visible beside peaks.
func sqrtScale(n, peak int) float64 {
	if n <= 0 || peak <= 0 {
		return 0
	}
	f := float64(n) / float64(peak)
	// Cheap square root; avoids importing math for one call.
	x := f
	for i := 0; i < 12; i++ {
		if x == 0 {
			break
		}
		x = (x + f/x) / 2
	}
	return x * 100
}

func ftoa(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 10)
	if frac < 0 {
		frac = -frac
	}
	return itoa(whole) + "." + itoa(frac)
}

func humanSpan(d time.Duration) string {
	switch {
	case d < time.Hour:
		return itoa(int(d.Minutes())) + " minutes"
	case d < 48*time.Hour:
		return itoa(int(d.Hours())) + " hours"
	default:
		return itoa(int(d.Hours()/24)) + " days"
	}
}

// pct is always a bare number so it can be interpolated into a CSS position as
// well as displayed. Unknown devices are marked with a flag, not a dash here.
func pct(f float64) string {
	if f <= 0 {
		return "0"
	}
	return itoa(int(f*100 + 0.5))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func comma(n int) string {
	s := itoa(n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ' ')
		}
		out = append(out, s[i])
	}
	return string(out)
}
