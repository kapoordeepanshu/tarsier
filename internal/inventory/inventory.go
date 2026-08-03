// Package inventory is the machine-readable form of a scan.
//
// The HTML report is what gets handed to a person. This is what gets handed to
// everything else: a diff against last week, a NetBox sync, a spreadsheet, a
// ticket. A report you read once is interesting; "three devices appeared on the
// finance VLAN overnight" is the thing someone checks every Monday, and that
// requires the scan to have an output a machine can compare.
//
// The schema is versioned and additive. Fields may be added; existing ones keep
// their meaning, so a snapshot written today still diffs against one written a
// year from now.
package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"tarsier/internal/identify"
)

// SchemaVersion is bumped only for a change that breaks older readers.
const SchemaVersion = 1

// Snapshot is one scan, in full.
type Snapshot struct {
	Schema    int       `json:"schema"`
	Tool      string    `json:"tool"`
	Source    string    `json:"source"`    // what was scanned
	Generated time.Time `json:"generated"` // when this snapshot was written
	First     time.Time `json:"first_event,omitempty"`
	Last      time.Time `json:"last_event,omitempty"`
	Events    int       `json:"events"`
	Skipped   int       `json:"skipped"`

	Devices  []Device  `json:"devices"`
	Findings []Finding `json:"findings"`
	// Identities is the same data seen from the other side: who signed in
	// where. Additive, so a consumer written against schema 1 keeps working.
	Identities []Identity `json:"identities,omitempty"`
}

// Identity is one account and the addresses it was seen signing in from.
type Identity struct {
	User    string   `json:"user"`
	Devices []string `json:"devices"`
}

// Device is one resolved thing on the network, in its exported form.
//
// This is deliberately a separate type from identify.Device rather than a set
// of json tags on it. The internal model changes as identification improves;
// this shape is a promise to whatever is reading the file.
type Device struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	RandomMAC bool   `json:"random_mac,omitempty"`

	Hostname  string   `json:"hostname,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`

	Class      string  `json:"class,omitempty"`
	Confidence float64 `json:"confidence"`
	Vendor     string  `json:"vendor,omitempty"`
	OS         string  `json:"os,omitempty"`
	Model      string  `json:"model,omitempty"`
	Firmware   string  `json:"firmware,omitempty"`
	Serial     string  `json:"serial,omitempty"`

	Services      []Service `json:"services,omitempty"`
	Protocols     []string  `json:"protocols,omitempty"`
	Users         []string  `json:"users,omitempty"`
	Shares        []string  `json:"shares,omitempty"`
	VLANs         []int     `json:"vlans,omitempty"`
	OTIdentifiers []string  `json:"ot_identifiers,omitempty"`
	JA4           []string  `json:"ja4,omitempty"`

	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`

	Alerts    int `json:"alerts,omitempty"`
	Anomalies int `json:"anomalies,omitempty"`

	Evidence []Evidence `json:"evidence,omitempty"`
}

// Service is a port the device answered on.
type Service struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto,omitempty"`
	AppProto string `json:"app_proto,omitempty"`
}

// Evidence is one observation behind a conclusion. Exported because an
// identification nobody can audit is one nobody will act on, and that stays
// true when the consumer is a script rather than a person.
type Evidence struct {
	Signal     string  `json:"signal"`
	Value      string  `json:"value"`
	Conclusion string  `json:"conclusion"`
	Weight     float64 `json:"weight"`
}

// Finding is something worth acting on.
type Finding struct {
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Device   string `json:"device"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

// Build converts a completed scan into its exported form.
func Build(source string, events, skipped int, devices []*identify.Device,
	findings []identify.Finding, first, last time.Time, now time.Time) Snapshot {

	snap := Snapshot{
		Schema:    SchemaVersion,
		Tool:      "tarsier-scan",
		Source:    source,
		Generated: now.UTC(),
		First:     first.UTC(),
		Last:      last.UTC(),
		Events:    events,
		Skipped:   skipped,
		Devices:   make([]Device, 0, len(devices)),
		Findings:  make([]Finding, 0, len(findings)),
	}

	for _, d := range devices {
		out := Device{
			IP:            d.IP,
			MAC:           d.MAC,
			RandomMAC:     d.RandomMAC,
			Hostname:      d.BestHostname(),
			Hostnames:     d.SortedHostnames(),
			Class:         string(d.Class),
			Confidence:    round3(d.Confidence()),
			Vendor:        d.Vendor,
			OS:            d.OS,
			Model:         d.Model,
			Firmware:      d.Firmware,
			Serial:        d.Serial,
			Protocols:     d.SortedProtocols(),
			Users:         d.SortedUsers(),
			Shares:        d.SortedShares(),
			VLANs:         d.SortedVLANs(),
			OTIdentifiers: d.SortedOTIdentifiers(),
			JA4:           sortedSet(d.JA4),
			FirstSeen:     d.FirstSeen.UTC(),
			LastSeen:      d.LastSeen.UTC(),
			Alerts:        d.Alerts,
			Anomalies:     d.Anomalies,
		}
		for _, s := range d.SortedServices() {
			out.Services = append(out.Services, Service{
				Port: s.Port, Proto: s.Proto, AppProto: s.AppProto,
			})
		}
		for _, e := range d.Evidence {
			out.Evidence = append(out.Evidence, Evidence{
				Signal: e.Signal, Value: e.Value,
				Conclusion: e.Conclusion, Weight: e.Weight,
			})
		}
		snap.Devices = append(snap.Devices, out)
	}

	// Sort by IP so two snapshots of the same network produce comparable files
	// and a diff of the raw JSON is readable.
	sort.Slice(snap.Devices, func(i, j int) bool {
		return ipLess(snap.Devices[i].IP, snap.Devices[j].IP)
	})

	for _, f := range findings {
		snap.Findings = append(snap.Findings, Finding{
			Severity: f.Severity.String(), Kind: f.Kind, Device: f.Device,
			Title: f.Title, Detail: f.Detail, Fix: f.Fix,
		})
	}

	for _, id := range identify.Identities(devices) {
		ips := make([]string, 0, len(id.Devices))
		for _, d := range id.Devices {
			ips = append(ips, d.IP)
		}
		snap.Identities = append(snap.Identities, Identity{User: id.User, Devices: ips})
	}

	return snap
}

// Write emits a snapshot as indented JSON. Indented on purpose: these files end
// up in git repositories and ticket attachments, where a readable diff is worth
// more than the bytes saved.
func Write(w io.Writer, snap Snapshot) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

// Read parses a snapshot, rejecting one written by a newer major schema rather
// than silently comparing fields it does not understand.
func Read(r io.Reader) (Snapshot, error) {
	var snap Snapshot
	if err := json.NewDecoder(r).Decode(&snap); err != nil {
		return snap, fmt.Errorf("not a tarsier snapshot: %w", err)
	}
	if snap.Schema == 0 {
		return snap, fmt.Errorf("not a tarsier snapshot: no schema version")
	}
	if snap.Schema > SchemaVersion {
		return snap, fmt.Errorf("snapshot uses schema %d, this build understands %d — upgrade tarsier",
			snap.Schema, SchemaVersion)
	}
	return snap, nil
}

// Key is the identity a device is tracked by across scans.
//
// A MAC address is the only durable identifier available: addresses move with
// DHCP, and a device that changed address is the same device, not a new one.
// A randomised MAC is explicitly excluded — phones rotate it per network, so
// treating it as durable would report a stream of new devices forever.
func (d Device) Key() string {
	if d.MAC != "" && !d.RandomMAC {
		return "mac:" + d.MAC
	}
	return "ip:" + d.IP
}

// Label is how a device is named to a human in output.
func (d Device) Label() string {
	switch {
	case d.Hostname != "":
		return d.Hostname
	case d.Vendor != "" && d.Class != "":
		return d.Vendor + " " + d.Class
	case d.Vendor != "":
		return d.Vendor
	case d.Class != "":
		return d.Class
	}
	return d.IP
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}

func ipLess(a, b string) bool {
	as, bs := splitIP(a), splitIP(b)
	if as == nil || bs == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return false
}

func splitIP(s string) []int {
	out := make([]int, 0, 4)
	n, digits := 0, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			n = n*10 + int(s[i]-'0')
			digits++
		case s[i] == '.':
			if digits == 0 {
				return nil
			}
			out = append(out, n)
			n, digits = 0, 0
		default:
			return nil
		}
	}
	if digits == 0 {
		return nil
	}
	out = append(out, n)
	if len(out) != 4 {
		return nil
	}
	return out
}
