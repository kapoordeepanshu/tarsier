package inventory

import (
	"sort"
	"strconv"
)

// Comparing two snapshots.
//
// This is the feature that turns a report into a habit. An inventory answers
// "what is on my network", which is interesting the first time and rarely the
// second. A diff answers "what changed since Friday", which is worth checking
// every week — and it is also the form in which most of the genuinely alarming
// things show up. A new device on the finance VLAN, a printer that started
// answering on 3389, a PLC whose firmware version moved without a change
// window: none of those are visible in a single scan, however good it is.

// Change is one difference between two snapshots.
type Change struct {
	Kind   string `json:"kind"` // "appeared", "disappeared", "changed"
	Key    string `json:"key"`  // the identity used to match across scans
	IP     string `json:"ip"`
	Label  string `json:"label"` // how to name this device to a person
	Detail string `json:"detail,omitempty"`
	// Fields lists the specific differences on a changed device.
	Fields []FieldChange `json:"fields,omitempty"`
}

// FieldChange is one attribute that moved.
type FieldChange struct {
	Field string `json:"field"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	// List marks an additive change — items gained or lost from a set — as
	// opposed to a scalar that moved from one value to another. Without it
	// "class: workstation" is ambiguous: it could mean the class became
	// workstation, or that workstation was added to a list of classes.
	List bool `json:"list,omitempty"`
}

// Diff is the full comparison.
type Diff struct {
	Appeared      []Change  `json:"appeared"`
	Disappeared   []Change  `json:"disappeared"`
	Changed       []Change  `json:"changed"`
	NewFindings   []Finding `json:"new_findings"`
	FixedFindings []Finding `json:"fixed_findings"`
}

// Empty reports whether nothing changed at all.
func (d Diff) Empty() bool {
	return len(d.Appeared) == 0 && len(d.Disappeared) == 0 && len(d.Changed) == 0 &&
		len(d.NewFindings) == 0 && len(d.FixedFindings) == 0
}

// Total counts every difference, for a one-line summary.
func (d Diff) Total() int {
	return len(d.Appeared) + len(d.Disappeared) + len(d.Changed) +
		len(d.NewFindings) + len(d.FixedFindings)
}

// Compare diffs two snapshots, oldest first.
func Compare(before, after Snapshot) Diff {
	// Empty rather than nil, so every list serialises as [] and not null. A
	// consumer asking jq for `.appeared | length` should get 0, not an error,
	// on the ordinary night when nothing happened.
	d := Diff{
		Appeared:      []Change{},
		Disappeared:   []Change{},
		Changed:       []Change{},
		NewFindings:   []Finding{},
		FixedFindings: []Finding{},
	}

	oldByKey := map[string]Device{}
	for _, dev := range before.Devices {
		oldByKey[dev.Key()] = dev
	}
	newByKey := map[string]Device{}
	for _, dev := range after.Devices {
		newByKey[dev.Key()] = dev
	}

	for _, dev := range after.Devices {
		prev, existed := oldByKey[dev.Key()]
		if !existed {
			d.Appeared = append(d.Appeared, Change{
				Kind: "appeared", Key: dev.Key(), IP: dev.IP, Label: dev.Label(),
				Detail: describe(dev),
			})
			continue
		}
		if fields := compareDevice(prev, dev); len(fields) > 0 {
			d.Changed = append(d.Changed, Change{
				Kind: "changed", Key: dev.Key(), IP: dev.IP, Label: dev.Label(),
				Fields: fields,
			})
		}
	}

	for _, dev := range before.Devices {
		if _, still := newByKey[dev.Key()]; !still {
			d.Disappeared = append(d.Disappeared, Change{
				Kind: "disappeared", Key: dev.Key(), IP: dev.IP, Label: dev.Label(),
				Detail: describe(dev),
			})
		}
	}

	d.NewFindings = findingsMissingFrom(after.Findings, before.Findings)
	d.FixedFindings = findingsMissingFrom(before.Findings, after.Findings)

	sortChanges(d.Appeared)
	sortChanges(d.Disappeared)
	sortChanges(d.Changed)
	return d
}

// compareDevice reports the attribute changes worth a human's attention.
//
// Deliberately not a full struct diff. Last-seen moves on every scan and
// evidence accumulates constantly; reporting those would bury the three lines
// that matter under a hundred that do not, and a change report nobody reads is
// no better than no change report.
func compareDevice(before, after Device) []FieldChange {
	var out []FieldChange

	scalar := []struct {
		field    string
		from, to string
	}{
		{"ip", before.IP, after.IP},
		{"hostname", before.Hostname, after.Hostname},
		{"os", before.OS, after.OS},
		{"class", before.Class, after.Class},
		{"vendor", before.Vendor, after.Vendor},
		{"model", before.Model, after.Model},
		// Firmware moving without a planned change window is exactly the kind
		// of thing an OT team needs told, and nothing else reports it.
		{"firmware", before.Firmware, after.Firmware},
		{"mac", before.MAC, after.MAC},
	}
	for _, s := range scalar {
		if s.from != s.to {
			out = append(out, FieldChange{Field: s.field, From: s.from, To: s.to})
		}
	}

	// New listening ports are the highest-value change in the whole diff: a
	// device that started serving something is either a misconfiguration or an
	// intrusion, and it is invisible in any single scan.
	if added := addedPorts(before.Services, after.Services); len(added) > 0 {
		out = append(out, FieldChange{List: true, Field: "new services", To: joinPorts(added)})
	}
	if gone := addedPorts(after.Services, before.Services); len(gone) > 0 {
		out = append(out, FieldChange{List: true, Field: "services gone", From: joinPorts(gone)})
	}

	if added := addedStrings(before.Protocols, after.Protocols); len(added) > 0 {
		out = append(out, FieldChange{List: true, Field: "new protocols", To: join(added)})
	}
	if added := addedStrings(before.Users, after.Users); len(added) > 0 {
		out = append(out, FieldChange{List: true, Field: "new users", To: join(added)})
	}
	if added := addedStrings(before.Shares, after.Shares); len(added) > 0 {
		out = append(out, FieldChange{List: true, Field: "new shares", To: join(added)})
	}
	if added := addedVLANs(before.VLANs, after.VLANs); len(added) > 0 {
		// A device appearing on a new VLAN is either a segmentation change or a
		// segmentation failure, and both are worth a look.
		out = append(out, FieldChange{List: true, Field: "new VLANs", To: joinPorts(added)})
	}
	if added := addedStrings(before.OTIdentifiers, after.OTIdentifiers); len(added) > 0 {
		out = append(out, FieldChange{List: true, Field: "new OT identifiers", To: join(added)})
	}

	return out
}

// describe summarises a device in one line, for appeared/disappeared entries.
func describe(d Device) string {
	s := d.IP
	if d.MAC != "" {
		s += "  " + d.MAC
	}
	if d.Vendor != "" {
		s += "  " + d.Vendor
	}
	if d.OS != "" {
		s += "  " + d.OS
	}
	if len(d.Services) > 0 {
		ports := make([]int, 0, len(d.Services))
		for _, svc := range d.Services {
			ports = append(ports, svc.Port)
		}
		s += "  ports " + joinPorts(ports)
	}
	return s
}

// findingsMissingFrom returns findings in a that have no counterpart in b.
// Findings are matched on device and kind rather than on their full text, so
// rewording a message does not present every device as newly broken.
func findingsMissingFrom(a, b []Finding) []Finding {
	have := map[string]bool{}
	for _, f := range b {
		have[f.Device+"\x00"+f.Kind] = true
	}
	out := []Finding{}
	for _, f := range a {
		if !have[f.Device+"\x00"+f.Kind] {
			out = append(out, f)
		}
	}
	return out
}

func addedPorts(before, after []Service) []int {
	had := map[int]bool{}
	for _, s := range before {
		had[s.Port] = true
	}
	var out []int
	for _, s := range after {
		if !had[s.Port] {
			out = append(out, s.Port)
		}
	}
	sort.Ints(out)
	return out
}

func addedVLANs(before, after []int) []int {
	had := map[int]bool{}
	for _, v := range before {
		had[v] = true
	}
	var out []int
	for _, v := range after {
		if !had[v] {
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

func addedStrings(before, after []string) []string {
	had := map[string]bool{}
	for _, s := range before {
		had[s] = true
	}
	var out []string
	for _, s := range after {
		if !had[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}

func joinPorts(p []int) string {
	out := ""
	for i, v := range p {
		if i > 0 {
			out += ", "
		}
		out += strconv.Itoa(v)
	}
	return out
}

func sortChanges(c []Change) {
	sort.Slice(c, func(i, j int) bool { return ipLess(c[i].IP, c[j].IP) })
}
