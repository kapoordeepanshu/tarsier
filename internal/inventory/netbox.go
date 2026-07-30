package inventory

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
)

// NetBox export.
//
// NetBox is where a great many organisations already keep their source of
// truth, and its best-known failure mode is stated plainly by its own
// community: it starts as a pristine database and becomes a read-only archive,
// because keeping it current is manual. NetBox's own answer, NetBox Discovery,
// probes with ICMP, TCP, UDP and SSH — which is unavailable on an OT network
// and unwelcome on plenty of IT ones.
//
// A passive feed fills exactly that gap, so the useful thing to emit is not a
// new interface but a file NetBox already accepts.
//
// This writes the ipam.ip_addresses form on purpose. NetBox's device import
// requires site, role, manufacturer and device_type to exist as objects first,
// so a device CSV fails on a fresh install and needs a schema conversation
// before it works. IP addresses import into any NetBox with no prerequisites at
// all, and they carry everything we actually learned in fields that survive.

// WriteNetBoxCSV emits devices as NetBox ipam.ip_addresses rows.
//
// Import in NetBox under IPAM → IP Addresses → Import. Existing addresses are
// matched on the address field, so re-importing a later scan updates rather
// than duplicates.
func WriteNetBoxCSV(w io.Writer, snap Snapshot) error {
	cw := csv.NewWriter(w)

	if err := cw.Write([]string{"address", "status", "dns_name", "description", "comments"}); err != nil {
		return err
	}

	for _, d := range snap.Devices {
		// NetBox wants a prefix length. A passive observation cannot know the
		// subnet mask — nothing on the wire states it — so /32 is the honest
		// answer: this address exists, and we are not claiming to know its
		// network. NetBox will still file it under the right prefix if one is
		// already defined.
		address := d.IP + "/32"

		if err := cw.Write([]string{
			address,
			"active",
			netboxDNSName(d.Hostname),
			netboxDescription(d),
			netboxComments(d),
		}); err != nil {
			return err
		}
	}

	cw.Flush()
	return cw.Error()
}

// netboxDNSName sanitises a hostname for NetBox's dns_name field, which
// accepts only characters valid in DNS. mDNS names and SMB names routinely
// contain neither.
func netboxDNSName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
			b.WriteRune(c)
		}
	}
	out := strings.Trim(b.String(), ".-")
	// NetBox caps dns_name at 255 characters.
	if len(out) > 255 {
		out = out[:255]
	}
	return out
}

// netboxDescription is the one-line summary shown in NetBox's address list.
func netboxDescription(d Device) string {
	parts := []string{}
	if d.Vendor != "" {
		parts = append(parts, d.Vendor)
	}
	if d.Model != "" {
		parts = append(parts, d.Model)
	}
	if d.Class != "" {
		parts = append(parts, d.Class)
	}
	if d.OS != "" {
		parts = append(parts, d.OS)
	}
	desc := strings.Join(parts, " · ")
	if desc == "" {
		desc = "unidentified device"
	}
	// Say where this came from and how sure we are. An entry in a source of
	// truth that does not disclose it was inferred is worse than no entry:
	// somebody will later treat a 40%-confidence guess as a fact on record.
	desc += " (tarsier, " + strconv.Itoa(int(d.Confidence*100)) + "% confidence)"
	if len(desc) > 200 {
		desc = desc[:200]
	}
	return desc
}

// netboxComments carries the detail that does not fit a description, including
// the evidence trail. NetBox renders comments as Markdown.
func netboxComments(d Device) string {
	var b strings.Builder
	b.WriteString("Discovered passively by Tarsier from Suricata metadata. ")
	b.WriteString("Not verified by scanning.\n\n")

	if d.MAC != "" {
		b.WriteString("- MAC: `" + d.MAC + "`")
		if d.RandomMAC {
			b.WriteString(" (randomised — not a stable identifier)")
		}
		b.WriteString("\n")
	}
	if d.Firmware != "" {
		b.WriteString("- Firmware: " + d.Firmware + "\n")
	}
	if d.Serial != "" {
		b.WriteString("- Serial: " + d.Serial + "\n")
	}
	if len(d.VLANs) > 0 {
		b.WriteString("- VLANs: " + joinPorts(d.VLANs) + "\n")
	}
	if len(d.Services) > 0 {
		ports := make([]int, 0, len(d.Services))
		for _, s := range d.Services {
			ports = append(ports, s.Port)
		}
		b.WriteString("- Open ports: " + joinPorts(ports) + "\n")
	}
	if len(d.Protocols) > 0 {
		b.WriteString("- Protocols: " + join(d.Protocols) + "\n")
	}
	if len(d.OTIdentifiers) > 0 {
		b.WriteString("- OT identifiers: " + join(d.OTIdentifiers) + "\n")
	}
	if !d.FirstSeen.IsZero() {
		b.WriteString("- First seen: " + d.FirstSeen.Format("2006-01-02 15:04") + " UTC\n")
	}
	if !d.LastSeen.IsZero() {
		b.WriteString("- Last seen: " + d.LastSeen.Format("2006-01-02 15:04") + " UTC\n")
	}
	return b.String()
}
