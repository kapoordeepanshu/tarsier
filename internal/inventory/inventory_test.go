package inventory

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

func dev(ip, mac string, opts ...func(*Device)) Device {
	d := Device{IP: ip, MAC: mac}
	for _, o := range opts {
		o(&d)
	}
	return d
}

func snap(devs ...Device) Snapshot {
	return Snapshot{Schema: SchemaVersion, Devices: devs}
}

// TestRoundTrip is the promise the diff depends on: a snapshot written today
// must still be readable later. If this breaks, every stored baseline breaks
// with it.
func TestRoundTrip(t *testing.T) {
	in := Snapshot{
		Schema: SchemaVersion, Tool: "tarsier-scan", Source: "eve.json",
		Generated: time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC),
		Events:    100,
		Devices: []Device{dev("10.0.0.5", "00:11:22:33:44:55", func(d *Device) {
			d.Class, d.Vendor, d.Confidence = "printer", "Brother", 0.9
			d.Services = []Service{{Port: 9100, Proto: "tcp"}}
		})},
		Findings: []Finding{{Severity: "HIGH", Kind: "smbv1", Device: "10.0.0.5", Title: "SMBv1"}},
	}

	var buf bytes.Buffer
	if err := Write(&buf, in); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(out.Devices) != 1 || out.Devices[0].IP != "10.0.0.5" {
		t.Fatalf("devices did not survive: %+v", out.Devices)
	}
	if out.Devices[0].Services[0].Port != 9100 {
		t.Errorf("services did not survive: %+v", out.Devices[0].Services)
	}
	if len(out.Findings) != 1 || out.Findings[0].Kind != "smbv1" {
		t.Errorf("findings did not survive: %+v", out.Findings)
	}
}

// TestReadRejectsNonSnapshots matters because the diff takes file paths from a
// user. Pointing it at an eve.json — an easy mistake, they are both JSON and
// both in the same directory — must say so rather than report every device on
// the network as newly appeared.
func TestReadRejectsNonSnapshots(t *testing.T) {
	for _, in := range []string{
		`{"event_type":"dhcp","src_ip":"10.0.0.1"}`, // an eve.json line
		`{}`,
		`[]`,
		`not json at all`,
	} {
		if _, err := Read(strings.NewReader(in)); err == nil {
			t.Errorf("Read(%q) succeeded; want an error", in)
		}
	}
}

// TestReadRejectsNewerSchema keeps an old binary from silently mis-diffing a
// file it does not fully understand.
func TestReadRejectsNewerSchema(t *testing.T) {
	_, err := Read(strings.NewReader(`{"schema":9999,"devices":[]}`))
	if err == nil {
		t.Fatal("a future schema was accepted")
	}
	if !strings.Contains(err.Error(), "upgrade") {
		t.Errorf("error %q does not tell the user what to do", err)
	}
}

// TestDeviceTracksAcrossAddressChange is the core of the diff being useful. A
// device that picked up a new DHCP lease is the same device; reporting it as
// one departure plus one arrival would make every Monday morning look like an
// incident.
func TestDeviceTracksAcrossAddressChange(t *testing.T) {
	before := snap(dev("10.0.1.20", "00:11:22:33:44:55"))
	after := snap(dev("10.0.1.99", "00:11:22:33:44:55"))

	d := Compare(before, after)
	if len(d.Appeared) != 0 || len(d.Disappeared) != 0 {
		t.Fatalf("a re-addressed device was treated as new: %+v / %+v", d.Appeared, d.Disappeared)
	}
	if len(d.Changed) != 1 {
		t.Fatalf("want 1 changed device, got %d", len(d.Changed))
	}
	got := d.Changed[0].Fields
	if len(got) != 1 || got[0].Field != "ip" || got[0].From != "10.0.1.20" || got[0].To != "10.0.1.99" {
		t.Errorf("address change not reported cleanly: %+v", got)
	}
}

// TestRandomisedMACsFallBackToAddress is the other half. A phone rotating its
// MAC must not be matched on it, or two unrelated devices would be reported as
// one device that changed everything about itself.
func TestRandomisedMACsFallBackToAddress(t *testing.T) {
	a := dev("10.0.3.66", "9a:11:22:33:44:55", func(d *Device) { d.RandomMAC = true })
	b := dev("10.0.3.67", "9a:99:88:77:66:55", func(d *Device) { d.RandomMAC = true })

	if a.Key() == b.Key() {
		t.Fatal("two randomised MACs collided on one key")
	}
	if !strings.HasPrefix(a.Key(), "ip:") {
		t.Errorf("Key() = %q, want a randomised MAC to fall back to the address", a.Key())
	}
}

// TestNewServiceIsReported covers the highest-value change in the diff: a
// device that started answering on a port it never served before is either a
// misconfiguration or an intrusion, and no single scan can show it.
func TestNewServiceIsReported(t *testing.T) {
	before := snap(dev("10.0.4.87", "00:80:77:aa:bb:cc", func(d *Device) {
		d.Services = []Service{{Port: 9100, Proto: "tcp"}}
	}))
	after := snap(dev("10.0.4.87", "00:80:77:aa:bb:cc", func(d *Device) {
		d.Services = []Service{{Port: 9100, Proto: "tcp"}, {Port: 3389, Proto: "tcp"}}
	}))

	d := Compare(before, after)
	if len(d.Changed) != 1 {
		t.Fatalf("want 1 changed device, got %d", len(d.Changed))
	}
	var found bool
	for _, f := range d.Changed[0].Fields {
		if f.Field == "new services" && strings.Contains(f.To, "3389") {
			found, _ = true, f
			if !f.List {
				t.Error("an additive change was not marked as a list")
			}
		}
	}
	if !found {
		t.Errorf("new port 3389 not reported: %+v", d.Changed[0].Fields)
	}
}

// TestFirmwareChangeIsReported is the OT case. A controller whose firmware
// moved without a change window is exactly what an OT team needs told, and
// nothing else in the ecosystem reports it.
func TestFirmwareChangeIsReported(t *testing.T) {
	before := snap(dev("10.20.0.50", "00:1d:9c:aa:bb:cc", func(d *Device) { d.Firmware = "20.011" }))
	after := snap(dev("10.20.0.50", "00:1d:9c:aa:bb:cc", func(d *Device) { d.Firmware = "21.003" }))

	d := Compare(before, after)
	if len(d.Changed) != 1 {
		t.Fatalf("want 1 changed device, got %d", len(d.Changed))
	}
	f := d.Changed[0].Fields[0]
	if f.Field != "firmware" || f.From != "20.011" || f.To != "21.003" {
		t.Errorf("firmware change not reported: %+v", f)
	}
}

// TestFindingsAreMatchedOnKindNotText keeps a reworded message from presenting
// every device on the network as newly broken.
func TestFindingsAreMatchedOnKindNotText(t *testing.T) {
	before := Snapshot{Schema: 1, Findings: []Finding{
		{Severity: "HIGH", Kind: "smbv1", Device: "10.0.0.42", Title: "SMBv1 file sharing is enabled"},
	}}
	after := Snapshot{Schema: 1, Findings: []Finding{
		{Severity: "HIGH", Kind: "smbv1", Device: "10.0.0.42", Title: "SMBv1 is on — reworded entirely"},
	}}

	d := Compare(before, after)
	if len(d.NewFindings) != 0 || len(d.FixedFindings) != 0 {
		t.Errorf("rewording a finding registered as a change: new=%v fixed=%v",
			d.NewFindings, d.FixedFindings)
	}
}

// TestFixedFindingIsReported is the reward half of the diff: work that got done
// should show up, or nobody gets credit for closing anything.
func TestFixedFindingIsReported(t *testing.T) {
	before := Snapshot{Schema: 1, Findings: []Finding{
		{Severity: "HIGH", Kind: "smbv1", Device: "10.0.0.42", Title: "SMBv1"},
	}}
	after := Snapshot{Schema: 1}

	d := Compare(before, after)
	if len(d.FixedFindings) != 1 || d.FixedFindings[0].Kind != "smbv1" {
		t.Errorf("a resolved finding was not reported: %+v", d.FixedFindings)
	}
}

// TestIdenticalSnapshotsProduceNothing guards the cron use case. A diff that
// reports noise on an unchanged network is one that gets muted within a week.
func TestIdenticalSnapshotsProduceNothing(t *testing.T) {
	s := snap(
		dev("10.0.0.5", "00:11:22:33:44:55", func(d *Device) {
			d.Services = []Service{{Port: 443, Proto: "tcp"}}
			d.Protocols = []string{"tls"}
		}),
		dev("10.0.0.6", "00:11:22:33:44:66"),
	)
	if d := Compare(s, s); !d.Empty() {
		t.Errorf("identical snapshots differed: %d changes", d.Total())
	}
}

// TestNetBoxCSVImports checks the shape NetBox actually accepts. Getting this
// wrong is invisible until someone pastes the file into a production NetBox and
// it is rejected, so the header and row width are worth pinning.
func TestNetBoxCSVImports(t *testing.T) {
	var buf bytes.Buffer
	err := WriteNetBoxCSV(&buf, snap(
		dev("10.0.4.87", "00:80:77:aa:bb:cc", func(d *Device) {
			d.Hostname, d.Vendor, d.Class, d.Confidence = "BRN3A1C44", "Brother", "printer", 0.92
		}),
	))
	if err != nil {
		t.Fatalf("WriteNetBoxCSV: %v", err)
	}

	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want a header and one row, got %d rows", len(rows))
	}
	want := []string{"address", "status", "dns_name", "description", "comments"}
	for i, h := range want {
		if rows[0][i] != h {
			t.Errorf("column %d = %q, want %q", i, rows[0][i], h)
		}
	}
	// NetBox requires a mask length on an address.
	if rows[1][0] != "10.0.4.87/32" {
		t.Errorf("address = %q, want a masked address", rows[1][0])
	}
	// An entry in a source of truth must disclose that it was inferred.
	if !strings.Contains(rows[1][3], "tarsier") || !strings.Contains(rows[1][3], "confidence") {
		t.Errorf("description %q does not disclose that this was inferred", rows[1][3])
	}
	if !strings.Contains(rows[1][4], "Not verified by scanning") {
		t.Errorf("comments %q do not disclose the discovery method", rows[1][4])
	}
}

// TestNetBoxDNSNameIsSanitised covers the names that come off a real network.
// SMB and mDNS names routinely contain characters NetBox's dns_name rejects,
// and one bad row fails the whole import.
func TestNetBoxDNSNameIsSanitised(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"DESKTOP-K2P9", "desktop-k2p9"},
		{"printer.local.", "printer.local"},
		{"WORKGROUP\\PC01", "workgrouppc01"},
		{"my printer!", "myprinter"},
		{"", ""},
	} {
		if got := netboxDNSName(tc.in); got != tc.want {
			t.Errorf("netboxDNSName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
