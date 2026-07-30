package identify

import (
	"strings"
	"testing"

	"tarsier/internal/eve"
)

// resolve runs a set of EVE lines through the resolver and returns the devices.
func resolve(t *testing.T, lines ...string) map[string]*Device {
	t.Helper()
	r := NewResolver()
	rd := eve.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	for rec := rd.Next(); rec != nil; rec = rd.Next() {
		r.Add(rec)
	}
	out := map[string]*Device{}
	for _, d := range r.Devices() {
		out[d.IP] = d
	}
	return out
}

// TestConfidenceDoesNotCompoundFromRepeatedSignals guards the bug that real
// data exposed: a host answering SMTP a thousand times told us one thing a
// thousand times, and the noisy-OR drove a single 0.7 signal to a displayed
// 100%. False certainty is the one failure this tool cannot afford.
func TestConfidenceDoesNotCompoundFromRepeatedSignals(t *testing.T) {
	line := `{"timestamp":"2026-07-30T09:00:00.000000+0000","event_type":"smtp",` +
		`"src_ip":"203.0.113.9","dest_ip":"10.0.0.5","dest_port":25,"proto":"TCP",` +
		`"smtp":{"helo":"kali"}}`

	one := resolve(t, line)
	many := resolve(t, repeat(line, 500)...)

	got1, gotN := one["10.0.0.5"].Confidence(), many["10.0.0.5"].Confidence()
	if got1 != gotN {
		t.Errorf("confidence changed with repetition: 1 event = %.3f, 500 events = %.3f", got1, gotN)
	}
	if gotN > 0.75 {
		t.Errorf("a single 0.7 signal reached %.3f; repeated sightings must not accumulate", gotN)
	}
}

// TestIndependentSignalsDoCombine is the other half: distinct evidence should
// still raise confidence, or the scoring would be useless.
func TestIndependentSignalsDoCombine(t *testing.T) {
	d := resolve(t,
		`{"event_type":"flow","src_ip":"10.0.0.7","dest_ip":"10.0.20.9","dest_port":502,"proto":"TCP","app_proto":"modbus"}`,
		`{"event_type":"dhcp","src_ip":"10.0.20.9","dest_ip":"10.0.0.1","dhcp":{"client_mac":"00:1d:9c:aa:31:07","assigned_ip":"10.0.20.9","hostname":"PLC-LINE-2"}}`,
	)["10.0.20.9"]

	if d == nil {
		t.Fatal("device not found")
	}
	if d.Class != ClassPLC {
		t.Errorf("Class = %q, want plc", d.Class)
	}
	if d.Confidence() < 0.9 {
		t.Errorf("confidence %.3f too low: modbus app_proto and port 502 are independent signals", d.Confidence())
	}
}

// TestSpecificOSBeatsGenericOS covers the second real bug: a DHCP vendor class
// of "MSFT 5.0" (weight 0.9, generic) was masking "Windows 7 (end of life)"
// from the user agent (weight 0.8, specific). The specific answer is the one
// worth reporting — an out-of-support machine is the finding.
func TestSpecificOSBeatsGenericOS(t *testing.T) {
	d := resolve(t,
		`{"event_type":"dhcp","src_ip":"10.0.1.20","dest_ip":"10.0.0.1","dhcp":{"client_mac":"00:15:5d:22:0e:91","assigned_ip":"10.0.1.20","hostname":"ACCTS-PC-04","vendor_class_identifier":"MSFT 5.0"}}`,
		`{"event_type":"http","src_ip":"10.0.1.20","dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","app_proto":"http","http":{"http_user_agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) Chrome/109.0"}}`,
	)["10.0.1.20"]

	if d == nil {
		t.Fatal("device not found")
	}
	if !strings.Contains(d.OS, "Windows 7") {
		t.Errorf("OS = %q, want the specific Windows 7 rather than a generic Windows", d.OS)
	}
}

// TestARPFindsStaticallyAddressedDevices covers the biggest blind spot in
// passive discovery: DHCP only reveals devices that ask for an address, so
// servers, printers and PLCs on static addresses are invisible without ARP.
func TestARPFindsStaticallyAddressedDevices(t *testing.T) {
	d := resolve(t,
		`{"event_type":"arp","src_ip":"10.0.0.1","dest_ip":"10.0.0.9","proto":"ARP",`+
			`"arp":{"opcode":"request","src_mac":"00:80:77:3a:1c:44","src_ip":"10.0.4.87",`+
			`"dest_mac":"00:00:00:00:00:00","dest_ip":"10.0.0.1"}}`,
	)["10.0.4.87"]

	if d == nil {
		t.Fatal("ARP did not produce a device; static-IP hosts would stay invisible")
	}
	if d.MAC != "00:80:77:3a:1c:44" {
		t.Errorf("MAC = %q, want the address from the ARP record", d.MAC)
	}
	if d.Vendor != "Brother" {
		t.Errorf("Vendor = %q, want Brother from the OUI", d.Vendor)
	}
}

// TestVLANsAreRecorded matters because without the tag, two devices reusing an
// address on different segments collapse into one, and any segmentation check
// is impossible.
func TestVLANsAreRecorded(t *testing.T) {
	d := resolve(t,
		`{"event_type":"flow","src_ip":"10.0.0.7","dest_ip":"10.0.0.42","dest_port":445,"proto":"TCP","vlan":[20]}`,
	)["10.0.0.42"]

	if d == nil {
		t.Fatal("device not found")
	}
	if got := d.SortedVLANs(); len(got) != 1 || got[0] != 20 {
		t.Errorf("VLANs = %v, want [20]", got)
	}
}

// TestVLANZeroIsIgnored — tag 0 appears in stats counters and on untagged
// traffic. Treating it as a real VLAN would put every device on "VLAN 0".
func TestVLANZeroIsIgnored(t *testing.T) {
	d := resolve(t,
		`{"event_type":"flow","src_ip":"10.0.0.7","dest_ip":"10.0.0.42","dest_port":445,"proto":"TCP","vlan":[0]}`,
	)["10.0.0.42"]

	if d != nil && len(d.VLANs) != 0 {
		t.Errorf("VLANs = %v, want none: tag 0 is not a VLAN", d.SortedVLANs())
	}
}

// TestPublicAddressesAreNotInventoried — external hosts are destinations, not
// assets. Inventorying the internet would make the device list meaningless.
func TestPublicAddressesAreNotInventoried(t *testing.T) {
	devices := resolve(t,
		`{"event_type":"flow","src_ip":"10.0.0.7","dest_ip":"142.250.187.206","dest_port":443,"proto":"TCP","app_proto":"tls"}`,
	)
	if _, found := devices["142.250.187.206"]; found {
		t.Error("a public address was inventoried as a local device")
	}
	if d := devices["10.0.0.7"]; d == nil || len(d.ExternalDsts) != 1 {
		t.Error("the external destination should still be recorded against the local device")
	}
}

// TestFindingsCarryAFix — a problem without a fix is homework, and homework
// gets ignored. Every finding must say what to do.
func TestFindingsCarryAFix(t *testing.T) {
	r := NewResolver()
	rd := eve.NewReader(strings.NewReader(strings.Join([]string{
		`{"event_type":"http","src_ip":"10.0.1.20","dest_ip":"93.184.216.34","dest_port":80,"proto":"TCP","app_proto":"http","http":{"http_user_agent":"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1)"}}`,
		`{"event_type":"smb","src_ip":"10.0.5.7","dest_ip":"10.0.0.42","dest_port":445,"proto":"TCP","app_proto":"smb","smb":{"dialect":"NT LM 0.12"}}`,
	}, "\n")))
	for rec := rd.Next(); rec != nil; rec = rd.Next() {
		r.Add(rec)
	}

	findings := r.Findings()
	if len(findings) == 0 {
		t.Fatal("expected findings for an end-of-life OS and SMBv1")
	}
	for _, f := range findings {
		if strings.TrimSpace(f.Fix) == "" {
			t.Errorf("finding %q has no Fix", f.Kind)
		}
		if strings.TrimSpace(f.Title) == "" || strings.TrimSpace(f.Detail) == "" {
			t.Errorf("finding %q is missing Title or Detail", f.Kind)
		}
	}
}

// TestFindingsAreDeduplicated — the same problem seen repeatedly is one entry
// with a count, not a wall of identical rows.
func TestFindingsAreDeduplicated(t *testing.T) {
	line := `{"event_type":"smb","src_ip":"10.0.5.7","dest_ip":"10.0.0.42","dest_port":445,"proto":"TCP","app_proto":"smb","smb":{"dialect":"NT LM 0.12"}}`
	r := NewResolver()
	rd := eve.NewReader(strings.NewReader(strings.Join(repeat(line, 50), "\n")))
	for rec := rd.Next(); rec != nil; rec = rd.Next() {
		r.Add(rec)
	}
	var smb int
	for _, f := range r.Findings() {
		if f.Kind == "smbv1" {
			smb++
			if f.Count != 50 {
				t.Errorf("Count = %d, want 50", f.Count)
			}
		}
	}
	if smb != 1 {
		t.Errorf("got %d smbv1 findings, want exactly 1", smb)
	}
}

// TestEvidenceIsAlwaysPresent — an identification a user cannot audit is one
// they will not trust, and checking the working is the first thing a competent
// operator does.
func TestEvidenceIsAlwaysPresent(t *testing.T) {
	d := resolve(t,
		`{"event_type":"dhcp","src_ip":"10.0.4.87","dest_ip":"10.0.0.1","dhcp":{"client_mac":"00:80:77:3a:1c:44","assigned_ip":"10.0.4.87","hostname":"BRN3A1C44","vendor_class_identifier":"Brother NC-8000w"}}`,
	)["10.0.4.87"]

	if d == nil || d.Class == ClassUnknown {
		t.Fatal("device not identified")
	}
	if len(d.Evidence) == 0 {
		t.Fatal("device identified with no evidence recorded")
	}
	for _, e := range d.Evidence {
		if e.Signal == "" || e.Conclusion == "" || e.Weight <= 0 {
			t.Errorf("incomplete evidence entry: %+v", e)
		}
	}
}

func repeat(line string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = line
	}
	return out
}
