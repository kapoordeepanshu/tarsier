package identify

import (
	"strings"
	"testing"

	"tarsier/internal/eve"
)

// feed runs EVE lines through an existing resolver, for tests that need to
// inspect findings rather than devices.
func feed(t *testing.T, r *Resolver, lines ...string) {
	t.Helper()
	rd := eve.NewReader(strings.NewReader(strings.Join(lines, "\n")))
	for rec := rd.Next(); rec != nil; rec = rd.Next() {
		r.Add(rec)
	}
}

// TestENIPIdentityFillsTheInventoryFields is the OT case that matters most.
// IEC 62443-3-2 asks for vendor, model and firmware version; an EtherNet/IP
// List Identity reply volunteers all three, unauthenticated, to anyone watching
// the wire — which is the only way to collect them on a network where active
// scanning is not permitted.
func TestENIPIdentityFillsTheInventoryFields(t *testing.T) {
	d := resolve(t,
		`{"event_type":"enip","src_ip":"10.20.0.50","dest_ip":"10.20.0.9","dest_port":44818,`+
			`"proto":"TCP","app_proto":"enip","enip":{"response":{"identity":{`+
			`"product_name":"1756-L71/B LOGIX5571","revision":"20.011","vendor_id":1,`+
			`"device_type":14,"serial":"0x00a1b2c3","protocol_version":1}}}}`,
	)["10.20.0.50"]

	if d == nil {
		t.Fatal("device not found")
	}
	if d.Model != "1756-L71/B LOGIX5571" {
		t.Errorf("Model = %q, want the product name from the identity block", d.Model)
	}
	if d.Firmware != "20.011" {
		t.Errorf("Firmware = %q, want the revision from the identity block", d.Firmware)
	}
	if d.Serial != "0x00a1b2c3" {
		t.Errorf("Serial = %q, want the serial from the identity block", d.Serial)
	}
	if d.Vendor != "Rockwell Automation/Allen-Bradley" {
		t.Errorf("Vendor = %q, want the ODVA vendor for ID 1", d.Vendor)
	}
	if d.Class != ClassPLC {
		t.Errorf("Class = %q, want plc", d.Class)
	}
	if !d.OTIdentifiers["EtherNet/IP device type: Programmable logic controller"] {
		t.Errorf("device type 14 not recorded; got %v", d.SortedOTIdentifiers())
	}
}

// TestENIPUnknownVendorIsNotGuessed guards the rule that keeps an OT inventory
// usable in an audit: an ODVA vendor ID we cannot resolve is reported as a
// number for an engineer to look up, never as a plausible-sounding name.
func TestENIPUnknownVendorIsNotGuessed(t *testing.T) {
	d := resolve(t,
		`{"event_type":"enip","src_ip":"10.20.0.51","dest_ip":"10.20.0.9","dest_port":44818,`+
			`"proto":"TCP","app_proto":"enip","enip":{"response":{"identity":{"vendor_id":9999}}}}`,
	)["10.20.0.51"]

	if d == nil {
		t.Fatal("device not found")
	}
	if d.Vendor != "" {
		t.Errorf("Vendor = %q, want none: ODVA vendor 9999 is not in the table", d.Vendor)
	}
	if !d.OTIdentifiers["EtherNet/IP vendor ID 9999"] {
		t.Errorf("unknown vendor ID not recorded for lookup; got %v", d.SortedOTIdentifiers())
	}
}

// TestModbusUnitIDsAreSeparateIdentities covers the gateway case: one IP
// address routinely fronts a whole serial loop, each slave answering under a
// different unit ID. Without this a dozen physical devices are inventoried as
// one, and the count an auditor is given is simply wrong.
func TestModbusUnitIDsAreSeparateIdentities(t *testing.T) {
	d := resolve(t,
		`{"event_type":"modbus","src_ip":"10.20.1.5","dest_ip":"10.20.1.80","dest_port":502,`+
			`"proto":"TCP","app_proto":"modbus","modbus":{"id":1,"request":{"unit_id":3,"function_code":3}}}`,
		`{"event_type":"modbus","src_ip":"10.20.1.5","dest_ip":"10.20.1.80","dest_port":502,`+
			`"proto":"TCP","app_proto":"modbus","modbus":{"id":2,"request":{"unit_id":7,"function_code":3}}}`,
		`{"event_type":"modbus","src_ip":"10.20.1.5","dest_ip":"10.20.1.80","dest_port":502,`+
			`"proto":"TCP","app_proto":"modbus","modbus":{"id":3,"request":{"unit_id":0,"function_code":3}}}`,
	)["10.20.1.80"]

	if d == nil {
		t.Fatal("device not found")
	}
	if !d.OTIdentifiers["Modbus unit 3"] || !d.OTIdentifiers["Modbus unit 7"] {
		t.Errorf("unit IDs not recorded; got %v", d.SortedOTIdentifiers())
	}
	// Unit 0 is the Modbus broadcast address, not a device on the loop.
	if d.OTIdentifiers["Modbus unit 0"] {
		t.Error("unit 0 recorded as a device; it is the broadcast address")
	}
}

// TestDNP3AddressesAreRecorded covers the cross-reference problem: engineers
// identify an outstation by its DNP3 address, not its IP, so an inventory
// without it cannot be matched against the plant's own documentation.
func TestDNP3AddressesAreRecorded(t *testing.T) {
	d := resolve(t,
		`{"event_type":"dnp3","src_ip":"10.20.2.4","dest_ip":"10.20.2.30","dest_port":20000,`+
			`"proto":"TCP","app_proto":"dnp3","dnp3":{"type":"request","src":1,"dst":10,`+
			`"application":{"function_code":1}}}`,
	)["10.20.2.30"]

	if d == nil {
		t.Fatal("device not found")
	}
	if !d.OTIdentifiers["DNP3 address 1"] || !d.OTIdentifiers["DNP3 address 10"] {
		t.Errorf("DNP3 addresses not recorded; got %v", d.SortedOTIdentifiers())
	}
	if d.Class != ClassPLC {
		t.Errorf("Class = %q, want plc", d.Class)
	}
}

// TestIndustrialExposureIsCritical keeps the existing guarantee intact: these
// protocols have no authentication at all, so reachability from outside the
// control network is the most serious thing this tool can report.
func TestIndustrialExposureIsCritical(t *testing.T) {
	r := NewResolver()
	feed(t, r,
		`{"event_type":"flow","src_ip":"203.0.113.7","dest_ip":"10.20.0.50","dest_port":502,`+
			`"proto":"TCP","app_proto":"modbus"}`,
	)

	var found bool
	for _, f := range r.Findings() {
		if f.Kind == "ot-exposed" && f.Severity == SevCritical {
			found = true
		}
	}
	if !found {
		t.Error("no critical ot-exposed finding for Modbus reached from a public address")
	}
}

// TestNewestObservationWins is the rotated-log case.
//
// A directory of rotated logs sorts lexically, so the live eve.json is read
// before eve.json.1 and the oldest records land last. Firmware, model, serial
// and MAC used to be plain assignments, which meant whichever file happened to
// be read last decided the answer. Reading the same two events in either order
// has to give the same device.
func TestNewestObservationWins(t *testing.T) {
	monday := `{"timestamp":"2026-07-27T09:00:00.000000+0000","event_type":"enip",` +
		`"src_ip":"10.20.0.50","dest_ip":"10.20.0.9","dest_port":44818,"proto":"TCP",` +
		`"app_proto":"enip","enip":{"response":{"identity":{` +
		`"product_name":"1756-L71/B LOGIX5571","revision":"20.011","serial":"0x00a1b2c3"}}}}`
	tuesday := `{"timestamp":"2026-07-28T09:00:00.000000+0000","event_type":"enip",` +
		`"src_ip":"10.20.0.50","dest_ip":"10.20.0.9","dest_port":44818,"proto":"TCP",` +
		`"app_proto":"enip","enip":{"response":{"identity":{` +
		`"product_name":"1756-L71/B LOGIX5571","revision":"21.004","serial":"0x00a1b2c3"}}}}`

	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"in order", []string{monday, tuesday}},
		{"newest file first", []string{tuesday, monday}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := resolve(t, tc.lines...)["10.20.0.50"]
			if d == nil {
				t.Fatal("device not found")
			}
			if d.Firmware != "21.004" {
				t.Errorf("Firmware = %q, want Tuesday's 21.004 whichever order it was read in",
					d.Firmware)
			}
		})
	}
}

// TestNewestMACWins covers the same problem on a DHCP lease that moved to a
// different machine. The address we report has to be the one seen most
// recently, not the one in whichever file was parsed last.
func TestNewestMACWins(t *testing.T) {
	old := `{"timestamp":"2026-07-27T09:00:00.000000+0000","event_type":"dhcp",` +
		`"src_ip":"10.0.0.5","dest_ip":"10.0.0.1","dhcp":{"assigned_ip":"10.0.0.5",` +
		`"client_mac":"00:1b:21:aa:bb:cc","dhcp_type":"ack"}}`
	recent := `{"timestamp":"2026-07-28T09:00:00.000000+0000","event_type":"dhcp",` +
		`"src_ip":"10.0.0.5","dest_ip":"10.0.0.1","dhcp":{"assigned_ip":"10.0.0.5",` +
		`"client_mac":"3c:22:fb:11:22:33","dhcp_type":"ack"}}`

	for _, lines := range [][]string{{old, recent}, {recent, old}} {
		d := resolve(t, lines...)["10.0.0.5"]
		if d == nil {
			t.Fatal("device not found")
		}
		if d.MAC != "3c:22:fb:11:22:33" {
			t.Errorf("MAC = %q, want the most recently observed address", d.MAC)
		}
	}
}
