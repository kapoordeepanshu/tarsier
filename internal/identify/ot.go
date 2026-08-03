package identify

import (
	"strings"

	"tarsier/internal/eve"
)

// Industrial control system identity.
//
// This is where passive discovery stops being a convenience and starts being
// the only option. NIST SP 800-82 Rev.3 §6.2.1 cautions against active scanning
// on live ICS networks for good reason: probe traffic can overwhelm an older
// PLC's network stack, corrupt memory on some legacy RTUs, and trip
// safety-critical logic. Meanwhile IEC 62443-3-2 §4.2 still expects an asset
// inventory carrying device type, vendor, model, firmware version, protocols in
// use and communication patterns.
//
// Those two facts together describe a gap that only passive observation can
// fill, and industrial protocols fill it unusually well. An EtherNet/IP List
// Identity response is a device volunteering its vendor, product name, firmware
// revision and serial number in one unauthenticated, unencrypted reply. No
// equivalent exists anywhere in IT: a Windows workstation will not tell you its
// build number for asking.

// addOTIdentity extracts everything an industrial protocol states outright
// about the device that spoke it.
func (r *Resolver) addOTIdentity(rec *eve.Record, d *Device, proto string) {
	if d == nil {
		return
	}
	switch proto {
	case "enip":
		r.addENIPIdentity(rec, d)
	case "dnp3":
		addDNP3Identity(rec, d)
	case "modbus":
		addModbusIdentity(rec, d)
	}
}

// addENIPIdentity reads an EtherNet/IP List Identity block.
//
// This single message answers most of what an OT asset inventory is required to
// record. Suricata nests it under request or response depending on direction,
// and older builds logged it unnested, so all three shapes are accepted — the
// cost of guessing wrong here is losing the best data on the network.
func (r *Resolver) addENIPIdentity(rec *eve.Record, d *Device) {
	get := func(field string) string {
		return rec.FirstStr(
			"enip.response.identity."+field,
			"enip.request.identity."+field,
			"enip.identity."+field,
		)
	}

	// The product name is a free-text string the device chose for itself, such
	// as "1756-L71/B LOGIX5571". It is worth more than any lookup table.
	if name := strings.TrimSpace(get("product_name")); name != "" {
		d.setLatest("model", &d.Model, name, rec.Timestamp())
		d.noteSpec("enip.identity.product_name", name, "class=plc", 0.95, 2)
		// Product names carry the vendor often enough to be worth checking
		// against the banner table, which already knows the major ICS vendors.
		applySubstringRules(d, "enip.identity.product_name", name, serverBanners)
		applySubstringRules(d, "enip.identity.product_name", name, dhcpVendorClassSecondary)
	}

	if rev := strings.TrimSpace(get("revision")); rev != "" {
		d.setLatest("firmware", &d.Firmware, rev, rec.Timestamp())
		d.note("enip.identity.revision", rev, "class=plc", 0.6)
	}
	if serial := strings.TrimSpace(get("serial")); serial != "" {
		d.setLatest("serial", &d.Serial, serial, rec.Timestamp())
	}

	// vendor_id is an ODVA-assigned number. Only translate the ones we can
	// state with confidence; an unknown ID is recorded as a number rather than
	// guessed at, because a wrong vendor on an OT inventory is worse than none.
	if vid := rec.FirstInt(
		"enip.response.identity.vendor_id",
		"enip.request.identity.vendor_id",
		"enip.identity.vendor_id",
	); vid > 0 {
		if name, ok := cipVendors[vid]; ok {
			d.note("enip.identity.vendor_id", itoa(vid), "vendor="+name, 0.9)
			applySubstringRules(d, "enip.identity.vendor", name, vendorClass)
		} else {
			d.OTIdentifiers["EtherNet/IP vendor ID "+itoa(vid)] = true
		}
	}

	if dt := rec.FirstInt(
		"enip.response.identity.device_type",
		"enip.request.identity.device_type",
		"enip.identity.device_type",
	); dt > 0 {
		if name, ok := cipDeviceTypes[dt]; ok {
			d.OTIdentifiers["EtherNet/IP device type: "+name] = true
		}
	}
}

// addDNP3Identity records outstation addressing.
//
// DNP3 carries its own address space, independent of IP. Engineers refer to a
// device by its outstation number, so an inventory that lists only IP addresses
// is one the people who actually run the plant cannot cross-reference against
// their own documentation.
func addDNP3Identity(rec *eve.Record, d *Device) {
	// The outstation is whichever end is not the master. Suricata logs both
	// addresses on every record, so record the pair as seen and let the report
	// present it; inferring which is which from one frame is not reliable.
	if src := rec.FirstInt("dnp3.src", "dnp3.request.src", "dnp3.response.src"); src > 0 {
		d.OTIdentifiers["DNP3 address "+itoa(src)] = true
	}
	if dst := rec.FirstInt("dnp3.dst", "dnp3.request.dst", "dnp3.response.dst"); dst > 0 {
		d.OTIdentifiers["DNP3 address "+itoa(dst)] = true
	}
}

// addModbusIdentity records the unit ID.
//
// One IP address routinely fronts many Modbus units — a gateway bridging a
// serial loop presents each slave under a different unit ID on the same socket.
// Without this, a dozen physical devices are inventoried as one.
func addModbusIdentity(rec *eve.Record, d *Device) {
	unit := rec.FirstInt(
		"modbus.request.unit_id",
		"modbus.response.unit_id",
		"modbus.unit_id",
	)
	// Unit 0 is the broadcast address, not a device.
	if unit > 0 {
		d.OTIdentifiers["Modbus unit "+itoa(unit)] = true
	}
}

// cipVendors maps ODVA vendor IDs to names.
//
// Deliberately tiny. The full list is ODVA's to publish and this table is not
// the place to reproduce it from memory: a confidently wrong vendor on a
// control-system inventory is exactly the kind of error that survives into an
// audit document. Entries here are ones that can be stated without doubt;
// everything else is reported as its numeric ID, which an engineer can look up.
var cipVendors = map[int]string{
	1: "Rockwell Automation/Allen-Bradley",
}

// cipDeviceTypes maps the CIP device profile number to its name. These are
// fixed by the CIP specification rather than vendor-assigned.
var cipDeviceTypes = map[int]string{
	0x00: "Generic device",
	0x02: "AC drive",
	0x03: "Motor overload protection",
	0x04: "Limit switch",
	0x05: "Inductive proximity switch",
	0x06: "Photoelectric sensor",
	0x07: "General purpose discrete I/O",
	0x09: "Resolver",
	0x0C: "Communications adapter",
	0x0E: "Programmable logic controller",
	0x10: "Position controller",
	0x13: "DC drive",
	0x15: "Contactor",
	0x16: "Motor starter",
	0x17: "Soft start",
	0x18: "Human-machine interface",
	0x1A: "Mass flow controller",
	0x1B: "Pneumatic valve",
	0x1C: "Vacuum pressure gauge",
	0x1D: "Process control value",
	0x1E: "Residual gas analyser",
	0x1F: "DC power generator",
	0x20: "RF power generator",
	0x21: "Turbomolecular vacuum pump",
	0x22: "Encoder",
	0x23: "Safety discrete I/O device",
	0x24: "Fluid flow controller",
	0x25: "CIP motion drive",
	0x26: "CompoNet repeater",
	0x2A: "CIP modbus device",
	0x2B: "CIP modbus translator",
	0x2C: "Safety analog I/O device",
	0x32: "ControlNet physical layer component",
}
