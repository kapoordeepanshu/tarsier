package identify

import (
	"net"
	"sort"
	"time"
)

// Class is a coarse device category. Deliberately small: a category nobody can
// act on is worse than none.
type Class string

const (
	ClassUnknown     Class = ""
	ClassWorkstation Class = "workstation"
	ClassServer      Class = "server"
	ClassPrinter     Class = "printer"
	ClassCamera      Class = "camera"
	ClassPhone       Class = "phone"
	ClassMobile      Class = "mobile"
	ClassNetworkGear Class = "network"
	ClassNAS         Class = "nas"
	ClassPLC         Class = "plc"
	ClassVM          Class = "vm"
	ClassIoT         Class = "iot"
)

// Evidence is one observation that supported a conclusion.
//
// Every conclusion carries its evidence. An identification a user cannot audit
// is one they will not trust, and the first thing a competent operator does
// with a tool like this is check its work.
type Evidence struct {
	Signal     string  // where it came from, e.g. "dhcp.vendor_class_identifier"
	Value      string  // what was observed
	Conclusion string  // what it implied, e.g. "os=Windows"
	Weight     float64 // 0..1, how much this observation is worth on its own
}

// Service is a port a device was observed answering on.
type Service struct {
	Port     int
	Proto    string // tcp/udp
	AppProto string // Suricata's app_proto, when it identified one
	Hits     int
}

// Device is one resolved thing on the network.
type Device struct {
	IP  string
	MAC string
	// RandomMAC records that the observed address had the locally-administered
	// bit set, i.e. the device generated it rather than inheriting it from its
	// manufacturer. Worth surfacing rather than hiding: it means this entry
	// cannot be correlated with the same device tomorrow, which is a real limit
	// on the inventory rather than a detail of the parser.
	RandomMAC bool

	Hostnames map[string]bool // every name seen for it, from any source
	Users     map[string]bool // usernames observed authenticating from it
	Services  map[int]*Service

	Vendor string
	Class  Class
	OS     string
	Model  string

	// Firmware and Serial are populated where a protocol states them outright.
	// In practice that means industrial equipment: IEC 62443-3-2 asks for device
	// type, vendor, model, firmware version and protocols in use, and an
	// EtherNet/IP List Identity response hands over four of the five unprompted.
	// Nothing on the IT side of a network is anywhere near this forthcoming.
	Firmware string
	Serial   string

	// OTIdentifiers holds protocol-level station addresses — a DNP3 outstation
	// number, a Modbus unit ID. On a control network these, not the IP address,
	// are how engineers refer to a device, so an inventory that omits them is
	// one the people who run the plant cannot cross-reference.
	OTIdentifiers map[string]bool

	JA3 map[string]bool // client TLS fingerprints
	JA4 map[string]bool

	// VLANs this device was seen on. Suricata reports 802.1Q tags as an array,
	// nested for QinQ. Without this a device on VLAN 20 and a different device
	// reusing the same address on VLAN 30 collapse into one entry — and any
	// segmentation check is impossible, because "which segment" is the question.
	VLANs map[int]bool

	Protocols map[string]bool // application protocols observed on this device
	Certs     []Cert          // certificates it presented
	Shares    map[string]bool // SMB/NFS shares it exposed
	Files     int             // file transfers observed

	FirstSeen time.Time
	LastSeen  time.Time
	// Activity counts events per hour, keyed by Unix hour. It drives the
	// per-device sparkline and time filtering. A device that appears for ten
	// minutes at 3am looks nothing like one that hums along all day, and that
	// shape is often the whole story.
	Activity map[int64]int

	Alerts       int
	Drops        int             // IPS blocks, when Suricata runs inline
	Anomalies    int             // protocol/decoder anomalies
	ExternalDsts map[string]bool // external IPs it contacted

	Evidence []Evidence

	// weights accumulates evidence per conclusion ("class=printer") so that
	// several weak signals can combine into a strong one.
	weights map[string]float64
	// specificity records how precise each conclusion is. "Windows" and
	// "Windows 7" are not competing answers — one refines the other — so a
	// more specific conclusion wins even when a vaguer one scored higher.
	specificity map[string]int
	// latest remembers when each single-valued field was last observed, so an
	// older record cannot overwrite a newer one.
	//
	// Records do not arrive in order and cannot be made to. A directory of
	// rotated logs sorts lexically, which reads the live eve.json first and
	// eve.json.10 before eve.json.2; a watcher catching up after downtime
	// replays old files after new ones. Without this, a PLC whose firmware
	// moved on Tuesday reports Monday's version depending on read order — the
	// exact change this tool is meant to notice.
	latest map[string]time.Time
	// seen deduplicates evidence before it is combined.
	//
	// Observing the same signal repeatedly is not new information. A host that
	// answers SMTP a thousand times has told us one thing a thousand times, and
	// compounding that through the noisy-OR drives a single 0.7 signal to a
	// displayed 100% — which is exactly the false certainty this tool exists to
	// avoid. Only the first sighting of a given signal/value/conclusion counts.
	seen map[string]bool
}

// Cert is a certificate a device presented, kept for expiry and hygiene checks.
type Cert struct {
	Subject  string
	Issuer   string
	NotAfter string
	Version  string
}

func newDevice(ip string) *Device {
	return &Device{
		IP:            ip,
		Hostnames:     map[string]bool{},
		Users:         map[string]bool{},
		OTIdentifiers: map[string]bool{},
		Services:      map[int]*Service{},
		JA3:           map[string]bool{},
		JA4:           map[string]bool{},
		VLANs:         map[int]bool{},
		Protocols:     map[string]bool{},
		Shares:        map[string]bool{},
		Activity:      map[int64]int{},
		ExternalDsts:  map[string]bool{},
		weights:       map[string]float64{},
		specificity:   map[string]int{},
		latest:        map[string]time.Time{},
		seen:          map[string]bool{},
	}
}

// setLatest assigns a single-valued field only if this observation is at least
// as recent as the one that set it, and says whether it did.
//
// Records with no usable timestamp fall back to last-write-wins among
// themselves, but never displace a value that came with one.
func (d *Device) setLatest(key string, field *string, value string, t time.Time) bool {
	if value == "" {
		return false
	}
	if prev, ok := d.latest[key]; ok && t.Before(prev) {
		return false
	}
	*field = value
	d.latest[key] = t
	return true
}

// SortedVLANs lists the 802.1Q tags this device was seen on, lowest first.
func (d *Device) SortedVLANs() []int {
	out := make([]int, 0, len(d.VLANs))
	for v := range d.VLANs {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// SortedProtocols lists the application protocols seen on this device.
func (d *Device) SortedProtocols() []string { return sortedKeys(d.Protocols) }

// SortedShares lists exposed file shares.
func (d *Device) SortedShares() []string { return sortedKeys(d.Shares) }

func (d *Device) seenAt(t time.Time) {
	if t.IsZero() {
		return
	}
	if d.FirstSeen.IsZero() || t.Before(d.FirstSeen) {
		d.FirstSeen = t
	}
	if t.After(d.LastSeen) {
		d.LastSeen = t
	}
	d.Activity[t.Unix()/3600]++
}

// ActiveBetween reports whether the device was seen in the window. Used by the
// time filter; a zero time on either side means unbounded.
func (d *Device) ActiveBetween(from, to time.Time) bool {
	if !from.IsZero() && d.LastSeen.Before(from) {
		return false
	}
	if !to.IsZero() && d.FirstSeen.After(to) {
		return false
	}
	return true
}

// note records an observation and folds its weight into the matching conclusion.
//
// Weights combine as noisy-OR: 1 - Π(1-w). Two independent 0.5 signals give
// 0.75, not 1.0. Nothing ever reaches certainty from accumulation alone, which
// is the honest behaviour — passive identification is inference, not proof.
func (d *Device) note(signal, value, conclusion string, weight float64) {
	d.noteSpec(signal, value, conclusion, weight, 1)
}

// noteSpec is note with an explicit specificity level. Higher wins ties of
// meaning: "Windows 7 (end of life)" (2) beats "Windows" (1) regardless of
// weight, because the vaguer answer is not wrong, merely less useful.
func (d *Device) noteSpec(signal, value, conclusion string, weight float64, spec int) {
	if conclusion == "" || weight <= 0 {
		return
	}
	// The same observation, seen again, is not additional evidence.
	key := signal + "\x00" + value + "\x00" + conclusion
	if d.seen[key] {
		return
	}
	d.seen[key] = true

	d.Evidence = append(d.Evidence, Evidence{
		Signal: signal, Value: value, Conclusion: conclusion, Weight: weight,
	})
	prev := d.weights[conclusion]
	d.weights[conclusion] = prev + weight*(1-prev)
	if spec > d.specificity[conclusion] {
		d.specificity[conclusion] = spec
	}
}

func (d *Device) addHostname(name string) {
	if name = normaliseHostname(name); name != "" {
		d.Hostnames[name] = true
	}
}

func (d *Device) addService(port int, proto, appProto string) {
	if port <= 0 {
		return
	}
	s, ok := d.Services[port]
	if !ok {
		s = &Service{Port: port, Proto: proto}
		d.Services[port] = s
	}
	s.Hits++
	if appProto != "" && appProto != "failed" && appProto != "unknown" {
		s.AppProto = appProto
	}
}

// Confidence is the weight behind the winning class conclusion.
func (d *Device) Confidence() float64 {
	if d.Class == ClassUnknown {
		return 0
	}
	return d.weights["class="+string(d.Class)]
}

// resolve picks the winning conclusions once all evidence is in.
func (d *Device) resolve() {
	bestClass, bestClassW := ClassUnknown, 0.0
	bestOS, bestOSW, bestOSSpec := "", 0.0, 0
	bestVendor, bestVendorW := "", 0.0

	for k, w := range d.weights {
		switch {
		case len(k) > 6 && k[:6] == "class=":
			if w > bestClassW {
				bestClass, bestClassW = Class(k[6:]), w
			}
		case len(k) > 3 && k[:3] == "os=":
			// Specificity first, weight only as the tiebreak.
			spec := d.specificity[k]
			if spec > bestOSSpec || (spec == bestOSSpec && w > bestOSW) {
				bestOS, bestOSW, bestOSSpec = k[3:], w, spec
			}
		case len(k) > 7 && k[:7] == "vendor=":
			if w > bestVendorW {
				bestVendor, bestVendorW = k[7:], w
			}
		}
	}
	d.Class, d.OS = bestClass, bestOS
	if d.Vendor == "" {
		d.Vendor = bestVendor
	}
}

// BestHostname returns the most useful name, preferring real hostnames over
// mDNS-style names ending in .local.
func (d *Device) BestHostname() string {
	names := d.SortedHostnames()
	for _, n := range names {
		if len(n) < 6 || n[len(n)-6:] != ".local" {
			return n
		}
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

func (d *Device) SortedHostnames() []string { return sortedKeys(d.Hostnames) }
func (d *Device) SortedUsers() []string     { return sortedKeys(d.Users) }

// SortedOTIdentifiers lists protocol-level station addresses.
func (d *Device) SortedOTIdentifiers() []string { return sortedKeys(d.OTIdentifiers) }

// SortedServices lists observed listening ports, lowest first.
func (d *Device) SortedServices() []*Service {
	out := make([]*Service, 0, len(d.Services))
	for _, s := range d.Services {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// IsExternal reports whether the device only ever appeared as a remote address.
func (d *Device) IsExternal() bool { return !isPrivate(d.IP) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isPrivate reports whether an address is in RFC1918 / RFC4193 / link-local
// space. Used to decide what counts as "on the network" versus "out there".
func isPrivate(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return ip.IsPrivate()
}
