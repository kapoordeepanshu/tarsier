package identify

import (
	"sort"
	"strings"
	"time"

	"tarsier/internal/eve"
)

// Resolver turns a stream of EVE records into a set of devices and findings.
//
// It is the core idea of the project: every event type Suricata emits carries a
// small statement about who is on the network. Individually those statements
// are weak. Accumulated across DHCP, ARP, DNS, TLS, HTTP, SMB, Kerberos, SSH,
// SNMP and flow records, they identify the device.
//
// Dispatch below covers every event type Suricata is known to emit. Types we do
// not interpret are still counted, and an event type that did not exist when
// this was written falls through to the default arm rather than being lost.
type Resolver struct {
	devices  map[string]*Device
	counts   map[string]int // events seen, per event_type
	findings []Finding
	seenFind map[string]bool

	// SensorHealth is populated from Suricata's own "stats" events.
	SensorHealth SensorHealth

	// policy is the declared segmentation, when one was supplied. Nil means
	// segmentation is not checked and costs nothing.
	policy *Policy

	// Window bounds which records are considered at all. Zero means unbounded.
	from, to time.Time
	// First and Last are the actual extent of the data that survived the
	// window, which is what the timeline is drawn against.
	First, Last time.Time
	// Filtered counts records rejected by the window, so the user can be told
	// their range excluded most of the capture rather than silently seeing less.
	Filtered int
}

// SetWindow restricts the resolver to events within a time range. Either bound
// may be zero for open-ended.
func (r *Resolver) SetWindow(from, to time.Time) {
	r.from, r.to = from, to
}

// SensorHealth reports what Suricata says about itself. A sensor dropping
// packets is silently producing an incomplete picture, which is worse than a
// sensor that is plainly offline.
type SensorHealth struct {
	Version         string
	Uptime          int
	PacketsCaptured int
	PacketsDropped  int
	Reported        bool
}

func NewResolver() *Resolver {
	return &Resolver{
		devices:  map[string]*Device{},
		counts:   map[string]int{},
		seenFind: map[string]bool{},
	}
}

func (r *Resolver) device(ip string) *Device {
	if ip == "" {
		return nil
	}
	d, ok := r.devices[ip]
	if !ok {
		d = newDevice(ip)
		r.devices[ip] = d
	}
	return d
}

// Add folds one EVE record into the model.
func (r *Resolver) Add(rec *eve.Record) {
	ts := rec.Timestamp()

	// Apply the window before anything else. Records without a usable timestamp
	// are kept: dropping them would silently lose data because of a parsing
	// quirk rather than because the user asked to exclude it.
	if !ts.IsZero() {
		if (!r.from.IsZero() && ts.Before(r.from)) || (!r.to.IsZero() && ts.After(r.to)) {
			r.Filtered++
			return
		}
		if r.First.IsZero() || ts.Before(r.First) {
			r.First = ts
		}
		if ts.After(r.Last) {
			r.Last = ts
		}
	}

	et := rec.Type()
	r.counts[et]++

	srcIP, destIP := rec.Str("src_ip"), rec.Str("dest_ip")

	// 802.1Q tags, present on any event when the sensor sees tagged traffic.
	// Suricata reports them as an array — nested for QinQ — so read them once
	// here rather than in every handler.
	vlans := vlanIDs(rec)

	// Touch both endpoints so first/last seen stays accurate even for event
	// types we do not otherwise interpret.
	for _, ip := range []string{srcIP, destIP} {
		if isPrivate(ip) {
			d := r.device(ip)
			d.seenAt(ts)
			for _, v := range vlans {
				d.VLANs[v] = true
			}
		}
	}

	// app_proto appears on most event types. Where Suricata positively
	// identified a protocol, trust it above any port number: it inspected the
	// traffic rather than guessing from a port.
	if ap := rec.Str("app_proto"); ap != "" && ap != "failed" && ap != "unknown" {
		if isPrivate(destIP) {
			d := r.device(destIP)
			d.Protocols[ap] = true
			if rule, ok := appProtoRules[ap]; ok {
				d.note("app_proto", ap, rule.Conclusion, rule.Weight)
			}
		}
		if isPrivate(srcIP) {
			r.device(srcIP).Protocols[ap] = true
		}
	}

	switch et {
	// --- identity: who is on the network -------------------------------
	case "dhcp":
		r.addDHCP(rec)
	case "arp":
		r.addARP(rec)
	case "dns", "doh2":
		r.addDNS(rec, et)

	// --- endpoints: what they run --------------------------------------
	case "http", "http2":
		r.addHTTP(rec, srcIP, destIP)
	case "tls":
		r.addTLS(rec, srcIP, destIP)
	case "quic":
		r.addQUIC(rec, srcIP, destIP)
	case "ssh":
		r.addSSH(rec, srcIP, destIP)
	case "rdp":
		r.addRDP(rec, srcIP, destIP)
	case "snmp":
		r.addSNMP(rec, destIP)
	case "rfb":
		r.addRFB(rec, destIP)
	case "websocket":
		r.markServer(destIP, "websocket", 0.3)

	// --- windows / directory -------------------------------------------
	case "smb":
		r.addSMB(rec, srcIP, destIP)
	case "krb5":
		r.addKerberos(rec, srcIP, destIP)
	case "ldap":
		r.addLDAP(rec, srcIP, destIP)
	case "dcerpc":
		r.addDCERPC(rec, srcIP, destIP)
	case "nfs":
		r.addNFS(rec, destIP)

	// --- servers and services ------------------------------------------
	case "smtp":
		r.addSMTP(rec, srcIP, destIP)
	case "pgsql":
		r.markServer(destIP, "postgresql", 0.8)
	case "sip":
		r.addSIP(rec, srcIP, destIP)
	case "mqtt":
		r.addMQTT(rec, srcIP, destIP)
	case "ike", "ikev2":
		r.markServer(destIP, "vpn", 0.6)

	// --- file transfer ---------------------------------------------------
	case "ftp", "ftp_data":
		r.addFTP(rec, srcIP, destIP)
	case "tftp":
		r.addTFTP(rec, destIP)
	case "fileinfo", "files":
		r.addFileInfo(rec, srcIP, destIP)

	// --- industrial / OT -------------------------------------------------
	case "modbus", "dnp3", "enip":
		r.addIndustrial(rec, srcIP, destIP, et)

	// --- security and policy ---------------------------------------------
	case "alert":
		r.addAlert(rec, srcIP, destIP)
	case "drop":
		if d := r.localDevice(srcIP, destIP); d != nil {
			d.Drops++
		}
	case "anomaly":
		if d := r.localDevice(srcIP, destIP); d != nil {
			d.Anomalies++
		}
	case "bittorrent-dht":
		r.addBitTorrent(srcIP)

	// --- topology ---------------------------------------------------------
	case "flow", "netflow":
		r.addFlow(rec, srcIP, destIP)

	// --- sensor itself ----------------------------------------------------
	case "stats":
		r.addStats(rec)

	// --- deliberately not interpreted -------------------------------------
	// "packet", "frame", "engine" and anything Suricata adds in a future
	// release land here. They are counted, never dropped. Because the original
	// line is retained upstream of this package, interpretation can be added
	// later and backfilled over history.
	default:
	}
}

// localDevice returns whichever endpoint is on the local network.
func (r *Resolver) localDevice(srcIP, destIP string) *Device {
	if isPrivate(srcIP) {
		return r.device(srcIP)
	}
	if isPrivate(destIP) {
		return r.device(destIP)
	}
	return nil
}

// markServer records that an address is offering a named service.
func (r *Resolver) markServer(ip, service string, weight float64) {
	if !isPrivate(ip) {
		return
	}
	d := r.device(ip)
	d.Protocols[service] = true
	d.note("service", service, "class=server", weight)
}

// Devices returns the resolved local devices, most-identified first.
func (r *Resolver) Devices() []*Device {
	out := make([]*Device, 0, len(r.devices))
	for _, d := range r.devices {
		if !isPrivate(d.IP) {
			continue
		}
		d.resolve()
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence() != out[j].Confidence() {
			return out[i].Confidence() > out[j].Confidence()
		}
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

// Prune forgets everything older than the cutoff and reports how many devices
// it dropped.
//
// A one-shot scan never needs this — it reads a file and exits. A watcher runs
// for months, and without a rolling window every device that ever appeared stays
// in the inventory forever, which turns "what is on my network" into "what has
// ever been on my network". Those are different questions and only one of them
// is useful.
//
// A device is forgotten only once it has been silent for the whole window. Its
// hourly activity is trimmed either way, because that is what the report draws
// its timeline from.
func (r *Resolver) Prune(before time.Time) int {
	if before.IsZero() {
		return 0
	}
	cutoffHour := before.Unix() / 3600

	dropped := 0
	for ip, d := range r.devices {
		if d.LastSeen.Before(before) {
			delete(r.devices, ip)
			dropped++
			continue
		}
		for h := range d.Activity {
			if h < cutoffHour {
				delete(d.Activity, h)
			}
		}
	}

	if dropped > 0 {
		// Findings outlive nothing. Clearing the dedup key as well means that if
		// the device comes back still broken, we say so again rather than
		// staying quiet because we mentioned it last month.
		kept := r.findings[:0]
		for _, f := range r.findings {
			if f.Device != "sensor" {
				if _, live := r.devices[f.Device]; !live {
					delete(r.seenFind, f.Device+"|"+f.Kind)
					continue
				}
			}
			kept = append(kept, f)
		}
		r.findings = kept
	}

	// The timeline starts at the window, not at the first thing we ever saw.
	if r.First.Before(before) {
		r.First = before
	}
	return dropped
}

// EventCounts reports how many of each EVE event type were seen. Used to tell a
// user that their Suricata is not logging the metadata we need — the most
// common reason this tool underperforms, and something they cannot otherwise
// discover for themselves.
func (r *Resolver) EventCounts() map[string]int { return r.counts }

// vlanIDs extracts 802.1Q tags. Suricata emits "vlan":[100] for a single tag
// and "vlan":[100,200] for QinQ. Tag 0 is not a real VLAN — it appears in stats
// counters and on untagged traffic — so it is skipped.
func vlanIDs(rec *eve.Record) []int {
	raw, ok := rec.Get("vlan").([]any)
	if !ok {
		return nil
	}
	var out []int
	for _, v := range raw {
		if f, ok := v.(float64); ok && f > 0 && f < 4096 {
			out = append(out, int(f))
		}
	}
	return out
}

// commonName pulls CN= out of a certificate subject.
func commonName(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return ""
}

func ipLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	if len(as) != 4 || len(bs) != 4 {
		return a < b
	}
	for i := 0; i < 4; i++ {
		x, y := atoi(as[i]), atoi(bs[i])
		if x != y {
			return x < y
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
