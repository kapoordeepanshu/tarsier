package identify

import (
	"strings"
)

// This file is the seed of the open device fingerprint database.
//
// It is deliberately plain data. The intent is that it moves out to its own
// public-domain repository and grows by contribution, because the mapping from
// observable signals to device identity is the part of this problem that no
// open dataset covers today. Keep entries evidence-based and keep the weights
// honest: a signal that is merely suggestive should not be scored as proof.
//
// Weights, roughly:
//   0.9  the device effectively announced what it is
//   0.7  a strong, rarely-wrong indicator
//   0.5  a good indicator with known false positives
//   0.3  suggestive only, meant to combine with others

// ---------------------------------------------------------------------------
// MAC OUI -> vendor
// ---------------------------------------------------------------------------

// ouiVendors is a starter set, not the real registry. Before release this
// should be replaced by the full IEEE OUI assignment list (a public download)
// compiled into the binary. The virtualisation prefixes below are the most
// immediately useful: they separate real hardware from virtual machines.
var ouiVendors = map[string]string{
	// Virtualisation — high confidence, high value
	"00:50:56": "VMware",
	"00:0C:29": "VMware",
	"00:05:69": "VMware",
	"00:1C:14": "VMware",
	"08:00:27": "VirtualBox",
	"0A:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",
	"00:15:5D": "Microsoft Hyper-V",
	"00:16:3E": "Xen",

	// Single-board computers
	"B8:27:EB": "Raspberry Pi",
	"DC:A6:32": "Raspberry Pi",
	"E4:5F:01": "Raspberry Pi",
	"28:CD:C1": "Raspberry Pi",

	// Printers
	"00:80:77": "Brother",
	"00:00:48": "Seiko Epson",
	"00:26:AB": "Seiko Epson",

	// Telephony
	"00:04:F2": "Polycom",
}

// ouiClass maps a vendor to a class where the vendor implies one.
var ouiClass = map[string]Class{
	"VMware":            ClassVM,
	"VirtualBox":        ClassVM,
	"QEMU/KVM":          ClassVM,
	"Microsoft Hyper-V": ClassVM,
	"Xen":               ClassVM,
	"Brother":           ClassPrinter,
	"Seiko Epson":       ClassPrinter,
	"Polycom":           ClassPhone,
}

func lookupOUI(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	return ouiVendors[strings.ToUpper(mac[:8])]
}

// ---------------------------------------------------------------------------
// DHCP vendor class identifier (option 60)
// ---------------------------------------------------------------------------

// The single best passive signal available: the device states what it is,
// unprompted, the moment it joins the network.
type substringRule struct {
	Match      string // lowercase substring
	Conclusion string // "os=Windows", "class=printer", "vendor=HP"
	Weight     float64
	// Spec is how precise this answer is; 0 is treated as 1. Use 2 for a
	// conclusion that refines a vaguer one ("Windows 7" over "Windows") so the
	// specific answer wins even against a higher-weighted generic signal.
	Spec int
}

var dhcpVendorClass = []substringRule{
	{"msft 5.0", "os=Windows", 0.9, 1},
	{"msft 98", "os=Windows (legacy)", 0.9, 1},
	{"android-dhcp", "os=Android", 0.9, 2},
	{"dhcpcd", "os=Linux", 0.6, 1},
	{"udhcp", "os=Embedded Linux", 0.6, 1},
	{"pxeclient", "class=workstation", 0.4, 1},
	{"jetdirect", "class=printer", 0.95, 1},
	{"hewlett-packard", "vendor=HP", 0.8, 1},
	{"epson", "vendor=Seiko Epson", 0.9, 1},
	{"brother", "vendor=Brother", 0.9, 1},
	{"canon", "vendor=Canon", 0.9, 1},
	{"lexmark", "vendor=Lexmark", 0.9, 1},
	{"ip phone", "class=phone", 0.9, 1},
	{"polycom", "class=phone", 0.9, 1},
	{"yealink", "class=phone", 0.9, 1},
	{"ubnt", "class=network", 0.8, 1},
	{"ubiquiti", "class=network", 0.8, 1},
	{"mikrotik", "class=network", 0.9, 1},
	{"cisco", "vendor=Cisco", 0.7, 1},
	{"vmware", "class=vm", 0.9, 1},
	{"axis", "class=camera", 0.8, 1},
	{"hikvision", "class=camera", 0.9, 1},
	{"dahua", "class=camera", 0.9, 1},
}

// Vendor class strings that also imply a class.
var dhcpVendorClassSecondary = []substringRule{
	{"jetdirect", "vendor=HP", 0.9, 1},
	{"epson", "class=printer", 0.8, 1},
	{"brother", "class=printer", 0.8, 1},
	{"canon", "class=printer", 0.7, 1},
	{"lexmark", "class=printer", 0.8, 1},
	{"mikrotik", "vendor=MikroTik", 0.9, 1},
	{"ubiquiti", "vendor=Ubiquiti", 0.9, 1},
	{"hikvision", "vendor=Hikvision", 0.9, 1},
	{"dahua", "vendor=Dahua", 0.9, 1},
	{"axis", "vendor=Axis", 0.8, 1},
}

// ---------------------------------------------------------------------------
// HTTP User-Agent
// ---------------------------------------------------------------------------

// Version-specific operating systems are marked Spec:2 — an out-of-support
// Windows box is one of the most useful things this tool can surface, and it
// must not be masked by a generic "Windows" from a DHCP vendor class.
var userAgents = []substringRule{
	{"windows nt 10.0", "os=Windows 10/11", 0.8, 2},
	{"windows nt 6.3", "os=Windows 8.1", 0.8, 2},
	{"windows nt 6.2", "os=Windows 8 (end of life)", 0.8, 2},
	{"windows nt 6.1", "os=Windows 7 (end of life)", 0.8, 2},
	{"windows nt 6.0", "os=Windows Vista (end of life)", 0.8, 2},
	{"windows nt 5.1", "os=Windows XP (end of life)", 0.8, 2},
	{"macintosh; intel mac os x", "os=macOS", 0.8, 2},
	{"cros ", "os=ChromeOS", 0.8, 2},
	{"iphone", "os=iOS", 0.85, 2},
	{"ipad", "os=iPadOS", 0.85, 2},
	{"android", "os=Android", 0.85, 2},
	{"x11; linux", "os=Linux", 0.7, 1},
	{"debian apt-http", "os=Debian/Ubuntu", 0.8, 2},
	{"curl/", "class=server", 0.2, 1},
}

var userAgentClass = []substringRule{
	{"windows nt", "class=workstation", 0.5, 1},
	{"macintosh", "class=workstation", 0.5, 1},
	{"iphone", "class=mobile", 0.85, 1},
	{"ipad", "class=mobile", 0.85, 1},
	{"android", "class=mobile", 0.7, 1},
	{"debian apt-http", "class=server", 0.5, 1},
}

// ---------------------------------------------------------------------------
// SSH banners
// ---------------------------------------------------------------------------

var sshBanners = []substringRule{
	{"ubuntu", "os=Ubuntu", 0.85, 2},
	{"debian", "os=Debian", 0.85, 2},
	{"freebsd", "os=FreeBSD", 0.85, 2},
	{"rosssh", "vendor=MikroTik", 0.9, 1},
	{"cisco", "vendor=Cisco", 0.85, 1},
	{"dropbear", "os=Embedded Linux", 0.7, 1},
	{"openssh_for_windows", "os=Windows", 0.85, 1},
}

// ---------------------------------------------------------------------------
// Service banners — HTTP Server headers, FTP banners, SNMP sysDescr
// ---------------------------------------------------------------------------

// Embedded devices are far more honest in their banners than general-purpose
// operating systems, which makes this a strong signal for exactly the devices
// nobody has inventoried.
var serverBanners = []substringRule{
	{"iis/", "os=Windows", 0.8, 1},
	{"microsoft-httpapi", "os=Windows", 0.8, 1},
	{"apache", "class=server", 0.4, 1},
	{"nginx", "class=server", 0.4, 1},
	{"openwrt", "class=network", 0.85, 1},
	{"routeros", "vendor=MikroTik", 0.9, 1},
	{"mikrotik", "vendor=MikroTik", 0.9, 1},
	{"cisco ios", "vendor=Cisco", 0.9, 1},
	{"juniper", "vendor=Juniper", 0.9, 1},
	{"ubiquiti", "vendor=Ubiquiti", 0.9, 1},
	{"hikvision", "class=camera", 0.9, 1},
	{"dahua", "class=camera", 0.9, 1},
	{"axis", "class=camera", 0.8, 1},
	{"boa/", "class=iot", 0.7, 1},
	{"lighttpd", "class=iot", 0.3, 1},
	{"gsoap", "class=camera", 0.6, 1},
	{"jetdirect", "class=printer", 0.9, 1},
	{"hp http server", "class=printer", 0.85, 1},
	{"synology", "class=nas", 0.9, 1},
	{"qnap", "class=nas", 0.9, 1},
	{"truenas", "class=nas", 0.9, 1},
	{"freenas", "class=nas", 0.9, 1},
	{"vxworks", "class=iot", 0.7, 1},
	{"siemens", "class=plc", 0.8, 1},
	{"rockwell", "class=plc", 0.85, 1},
	{"allen-bradley", "class=plc", 0.9, 1},
	{"schneider", "class=plc", 0.8, 1},
}

// ---------------------------------------------------------------------------
// Hostname patterns
// ---------------------------------------------------------------------------

var hostnamePrefixes = []substringRule{
	{"desktop-", "class=workstation", 0.7, 1},
	{"laptop-", "class=workstation", 0.7, 1},
	{"win-", "os=Windows", 0.5, 1},
	{"brn", "vendor=Brother", 0.6, 1},
	{"npi", "vendor=HP", 0.6, 1},
	{"epson", "vendor=Seiko Epson", 0.7, 1},
	{"raspberrypi", "os=Linux", 0.7, 1},
	{"macbook", "os=macOS", 0.7, 2},
	{"iphone", "class=mobile", 0.7, 1},
	{"ipad", "class=mobile", 0.7, 1},
}

// ---------------------------------------------------------------------------
// Listening ports
// ---------------------------------------------------------------------------

// A port a device answers on is a statement about its role. Weights are modest
// on their own because ports are reassignable; they are meant to combine.
type portRule struct {
	Conclusion string
	Weight     float64
	Note       string
}

var portRules = map[int]portRule{
	9100:  {"class=printer", 0.9, "JetDirect raw printing"},
	515:   {"class=printer", 0.8, "LPD printing"},
	631:   {"class=printer", 0.8, "IPP printing"},
	554:   {"class=camera", 0.75, "RTSP video stream"},
	8554:  {"class=camera", 0.6, "RTSP video stream"},
	3389:  {"os=Windows", 0.7, "Remote Desktop"},
	445:   {"os=Windows", 0.4, "SMB file sharing"},
	139:   {"os=Windows", 0.3, "NetBIOS"},
	88:    {"class=server", 0.7, "Kerberos — likely a domain controller"},
	389:   {"class=server", 0.6, "LDAP — likely a domain controller"},
	636:   {"class=server", 0.6, "LDAPS"},
	53:    {"class=server", 0.5, "DNS server"},
	25:    {"class=server", 0.6, "SMTP mail server"},
	587:   {"class=server", 0.5, "SMTP submission"},
	993:   {"class=server", 0.5, "IMAPS"},
	3306:  {"class=server", 0.7, "MySQL database"},
	5432:  {"class=server", 0.7, "PostgreSQL database"},
	1433:  {"class=server", 0.7, "SQL Server database"},
	27017: {"class=server", 0.7, "MongoDB database"},
	6379:  {"class=server", 0.7, "Redis"},
	2049:  {"class=nas", 0.7, "NFS share"},
	548:   {"class=nas", 0.7, "AFP share"},
	161:   {"class=network", 0.5, "SNMP agent"},
	23:    {"class=network", 0.4, "Telnet — insecure management"},
	5060:  {"class=phone", 0.8, "SIP telephony"},
	5061:  {"class=phone", 0.7, "SIP over TLS"},
	1883:  {"class=iot", 0.6, "MQTT broker"},
	8883:  {"class=iot", 0.6, "MQTT over TLS"},
	502:   {"class=plc", 0.95, "Modbus — industrial control"},
	20000: {"class=plc", 0.9, "DNP3 — industrial control"},
	44818: {"class=plc", 0.95, "EtherNet/IP — industrial control"},
	47808: {"class=iot", 0.8, "BACnet — building automation"},
}

// ---------------------------------------------------------------------------
// Suricata app_proto
// ---------------------------------------------------------------------------

// Where Suricata has positively identified the protocol, trust it more than a
// port number: it inspected the traffic.
var appProtoRules = map[string]substringRule{
	"modbus": {Conclusion: "class=plc", Weight: 0.95},
	"dnp3":   {Conclusion: "class=plc", Weight: 0.95},
	"enip":   {Conclusion: "class=plc", Weight: 0.95},
	"rdp":    {Conclusion: "os=Windows", Weight: 0.8},
	"smb":    {Conclusion: "os=Windows", Weight: 0.4},
	"krb5":   {Conclusion: "class=server", Weight: 0.6},
	"sip":    {Conclusion: "class=phone", Weight: 0.8},
	"mqtt":   {Conclusion: "class=iot", Weight: 0.7},
	"snmp":   {Conclusion: "class=network", Weight: 0.5},
}

// ---------------------------------------------------------------------------

// applySubstringRules folds every matching rule into the device.
func applySubstringRules(d *Device, signal, value string, rules []substringRule) {
	if value == "" {
		return
	}
	lower := strings.ToLower(value)
	for _, r := range rules {
		if strings.Contains(lower, r.Match) {
			spec := r.Spec
			if spec == 0 {
				spec = 1
			}
			d.noteSpec(signal, value, r.Conclusion, r.Weight, spec)
		}
	}
}

func normaliseHostname(s string) string {
	s = strings.TrimSpace(strings.Trim(s, "."))
	s = strings.TrimSuffix(s, "\x00")
	if s == "" || s == "*" || strings.ContainsAny(s, " \t") {
		return ""
	}
	return strings.ToLower(s)
}
