package identify

import "strings"

// JA4 client fingerprints.
//
// A JA4 fingerprint describes how a TLS client is configured: which version it
// offers, whether it sent a server name, how many ciphers and extensions it
// listed, and what application protocol it asked for. Devices running the same
// TLS library produce the same fingerprint, which makes it the one strong signal
// left for a device that speaks nothing but encrypted traffic.
//
// The important property for this tool is that the first ten characters are not
// a hash. They are a documented, readable encoding, so useful conclusions can be
// drawn from any JA4 string with no database at all — which matters because the
// lookup table (data/ja4.tsv) is empty and can only be filled by people
// observing devices they can positively identify.
//
// This decodes JA4 only, the TLS client fingerprint, which is BSD-3-Clause. The
// JA4+ family — JA4S, JA4H, JA4X, JA4L, JA4SSH — is under the FoxIO License 1.1
// and is deliberately not implemented here.
//
// Format of the first segment, from the JA4 specification:
//
//	t 13 d 15 16 h2
//	│  │ │  │  │  └── first and last character of the first ALPN value
//	│  │ │  │  └───── extension count, excluding GREASE
//	│  │ │  └──────── cipher count, excluding GREASE
//	│  │ └─────────── d = SNI present, i = connecting to a bare IP
//	│  └───────────── TLS version offered
//	└──────────────── t = TLS over TCP, q = QUIC, d = DTLS
type JA4 struct {
	Transport  string // "TCP", "QUIC", "DTLS"
	TLSVersion string // "TLS 1.3", "SSL 3.0", ...
	Obsolete   bool   // the offered version is SSL 3.0 or older, or TLS 1.0/1.1
	SNI        bool   // the client named the host it wanted
	Ciphers    int
	Extensions int
	ALPN       string // "HTTP/2", "DNS-over-TLS", "" when none was offered
	OK         bool   // the string parsed as a JA4_a segment
}

// ja4Versions is the version table from the JA4 specification.
var ja4Versions = map[string]struct {
	name     string
	obsolete bool
}{
	"13": {"TLS 1.3", false},
	"12": {"TLS 1.2", false},
	"11": {"TLS 1.1", true},
	"10": {"TLS 1.0", true},
	"s3": {"SSL 3.0", true},
	"s2": {"SSL 2.0", true},
	"d1": {"DTLS 1.0", true},
	"d2": {"DTLS 1.2", false},
	"d3": {"DTLS 1.3", false},
	"00": {"unknown", false},
}

// ja4ALPN expands the two-character ALPN encoding — the first and last
// character of the negotiated protocol name — back into a readable protocol.
// Only unambiguous cases are listed; anything else is reported verbatim.
var ja4ALPN = map[string]string{
	"h1": "HTTP/1.1",
	"h2": "HTTP/2",
	"h3": "HTTP/3",
	"dt": "DNS-over-TLS",
	"dq": "DNS-over-QUIC",
	"00": "",
}

// DecodeJA4 reads the structured first segment of a JA4 fingerprint.
//
// It accepts either a full fingerprint ("t13d1516h2_8daaf6152771_e5627efa2ab1")
// or the leading segment alone. A string that does not parse returns OK false
// rather than a zero-valued guess, because a misread fingerprint would produce
// confident nonsense about a device's TLS configuration.
func DecodeJA4(s string) JA4 {
	var j JA4

	// Take the JA4_a segment. The remaining two segments are hashes of the
	// cipher and extension lists and carry nothing readable.
	if i := strings.Index(s, "_"); i >= 0 {
		s = s[:i]
	}
	if len(s) != 10 {
		return j
	}

	switch s[0] {
	case 't':
		j.Transport = "TCP"
	case 'q':
		j.Transport = "QUIC"
	case 'd':
		j.Transport = "DTLS"
	default:
		return j
	}

	v, ok := ja4Versions[s[1:3]]
	if !ok {
		return j
	}
	j.TLSVersion, j.Obsolete = v.name, v.obsolete

	switch s[3] {
	case 'd':
		j.SNI = true
	case 'i':
		j.SNI = false
	default:
		return j
	}

	c, okc := ja4Count(s[4:6])
	e, oke := ja4Count(s[6:8])
	if !okc || !oke {
		return j
	}
	j.Ciphers, j.Extensions = c, e

	alpn := s[8:10]
	if name, known := ja4ALPN[alpn]; known {
		j.ALPN = name
	} else {
		j.ALPN = alpn
	}

	j.OK = true
	return j
}

func ja4Count(s string) (int, bool) {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// applyJA4 folds a client fingerprint into the device.
//
// The conclusions here are deliberately narrow. A JA4 string states facts about
// a TLS configuration; it does not, on its own, say what kind of device is on
// the other end. Naming the device is what data/ja4.tsv is for, and that table
// can only be filled by observation — so this function draws the conclusions
// that are true by construction and leaves the rest alone.
func (r *Resolver) applyJA4(d *Device, fp string) {
	if d == nil || fp == "" {
		return
	}
	d.JA4[fp] = true

	// Any curated fingerprint match is the most specific answer available.
	applyPrefixRules(d, "tls.ja4", fp, ja4Fingerprints)

	j := DecodeJA4(fp)
	if !j.OK {
		return
	}

	if j.Transport == "QUIC" {
		d.Protocols["quic"] = true
	}

	// Encrypted DNS from a client is worth surfacing for the same reason
	// DNS-over-HTTPS already is: it moves name resolution out of sight of
	// whatever local DNS controls the network relies on.
	switch j.ALPN {
	case "DNS-over-TLS":
		d.Protocols["dns-over-tls"] = true
	case "DNS-over-QUIC":
		d.Protocols["dns-over-quic"] = true
	}

	// A client that still offers an obsolete protocol version is a finding in
	// its own right, and a different one from a server that still accepts it.
	// The server-side check cannot see this: the client's offer is made before
	// anything is negotiated.
	if j.Obsolete {
		d.note("tls.ja4", fp, "class=iot", 0.25)
		r.addFinding(Finding{
			Severity: SevMedium, Kind: "client-obsolete-tls", Device: d.IP,
			Title:  "This device still offers " + j.TLSVersion,
			Detail: "Its TLS fingerprint (" + fp + ") shows it opens connections offering " + j.TLSVersion + ", which is obsolete and no longer considered secure. Because this is what the device asks for rather than what a server accepts, it is a property of the device itself — usually old firmware or an old TLS library built into the product.",
			Fix:    "Update the device's firmware. If no update exists, which is common for embedded equipment, restrict what it is allowed to reach: an obsolete TLS client is at risk from any server it connects to, including a hostile one.",
		})
	}
}
