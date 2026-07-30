package identify

import (
	"sort"
	"strings"
	"time"
)

// Findings are the point of the product.
//
// A device inventory is the hook; what keeps someone using this is a short list
// of things that are actually wrong. Every finding must be something a
// non-specialist can act on, so each one states what it is and what to do. A
// finding nobody can act on is worse than silence — it teaches people to ignore
// the tool.

type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	}
	return "INFO"
}

type Finding struct {
	Severity Severity
	Kind     string // stable machine-readable identifier
	Device   string // IP, or "sensor" for sensor-health findings
	Title    string // what it is, in plain language
	Detail   string // what it means, and why it matters
	// Fix is what to actually do about it, written for someone who is not a
	// security specialist. This field is the difference between a report people
	// read once and a tool they keep open: a problem without a fix is homework,
	// and homework gets ignored.
	Fix string
	// Command is the exact thing to run or open, where one exists. Empty when
	// the fix genuinely depends on the device — inventing a plausible-looking
	// command that does not work would be worse than offering none.
	Command string
	Count   int
}

// addFinding records a finding once per device and kind. Repeating the same
// problem for every packet that exhibits it turns a useful list into noise.
func (r *Resolver) addFinding(f Finding) {
	if f.Device == "" {
		return
	}
	key := f.Device + "|" + f.Kind
	if r.seenFind[key] {
		for i := range r.findings {
			if r.findings[i].Device == f.Device && r.findings[i].Kind == f.Kind {
				r.findings[i].Count++
				return
			}
		}
		return
	}
	r.seenFind[key] = true
	f.Count = 1
	r.findings = append(r.findings, f)
}

// Findings returns everything found, most severe first.
func (r *Resolver) Findings() []Finding {
	out := make([]Finding, len(r.findings))
	copy(out, r.findings)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return ipLess(out[i].Device, out[j].Device)
	})
	return out
}

// --- checks -----------------------------------------------------------------

// checkEndOfLifeOS surfaces unsupported operating systems. For a small company
// this is often the single most valuable thing the tool reports: an
// out-of-support machine nobody remembered was still running.
func (r *Resolver) checkEndOfLifeOS(d *Device, ua string) {
	if ua == "" {
		return
	}
	lower := strings.ToLower(ua)
	for _, eol := range []struct{ match, name string }{
		{"windows nt 5.1", "Windows XP"},
		{"windows nt 6.0", "Windows Vista"},
		{"windows nt 6.1", "Windows 7"},
		{"windows nt 6.2", "Windows 8"},
	} {
		if strings.Contains(lower, eol.match) {
			r.addFinding(Finding{
				Severity: SevHigh, Kind: "end-of-life-os", Device: d.IP,
				Title:  eol.name + " is still in use on this device",
				Detail: eol.name + " no longer receives security updates, so any vulnerability found in it stays unpatched forever.",
				// Machine controllers and lab equipment often cannot be
				// upgraded at all, so isolation has to be a first-class answer
				// rather than a footnote.
				Fix: "Upgrade or replace this machine. If it runs equipment that cannot be upgraded — which is common for machine controllers and lab gear — move it onto its own VLAN with no internet access and no route to the rest of the network.",
			})
			return
		}
	}
}

// checkTLSVersion flags obsolete TLS, which is both a real weakness and a
// common audit and questionnaire failure.
func (r *Resolver) checkTLSVersion(d *Device, version string) {
	switch strings.ToUpper(strings.TrimSpace(version)) {
	case "SSLV2", "SSLV3":
		r.addFinding(Finding{
			Severity: SevCritical, Kind: "obsolete-ssl", Device: d.IP,
			Title:   "SSL " + version + " in use",
			Detail:  "SSLv2 and SSLv3 are broken. Traffic to this device is not meaningfully protected, even though it looks encrypted.",
			Fix:     "Turn off SSLv2 and SSLv3 on this service and allow only TLS 1.2 and 1.3. On nginx or Apache this is one line in the config; on an appliance it is usually under Settings → Security.",
			Command: `nginx:  ssl_protocols TLSv1.2 TLSv1.3;`,
		})
	case "TLS 1.0", "TLSV1", "TLS 1.1", "TLSV1.1":
		r.addFinding(Finding{
			Severity: SevMedium, Kind: "weak-tls", Device: d.IP,
			Title:   "Obsolete TLS version in use (" + version + ")",
			Detail:  "TLS 1.0 and 1.1 are deprecated and fail most compliance checks, including PCI-DSS.",
			Fix:     "Set this service to accept only TLS 1.2 and 1.3. If a device is too old to support them, put it behind a reverse proxy that does.",
			Command: `nginx:  ssl_protocols TLSv1.2 TLSv1.3;`,
		})
	}
}

// checkCertificate reports certificates that are expiring, already expired, or
// self-signed. Expiry in particular causes real outages and nobody tracks it.
func (r *Resolver) checkCertificate(d *Device, subject, issuer, notAfter string) {
	if subject != "" && issuer != "" && subject == issuer {
		r.addFinding(Finding{
			Severity: SevLow, Kind: "self-signed-cert", Device: d.IP,
			Title:  "Self-signed certificate in use",
			Detail: "Nobody connecting to this service can verify it is really the right machine, so an impersonation attack would not be noticed.",
			Fix:    "Fine for a service only you use internally. For anything staff or customers touch, get a real certificate — Let's Encrypt issues them free, and most appliances have a built-in option for it.",
		})
	}
	exp := parseCertTime(notAfter)
	if exp.IsZero() {
		return
	}
	days := int(time.Until(exp).Hours() / 24)
	switch {
	case days < 0:
		r.addFinding(Finding{
			Severity: SevHigh, Kind: "cert-expired", Device: d.IP,
			Title:   "Certificate has expired",
			Detail:  "Expired on " + exp.Format("2 January 2006") + ". People are seeing security warnings, or connections are failing outright.",
			Fix:     "Renew it now. Most appliances have a certificate page in their admin interface; on a Linux server with Let's Encrypt it is one command.",
			Command: "sudo certbot renew --force-renewal",
		})
	case days <= 30:
		r.addFinding(Finding{
			Severity: SevMedium, Kind: "cert-expiring", Device: d.IP,
			Title:   "Certificate expires in " + itoa(days) + " days",
			Detail:  "Expires on " + exp.Format("2 January 2006") + ". Nothing is broken yet — this is the warning you would otherwise get on the day it fails.",
			Fix:     "Renew it this week. Certificate expiry is one of the commonest causes of an unplanned outage, and it is entirely avoidable.",
			Command: "sudo certbot renew",
		})
	}
}

// parseCertTime handles the several shapes Suricata has used for notAfter.
func parseCertTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05",
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
