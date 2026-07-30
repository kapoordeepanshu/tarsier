package identify

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

// The fingerprint database, compiled in.
//
// These files are data, not code. They are embedded so that the binary stays
// self-contained — a tool meant to run on an isolated OT network cannot expect
// to download anything — but they are kept as plain text rather than generated
// Go so that a contributor who is not a programmer can still fix a wrong
// identification, and so the whole set can move to its own public-domain
// repository later without touching this package.

//go:embed data/fingerprints.tsv
var fingerprintsTSV string

//go:embed data/ports.tsv
var portsTSV string

//go:embed data/app_proto.tsv
var appProtoTSV string

//go:embed data/ja4.tsv
var ja4TSV string

//go:embed data/oui.tsv
var ouiTSV string

//go:embed data/oui_override.tsv
var ouiOverrideTSV string

// The substring rule tables, populated from fingerprints.tsv at startup. These
// total a few hundred rows, so parsing them eagerly costs nothing measurable.
var (
	vendorClass              []substringRule
	dhcpVendorClass          []substringRule
	dhcpVendorClassSecondary []substringRule
	userAgents               []substringRule
	userAgentClass           []substringRule
	sshBanners               []substringRule
	serverBanners            []substringRule
	hostnamePrefixes         []substringRule
	ja4Fingerprints          []substringRule
	portRules                = map[int]portRule{}
	appProtoRules            = map[string]substringRule{}
)

func init() {
	tables := map[string]*[]substringRule{
		"vendor_class":                &vendorClass,
		"dhcp_vendor_class":           &dhcpVendorClass,
		"dhcp_vendor_class_secondary": &dhcpVendorClassSecondary,
		"user_agent":                  &userAgents,
		"user_agent_class":            &userAgentClass,
		"ssh_banner":                  &sshBanners,
		"server_banner":               &serverBanners,
		"hostname_prefix":             &hostnamePrefixes,
	}

	for _, f := range fields(fingerprintsTSV, 4) {
		dst, ok := tables[f[0]]
		if !ok {
			// An unknown table name means this binary is older than the data
			// file. Skipping is the right behaviour: a future rule we cannot
			// apply is not a reason to refuse to run.
			continue
		}
		*dst = append(*dst, substringRule{
			Match:      strings.ToLower(f[1]),
			Conclusion: f[2],
			Weight:     parseFloat(f[3]),
			Spec:       parseIntField(f, 4, 1),
		})
	}

	for _, f := range fields(portsTSV, 4) {
		port, err := strconv.Atoi(f[0])
		if err != nil || port <= 0 {
			continue
		}
		portRules[port] = portRule{
			Conclusion: f[1],
			Weight:     parseFloat(f[2]),
			Note:       f[3],
		}
	}

	for _, f := range fields(appProtoTSV, 3) {
		appProtoRules[strings.ToLower(f[0])] = substringRule{
			Conclusion: f[1],
			Weight:     parseFloat(f[2]),
		}
	}

	for _, f := range fields(ja4TSV, 3) {
		ja4Fingerprints = append(ja4Fingerprints, substringRule{
			Match:      f[0], // JA4 strings are case-sensitive; do not fold
			Conclusion: f[1],
			Weight:     parseFloat(f[2]),
			Spec:       parseIntField(f, 3, 1),
		})
	}
}

// fields splits a TSV file into records, dropping comments and blank lines and
// rejecting rows with too few columns. min is the number of columns a usable
// row must have; extra columns are preserved so a data file can grow a field
// without breaking older binaries.
func fields(src string, min int) [][]string {
	var out [][]string
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < min {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if f[0] == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

func parseFloat(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return v
}

func parseIntField(f []string, idx, def int) int {
	if idx >= len(f) {
		return def
	}
	v, err := strconv.Atoi(strings.TrimSpace(f[idx]))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

// --- MAC OUI ---------------------------------------------------------------

// The IEEE table holds roughly 53,000 assignments, which is large enough that
// parsing it eagerly would be felt by anything that starts the binary without
// scanning — `--help`, `--version`, a shell completion. It is built on first
// lookup instead.
var (
	ouiOnce     sync.Once
	ouiIEEE     map[string]string
	ouiOverride map[string]string
	// ouiOverrideLens holds the distinct prefix lengths present in the curated
	// table, longest first, so lookup tries only lengths that can match.
	ouiOverrideLens []int
)

func loadOUI() {
	ouiIEEE = make(map[string]string, 55000)
	for _, f := range fields(ouiTSV, 2) {
		ouiIEEE[strings.ToUpper(f[0])] = f[1]
	}

	ouiOverride = map[string]string{}
	seenLen := map[int]bool{}
	for _, f := range fields(ouiOverrideTSV, 2) {
		p := strings.ToUpper(f[0])
		ouiOverride[p] = f[1]
		seenLen[len(p)] = true
	}
	for l := range seenLen {
		ouiOverrideLens = append(ouiOverrideLens, l)
	}
	// Longest first: a curated 8-hex prefix must beat a curated 4-hex one.
	for i := 0; i < len(ouiOverrideLens); i++ {
		for j := i + 1; j < len(ouiOverrideLens); j++ {
			if ouiOverrideLens[j] > ouiOverrideLens[i] {
				ouiOverrideLens[i], ouiOverrideLens[j] = ouiOverrideLens[j], ouiOverrideLens[i]
			}
		}
	}
}

// lookupOUI maps a MAC address to the vendor that made the hardware.
//
// Resolution order is longest-prefix-wins, with the curated table beating the
// IEEE registry at every length. The three IEEE prefix lengths correspond to
// the size of block a vendor bought: a small vendor holding a 36-bit MA-S block
// must resolve to itself rather than to whoever owns the enclosing 24-bit block.
func lookupOUI(mac string) string {
	ouiOnce.Do(loadOUI)

	hex := normaliseMAC(mac)
	if len(hex) < 6 {
		return ""
	}

	for _, l := range ouiOverrideLens {
		if l <= len(hex) {
			if v, ok := ouiOverride[hex[:l]]; ok {
				return v
			}
		}
	}
	// MA-S (36-bit), then MA-M (28-bit), then MA-L (24-bit).
	for _, l := range []int{9, 7, 6} {
		if l <= len(hex) {
			if v, ok := ouiIEEE[hex[:l]]; ok {
				return v
			}
		}
	}
	return ""
}

// normaliseMAC strips separators and upper-cases, so that "00:1b:21:..." and
// "001B21..." are the same lookup. Suricata emits colon-separated addresses,
// but the field has come through enough intermediaries to be worth defending.
func normaliseMAC(mac string) string {
	var b strings.Builder
	b.Grow(12)
	for _, c := range mac {
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			b.WriteRune(c)
		case c >= 'a' && c <= 'f':
			b.WriteRune(c - 32)
		}
	}
	return b.String()
}

// IsLocallyAdministered reports whether a MAC has the locally-administered bit
// set, which means it was not assigned by the manufacturer.
//
// This matters for inventory: modern phones and laptops randomise their MAC per
// network by default, so a locally-administered address is usually one device
// wearing a disposable identity rather than a new device on the network. Left
// unmarked, MAC randomisation inflates a device count without limit.
func IsLocallyAdministered(mac string) bool {
	hex := normaliseMAC(mac)
	if len(hex) < 2 {
		return false
	}
	b, err := strconv.ParseUint(hex[:2], 16, 8)
	if err != nil {
		return false
	}
	return b&0x02 != 0
}
