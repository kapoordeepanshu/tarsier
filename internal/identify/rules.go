package identify

import (
	"strings"
)

// The rule *types* and the matching logic live here. The rules themselves live
// in data/, loaded by data.go.
//
// They were moved out of this file deliberately. The mapping from an observable
// signal to a device identity is the part of this problem no open dataset
// covers, and it will only get covered if the people who hold that knowledge
// can contribute it. Someone who knows exactly how a Zebra label printer
// announces itself on DHCP is very often not a Go programmer, and making them
// edit a Go slice to tell us was a guaranteed way never to hear from them.
//
// The intent remains that data/ moves out to its own public-domain repository
// once it is large enough to have its own release cadence. Keeping it as plain
// text with no Go syntax in it is what makes that a move rather than a rewrite.

// substringRule fires when an observed value contains Match.
type substringRule struct {
	Match      string // lowercase substring
	Conclusion string // "os=Windows", "class=printer", "vendor=HP"
	Weight     float64
	// Spec is how precise this answer is; 0 is treated as 1. Use 2 for a
	// conclusion that refines a vaguer one ("Windows 7" over "Windows") so the
	// specific answer wins even against a higher-weighted generic signal.
	Spec int
}

// portRule is what a device answering on a port implies about its role.
//
// Weights are modest on their own because ports are reassignable; they are
// meant to combine with other signals rather than to decide anything alone.
type portRule struct {
	Conclusion string
	Weight     float64
	Note       string
}

// applySubstringRules folds every matching rule into the device.
func applySubstringRules(d *Device, signal, value string, rules []substringRule) {
	if d == nil || value == "" {
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

// applyPrefixRules is applySubstringRules for values matched from the start and
// compared case-sensitively. JA4 fingerprints are the case in point: they are
// hex digests where a prefix is meaningful but a substring is not.
func applyPrefixRules(d *Device, signal, value string, rules []substringRule) {
	if d == nil || value == "" {
		return
	}
	for _, r := range rules {
		if r.Match != "" && strings.HasPrefix(value, r.Match) {
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
