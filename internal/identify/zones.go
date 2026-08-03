package identify

// Segmentation policy: you say which segments you meant to have, and we say
// where the traffic disagrees.
//
// This is the one finding that reliably changes a conversation. Nobody is
// surprised to hear a printer has an old firmware, but "the card-data segment
// has been talking to the office network every day since March" is a different
// meeting. Every framework asks for segmentation and almost nobody verifies it,
// because verifying it has meant either trusting the firewall config or running
// a scan you are not allowed to run.
//
// Zones are declared by CIDR and nothing else. VLAN tags look tempting, but a
// sensor watching a routed link sees one tag for the whole frame and cannot use
// it to tell the two endpoints apart — a policy that appeared to check VLANs
// while silently checking nothing would be worse than not offering it.
//
// The policy is deliberately deny-by-default between declared zones, and
// completely silent about anything it was not told about. An address in no zone
// raises nothing: we do not know where you meant it to live, and guessing would
// bury the real findings under noise.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

// Policy is a declared network segmentation, and the traffic that broke it.
type Policy struct {
	zones []zone
	// allowed holds "from\x00to" for permitted directions.
	allowed map[string]bool
}

type zone struct {
	name string
	nets []*net.IPNet
}

// ParsePolicy reads a segmentation policy.
//
//	# the segments you meant to have
//	zone office 10.0.1.0/24 10.0.2.0/24
//	zone card   10.0.5.0/24
//	zone ot     10.0.20.0/24
//
//	# and what may talk to what. Anything else between declared zones is
//	# reported. Traffic inside a zone is always fine.
//	allow office -> mgmt
//	allow office <-> printers
func ParsePolicy(r io.Reader) (*Policy, error) {
	p := &Policy{allowed: map[string]bool{}}
	sc := bufio.NewScanner(r)

	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}
		fields := strings.Fields(text)

		switch strings.ToLower(fields[0]) {
		case "zone":
			if len(fields) < 3 {
				return nil, fmt.Errorf("line %d: zone needs a name and at least one network", line)
			}
			z := zone{name: fields[1]}
			for _, cidr := range fields[2:] {
				_, n, err := net.ParseCIDR(cidr)
				if err != nil {
					return nil, fmt.Errorf("line %d: %q is not a network in CIDR form, such as 10.0.1.0/24", line, cidr)
				}
				z.nets = append(z.nets, n)
			}
			p.zones = append(p.zones, z)

		case "allow":
			// allow A -> B, or allow A <-> B
			if len(fields) != 4 {
				return nil, fmt.Errorf("line %d: allow needs the form 'allow office -> mgmt'", line)
			}
			from, arrow, to := fields[1], fields[2], fields[3]
			switch arrow {
			case "->":
				p.allowed[from+"\x00"+to] = true
			case "<->":
				p.allowed[from+"\x00"+to] = true
				p.allowed[to+"\x00"+from] = true
			default:
				return nil, fmt.Errorf("line %d: expected -> or <-> between zone names, found %q", line, arrow)
			}

		default:
			return nil, fmt.Errorf("line %d: expected 'zone' or 'allow', found %q", line, fields[0])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(p.zones) == 0 {
		return nil, errors.New("no zones declared: a policy with nothing in it would check nothing")
	}

	// An allow naming a zone that was never declared is a typo, and a typo in a
	// policy file fails open — the rule silently never matches and the crossing
	// it was meant to permit gets reported forever. Catch it at load.
	known := map[string]bool{}
	for _, z := range p.zones {
		known[z.name] = true
	}
	for pair := range p.allowed {
		for _, name := range strings.Split(pair, "\x00") {
			if !known[name] {
				return nil, fmt.Errorf("allow refers to zone %q, which is never declared", name)
			}
		}
	}
	return p, nil
}

// ZoneOf names the zone an address belongs to, or "" when it is in none.
//
// The most specific match wins, so a policy can carve a management subnet out
// of a wider office range without having to describe the office as a list of
// holes.
func (p *Policy) ZoneOf(ip string) string {
	if p == nil {
		return ""
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return ""
	}
	best, bestBits := "", -1
	for _, z := range p.zones {
		for _, n := range z.nets {
			if !n.Contains(addr) {
				continue
			}
			if ones, _ := n.Mask.Size(); ones > bestBits {
				best, bestBits = z.name, ones
			}
		}
	}
	return best
}

// Permits reports whether traffic from one address to another is within policy.
//
// Traffic is permitted when either end is outside every declared zone (we were
// not told where it belongs), when both ends are in the same zone, or when an
// allow covers that direction.
func (p *Policy) Permits(srcIP, destIP string) (ok bool, from, to string) {
	if p == nil {
		return true, "", ""
	}
	from, to = p.ZoneOf(srcIP), p.ZoneOf(destIP)
	if from == "" || to == "" || from == to {
		return true, from, to
	}
	return p.allowed[from+"\x00"+to], from, to
}

// Zones lists the declared zone names, for reporting.
func (p *Policy) Zones() []string {
	if p == nil {
		return nil
	}
	out := make([]string, 0, len(p.zones))
	for _, z := range p.zones {
		out = append(out, z.name)
	}
	sort.Strings(out)
	return out
}

// SetPolicy attaches a segmentation policy. Without one, nothing about
// segmentation is recorded or reported and there is no cost to having the
// feature — which is the point: most people will not write a policy, and they
// should not pay for the ones who do.
func (r *Resolver) SetPolicy(p *Policy) { r.policy = p }

// checkSegmentation records traffic that crossed a boundary the policy did not
// permit.
//
// Reported against the source, because that is the end doing something it was
// not meant to, and the end whose owner can usually explain why.
func (r *Resolver) checkSegmentation(srcIP, destIP string, destPort int) {
	if r.policy == nil || !isPrivate(srcIP) || !isPrivate(destIP) {
		return
	}
	ok, from, to := r.policy.Permits(srcIP, destIP)
	if ok {
		return
	}

	where := destIP
	if destPort > 0 {
		where = fmt.Sprintf("%s:%d", destIP, destPort)
	}
	r.addFinding(Finding{
		Severity: SevHigh,
		// Keyed by the pair of zones rather than by the destination, so one
		// chatty host does not file the same breach a thousand times. The first
		// example is kept in the detail; the point is the boundary, not the
		// packet.
		Kind:   "segmentation-" + from + "-to-" + to,
		Device: srcIP,
		Title:  "Traffic crossed from " + from + " to " + to + ", which your policy does not allow",
		Detail: "Your segmentation policy declares " + from + " and " + to + " as separate segments with no route between them, and this device is talking across that line anyway — first seen going to " + where + ". Either the firewall rule is not doing what it looks like it does, or there is a path around it.",
		Fix:    "Check the firewall rule between " + from + " and " + to + " and confirm it matches this traffic. If the crossing is intended, add 'allow " + from + " -> " + to + "' to the policy so it stops being reported.",
	})
}
