package identify

// The identity graph: which people are on which machines.
//
// The inventory answers "what is on this network". This answers "who", which is
// the question that follows about four seconds later — and it needs no new
// collection, because Kerberos and SMB have been naming users on the wire the
// whole time. Turning that into a person-shaped view is aggregation, not
// inference.
//
// Deliberately no findings come out of this. The tempting one is "this account
// signed in from nine machines", and it would be wrong constantly: service
// accounts, shared kiosks, roaming profiles and admin tooling all look exactly
// like a compromised credential from the outside. A number that fires on
// ordinary Tuesdays teaches people to ignore it, and then it is worth less than
// nothing. What an operator wants here is to look, recognise their own network,
// and notice the one line that surprises them — so we lay it out and stay quiet.

import "sort"

// Identity is one account and everywhere it was seen signing in.
type Identity struct {
	User    string
	Devices []*Device
}

// Identities aggregates every observed account across the devices it appeared
// on, busiest first.
//
// "Busiest" means seen on the most machines, because an account on one machine
// is a person at a desk and an account on twenty is either infrastructure or a
// problem — either way it is the row worth reading first.
//
// Takes the resolved devices rather than reading the resolver, so the report and
// the JSON snapshot both build it from exactly the set they are describing. A
// filtered report showing identities from devices it is not showing would be a
// quiet lie.
func Identities(devices []*Device) []Identity {
	byUser := map[string][]*Device{}
	for _, d := range devices {
		if d == nil || !isPrivate(d.IP) {
			continue
		}
		for u := range d.Users {
			byUser[u] = append(byUser[u], d)
		}
	}

	out := make([]Identity, 0, len(byUser))
	for user, devices := range byUser {
		sort.Slice(devices, func(i, j int) bool { return ipLess(devices[i].IP, devices[j].IP) })
		out = append(out, Identity{User: user, Devices: devices})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Devices) != len(out[j].Devices) {
			return len(out[i].Devices) > len(out[j].Devices)
		}
		return out[i].User < out[j].User
	})
	return out
}
