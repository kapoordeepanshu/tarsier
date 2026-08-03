package identify

// Saving and restoring the model, so a long-running watcher's window outlives
// the logs it was built from.
//
// Without this, restarting means rebuilding from whatever rotation still has on
// disk — which works, and is why it was the first approach, but caps the window
// at your logrotate settings. A sensor keeping five hourly files can only ever
// remember five hours, however long you asked it to retain.
//
// The state is the conclusions, never the traffic. A month of them is a few tens
// of megabytes because it is one record per device plus a byte per device-hour;
// a month of eve.json is hundreds of gigabytes. That difference is the whole
// reason this fits on a mini-PC and does not need a database.
//
// Everything the model needs to keep accumulating correctly is written out,
// including the evidence weights and the deduplication sets. Persisting only the
// visible answers would look right and then drift: a restored device would
// re-count evidence it had already seen and creep towards a confidence it never
// earned.

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// stateVersion guards against reading a file written by a different model. On a
// mismatch the state is discarded rather than half-understood — starting from
// the logs on disk is a known-good fallback, and a subtly wrong inventory is
// worse than a smaller one.
const stateVersion = 1

type savedState struct {
	Version int    `json:"version"`
	Tool    string `json:"tool"`

	Written time.Time `json:"written"`
	First   time.Time `json:"first_event,omitempty"`
	Last    time.Time `json:"last_event,omitempty"`

	Devices  []savedDevice  `json:"devices"`
	Findings []Finding      `json:"findings"`
	SeenFind []string       `json:"seen_findings"`
	Counts   map[string]int `json:"event_counts"`
	Health   SensorHealth   `json:"sensor_health"`

	// Source and Offset record where in the live log we had read to, so a
	// restart resumes rather than re-reading and counting the same events
	// twice. Empty when the caller does not track a position.
	Source string `json:"source,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Sig    string `json:"signature,omitempty"`
}

type savedDevice struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	RandomMAC bool   `json:"random_mac,omitempty"`

	Hostnames     []string             `json:"hostnames,omitempty"`
	Users         []string             `json:"users,omitempty"`
	Services      map[int]*Service     `json:"services,omitempty"`
	Vendor        string               `json:"vendor,omitempty"`
	Class         Class                `json:"class,omitempty"`
	OS            string               `json:"os,omitempty"`
	Model         string               `json:"model,omitempty"`
	Firmware      string               `json:"firmware,omitempty"`
	Serial        string               `json:"serial,omitempty"`
	OTIdentifiers []string             `json:"ot_identifiers,omitempty"`
	JA3           []string             `json:"ja3,omitempty"`
	JA4           []string             `json:"ja4,omitempty"`
	VLANs         []int                `json:"vlans,omitempty"`
	Protocols     []string             `json:"protocols,omitempty"`
	Certs         []Cert               `json:"certs,omitempty"`
	Shares        []string             `json:"shares,omitempty"`
	Files         int                  `json:"files,omitempty"`
	FirstSeen     time.Time            `json:"first_seen,omitempty"`
	LastSeen      time.Time            `json:"last_seen,omitempty"`
	Activity      map[int64]int        `json:"activity,omitempty"`
	Alerts        int                  `json:"alerts,omitempty"`
	Drops         int                  `json:"drops,omitempty"`
	Anomalies     int                  `json:"anomalies,omitempty"`
	ExternalDsts  []string             `json:"external,omitempty"`
	Evidence      []Evidence           `json:"evidence,omitempty"`
	Weights       map[string]float64   `json:"weights,omitempty"`
	Specificity   map[string]int       `json:"specificity,omitempty"`
	Seen          []string             `json:"seen,omitempty"`
	Latest        map[string]time.Time `json:"latest,omitempty"`
}

// Position is where in a log the caller had read to. Carried through the state
// file so a restart resumes instead of re-reading events it already counted.
type Position struct {
	Source string
	Offset int64
	Sig    string
}

// Save writes the model. The caller supplies its read position, if it has one.
func (r *Resolver) Save(w io.Writer, pos Position) error {
	st := savedState{
		Version: stateVersion,
		Tool:    "tarsier",
		Written: time.Now().UTC(),
		First:   r.First,
		Last:    r.Last,
		Counts:  r.counts,
		Health:  r.SensorHealth,
		Source:  pos.Source,
		Offset:  pos.Offset,
		Sig:     pos.Sig,
	}
	st.Findings = append(st.Findings, r.findings...)
	for k := range r.seenFind {
		st.SeenFind = append(st.SeenFind, k)
	}
	for _, d := range r.devices {
		st.Devices = append(st.Devices, saveDevice(d))
	}
	return json.NewEncoder(w).Encode(st)
}

// Load restores a model previously written by Save, and reports the read
// position that went with it.
//
// A file from a different model version is refused rather than partially
// understood: rebuilding from the logs on disk is a known-good fallback, and a
// silently wrong inventory is worse than a smaller one.
func (r *Resolver) Load(rd io.Reader) (Position, error) {
	var st savedState
	if err := json.NewDecoder(rd).Decode(&st); err != nil {
		return Position{}, err
	}
	if st.Version != stateVersion {
		return Position{}, fmt.Errorf("state was written by a different version of the model (%d, expected %d)",
			st.Version, stateVersion)
	}

	r.devices = make(map[string]*Device, len(st.Devices))
	for _, sd := range st.Devices {
		r.devices[sd.IP] = loadDevice(sd)
	}
	r.findings = append(r.findings[:0], st.Findings...)
	r.seenFind = make(map[string]bool, len(st.SeenFind))
	for _, k := range st.SeenFind {
		r.seenFind[k] = true
	}
	r.counts = st.Counts
	if r.counts == nil {
		r.counts = map[string]int{}
	}
	r.SensorHealth = st.Health
	r.First, r.Last = st.First, st.Last

	return Position{Source: st.Source, Offset: st.Offset, Sig: st.Sig}, nil
}

func saveDevice(d *Device) savedDevice {
	return savedDevice{
		IP: d.IP, MAC: d.MAC, RandomMAC: d.RandomMAC,
		Hostnames:     sortedKeys(d.Hostnames),
		Users:         sortedKeys(d.Users),
		Services:      d.Services,
		Vendor:        d.Vendor,
		Class:         d.Class,
		OS:            d.OS,
		Model:         d.Model,
		Firmware:      d.Firmware,
		Serial:        d.Serial,
		OTIdentifiers: sortedKeys(d.OTIdentifiers),
		JA3:           sortedKeys(d.JA3),
		JA4:           sortedKeys(d.JA4),
		VLANs:         d.SortedVLANs(),
		Protocols:     sortedKeys(d.Protocols),
		Certs:         d.Certs,
		Shares:        sortedKeys(d.Shares),
		Files:         d.Files,
		FirstSeen:     d.FirstSeen,
		LastSeen:      d.LastSeen,
		Activity:      d.Activity,
		Alerts:        d.Alerts,
		Drops:         d.Drops,
		Anomalies:     d.Anomalies,
		ExternalDsts:  sortedKeys(d.ExternalDsts),
		Evidence:      d.Evidence,
		Weights:       d.weights,
		Specificity:   d.specificity,
		Seen:          sortedKeys(d.seen),
		Latest:        d.latest,
	}
}

func loadDevice(sd savedDevice) *Device {
	d := newDevice(sd.IP)
	d.MAC, d.RandomMAC = sd.MAC, sd.RandomMAC
	d.Vendor, d.Class, d.OS = sd.Vendor, sd.Class, sd.OS
	d.Model, d.Firmware, d.Serial = sd.Model, sd.Firmware, sd.Serial
	d.Files, d.Alerts, d.Drops, d.Anomalies = sd.Files, sd.Alerts, sd.Drops, sd.Anomalies
	d.FirstSeen, d.LastSeen = sd.FirstSeen, sd.LastSeen
	d.Certs = sd.Certs
	d.Evidence = sd.Evidence

	fillSet(d.Hostnames, sd.Hostnames)
	fillSet(d.Users, sd.Users)
	fillSet(d.OTIdentifiers, sd.OTIdentifiers)
	fillSet(d.JA3, sd.JA3)
	fillSet(d.JA4, sd.JA4)
	fillSet(d.Protocols, sd.Protocols)
	fillSet(d.Shares, sd.Shares)
	fillSet(d.ExternalDsts, sd.ExternalDsts)
	fillSet(d.seen, sd.Seen)

	for _, v := range sd.VLANs {
		d.VLANs[v] = true
	}
	if sd.Services != nil {
		d.Services = sd.Services
	}
	if sd.Activity != nil {
		d.Activity = sd.Activity
	}
	if sd.Weights != nil {
		d.weights = sd.Weights
	}
	if sd.Specificity != nil {
		d.specificity = sd.Specificity
	}
	if sd.Latest != nil {
		d.latest = sd.Latest
	}
	return d
}

func fillSet(dst map[string]bool, keys []string) {
	for _, k := range keys {
		dst[k] = true
	}
}
