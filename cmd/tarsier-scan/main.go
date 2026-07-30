// Command tarsier-scan reads a Suricata eve.json file and prints the devices
// it found on the network.
//
// This is the whole idea in one command: everything printed below was already
// being written to disk by Suricata and thrown away.
//
//	tarsier-scan /var/log/suricata/eve.json
//	cat eve.json | tarsier-scan
//	tarsier-scan -v eve.json      # show the evidence behind each conclusion
package main

import (
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"tarsier/internal/eve"
	"tarsier/internal/identify"
	"tarsier/internal/report"
)

func main() {
	verbose := flag.Bool("v", false, "show the evidence behind each identification")
	minConf := flag.Float64("min-confidence", 0, "hide devices below this confidence (0-1)")
	htmlOut := flag.String("html", "", "write a self-contained HTML report to this path")
	last := flag.String("last", "", "only the most recent period, e.g. 24h, 7d, 30m")
	since := flag.String("since", "", "only events at or after this time (2026-07-30 or 2026-07-30T09:00)")
	until := flag.String("until", "", "only events at or before this time")
	flag.Usage = usage
	flag.Parse()

	from, to, err := window(*last, *since, *until)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarsier-scan:", err)
		os.Exit(1)
	}

	// Accept many inputs: several files, a glob, or a directory of rotated
	// logs. Suricata rotates eve.json constantly, so "scan yesterday" has to
	// mean more than one file or the tool is useless on a real sensor.
	inputs, err := expand(flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarsier-scan:", err)
		os.Exit(1)
	}

	res := identify.NewResolver()
	res.SetWindow(from, to)
	var total, skipped int

	for _, path := range inputs {
		in, err := openOne(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tarsier-scan:", err)
			os.Exit(1)
		}
		rd := eve.NewReader(in)
		for rec := rd.Next(); rec != nil; rec = rd.Next() {
			res.Add(rec)
		}
		if err := rd.Err(); err != nil {
			in.Close()
			fmt.Fprintln(os.Stderr, "tarsier-scan: reading "+path+":", err)
			os.Exit(1)
		}
		t, s := rd.Stats()
		total, skipped = total+t, skipped+s
		in.Close()
	}

	name := describeInputs(inputs)
	devices := res.Devices()

	// The HTML report is the shareable artefact: one file, no dependencies,
	// opens offline. It is what gets handed to a client or an auditor.
	if *htmlOut != "" {
		f, err := os.Create(*htmlOut)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tarsier-scan:", err)
			os.Exit(1)
		}
		rep := report.Build(name, total, skipped, devices, res.Findings(),
			res.EventCounts(), res.First, res.Last)
		if err := report.Write(f, rep); err != nil {
			f.Close()
			fmt.Fprintln(os.Stderr, "tarsier-scan: writing report:", err)
			os.Exit(1)
		}
		f.Close()
		fmt.Printf("\n  wrote %s — %d devices, %d findings\n\n",
			*htmlOut, len(devices), len(res.Findings()))
		return
	}

	printHeader(name, total, skipped, devices)
	printCoverage(res.EventCounts())
	printDevices(devices, *minConf, *verbose)
	printFindings(res.Findings())
	printSummary(devices)
}

// printFindings comes before the summary because it is the part that matters.
// An inventory is interesting once; the findings are why anyone comes back.
func printFindings(findings []identify.Finding) {
	if len(findings) == 0 {
		return
	}
	fmt.Printf("  %s\n\n", bold(fmt.Sprintf("%d THINGS WORTH LOOKING AT", len(findings))))
	for _, f := range findings {
		fmt.Printf("  %-9s %-15s %s\n", severityLabel(f.Severity), f.Device, bold(f.Title))
		fmt.Printf("  %-9s %-15s %s\n", "", "", dim(f.Detail))
		// The fix is the point. Without it this is a list of homework.
		if f.Fix != "" {
			fmt.Printf("  %-9s %-15s %s %s\n", "", "", bold("→ Fix:"), f.Fix)
		}
		for _, line := range strings.Split(f.Command, "\n") {
			if line != "" {
				fmt.Printf("  %-9s %-15s   %s\n", "", "", cmd(line))
			}
		}
		if f.Count > 1 {
			fmt.Printf("  %-9s %-15s %s\n", "", "", dim(fmt.Sprintf("seen %d times", f.Count)))
		}
		fmt.Println()
	}
}

func severityLabel(s identify.Severity) string {
	if !colour {
		return s.String()
	}
	switch s {
	case identify.SevCritical:
		return "\033[1;31m" + s.String() + "\033[0m"
	case identify.SevHigh:
		return "\033[31m" + s.String() + "\033[0m"
	case identify.SevMedium:
		return "\033[33m" + s.String() + "\033[0m"
	}
	return dim(s.String())
}

func usage() {
	fmt.Fprint(os.Stderr, `tarsier-scan — find every device on your network from Suricata's eve.json

usage:
  tarsier-scan [flags] <file|glob|directory>...
  cat eve.json | tarsier-scan [flags]

examples:
  tarsier-scan /var/log/suricata/eve.json
  tarsier-scan -last 24h /var/log/suricata/          # every rotated log, last day
  tarsier-scan -since 2026-07-28 -until 2026-07-30 'eve.json.*'
  tarsier-scan -html survey.html /var/log/suricata/  # shareable report

flags:
  -v                    show the evidence behind each identification
  -min-confidence 0.5   hide devices identified with low confidence
  -html FILE            write a self-contained HTML report
  -last 24h             only the most recent period (24h, 7d, 30m)
  -since 2026-07-28     only events at or after this time
  -until 2026-07-30     only events at or before this time

Suricata must be logging more than alerts. In suricata.yaml:

  outputs:
    - eve-log:
        types: [alert, flow, dns, http, tls, dhcp, smb, ssh, krb5, snmp, anomaly]

  and for TLS fingerprints:
    app-layer.protocols.tls.ja3-fingerprints: yes
`)
}

// window turns the time flags into a concrete range.
func window(last, since, until string) (from, to time.Time, err error) {
	if last != "" {
		d, e := parseSpan(last)
		if e != nil {
			return from, to, e
		}
		return time.Now().Add(-d), time.Time{}, nil
	}
	if since != "" {
		if from, err = parseWhen(since, false); err != nil {
			return
		}
	}
	if until != "" {
		if to, err = parseWhen(until, true); err != nil {
			return
		}
	}
	return
}

// parseSpan accepts Go durations plus "d" for days, which is what people
// actually type when they mean "the last week".
func parseSpan(s string) (time.Duration, error) {
	if n := strings.TrimSuffix(s, "d"); n != s {
		days, err := strconv.Atoi(n)
		if err != nil || days <= 0 {
			return 0, errors.New("bad period: " + s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("bad period: " + s + " (try 24h, 7d, 30m)")
	}
	return d, nil
}

// parseWhen accepts a date or a date and time. A bare date as an upper bound
// means the end of that day, because "until the 30th" includes the 30th.
func parseWhen(s string, endOfDay bool) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04",
		"2006-01-02 15:04:05", "2006-01-02 15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		if endOfDay {
			return t.Add(24*time.Hour - time.Nanosecond), nil
		}
		return t, nil
	}
	return time.Time{}, errors.New("bad time: " + s + " (try 2026-07-30 or 2026-07-30T09:00)")
}

// expand resolves arguments into a list of files: literal paths, shell globs
// the shell did not expand, and directories of rotated logs.
func expand(args []string) ([]string, error) {
	if len(args) == 0 {
		return []string{"-"}, nil
	}
	var out []string
	for _, a := range args {
		if a == "-" {
			out = append(out, a)
			continue
		}
		fi, err := os.Stat(a)
		if err == nil && fi.IsDir() {
			found, _ := filepath.Glob(filepath.Join(a, "eve*.json*"))
			if len(found) == 0 {
				return nil, errors.New("no eve.json files in " + a)
			}
			sort.Strings(found)
			out = append(out, found...)
			continue
		}
		if err == nil {
			out = append(out, a)
			continue
		}
		matches, _ := filepath.Glob(a)
		if len(matches) == 0 {
			return nil, errors.New("no such file: " + a)
		}
		sort.Strings(matches)
		out = append(out, matches...)
	}
	return out, nil
}

func openOne(arg string) (io.ReadCloser, error) {
	if arg == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	f, err := os.Open(arg)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(arg, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{gz, f}, nil
	}
	return f, nil
}

func describeInputs(in []string) string {
	if len(in) == 1 {
		if in[0] == "-" {
			return "stdin"
		}
		return filepath.Base(in[0])
	}
	return fmt.Sprintf("%d log files", len(in))
}

func printHeader(name string, total, skipped int, devices []*identify.Device) {
	fmt.Printf("\n  %s\n", bold("Tarsier"))
	fmt.Printf("  read %s — %s events", name, comma(total))
	if skipped > 0 {
		fmt.Printf(", %s unparseable", comma(skipped))
	}
	fmt.Printf("\n\n  %s\n\n", bold(fmt.Sprintf("%d devices found on your network", len(devices))))
}

// printCoverage tells the user what Suricata is and is not logging. The most
// common reason this tool underperforms is that eve-log is alert-only, and the
// user has no way to know that unless we say so.
func printCoverage(counts map[string]int) {
	wanted := []struct {
		Type string
		Why  string
	}{
		{"dhcp", "device names, MAC addresses, vendor and OS"},
		{"dns", "friendly device names"},
		{"tls", "certificates, TLS fingerprints, shadow IT"},
		{"http", "operating systems, browsers, embedded devices"},
		{"flow", "which devices serve which ports"},
		{"smb", "Windows hostnames and usernames"},
		{"krb5", "usernames and Active Directory realm"},
		{"ssh", "operating system detail"},
	}
	var missing []string
	for _, w := range wanted {
		if counts[w.Type] == 0 {
			missing = append(missing, fmt.Sprintf("    %-6s missing — no %s", w.Type, w.Why))
		}
	}
	if len(missing) == 0 {
		return
	}
	fmt.Printf("  %s\n", dim("Suricata is not logging everything Tarsier can use:"))
	for _, m := range missing {
		fmt.Println(dim(m))
	}
	fmt.Printf("%s\n\n", dim("    → enable these event types in suricata.yaml for much better results"))
}

func printDevices(devices []*identify.Device, minConf float64, verbose bool) {
	for _, d := range devices {
		if d.Confidence() < minConf {
			continue
		}
		fmt.Printf("  %-15s %s\n", bold(d.IP), describe(d))

		if n := d.BestHostname(); n != "" {
			fmt.Printf("  %-15s %s\n", "", dim("name:     "+n))
		}
		if d.MAC != "" {
			mac := d.MAC
			if d.Vendor != "" {
				mac += "  (" + d.Vendor + ")"
			}
			fmt.Printf("  %-15s %s\n", "", dim("mac:      "+mac))
		}
		if users := d.SortedUsers(); len(users) > 0 {
			fmt.Printf("  %-15s %s\n", "", dim("users:    "+strings.Join(users, ", ")))
		}
		if svcs := d.SortedServices(); len(svcs) > 0 {
			fmt.Printf("  %-15s %s\n", "", dim("serving:  "+serviceList(svcs)))
		}
		if n := len(d.ExternalDsts); n > 0 {
			fmt.Printf("  %-15s %s\n", "", dim(fmt.Sprintf("external: %d destinations", n)))
		}
		if d.Alerts > 0 {
			fmt.Printf("  %-15s %s\n", "", dim(fmt.Sprintf("alerts:   %d", d.Alerts)))
		}
		if verbose && len(d.Evidence) > 0 {
			fmt.Printf("  %-15s %s\n", "", dim("why:"))
			for _, e := range dedupeEvidence(d.Evidence) {
				fmt.Printf("  %-15s %s\n", "", dim(fmt.Sprintf("    %-24s %-34s → %s (%.2f)",
					e.Signal, truncate(e.Value, 34), e.Conclusion, e.Weight)))
			}
		}
		fmt.Println()
	}
}

// describe builds the one-line identity, always with its confidence attached.
// Never present an inference as a fact.
func describe(d *identify.Device) string {
	var parts []string
	if d.Vendor != "" {
		parts = append(parts, d.Vendor)
	}
	if d.OS != "" {
		parts = append(parts, d.OS)
	}
	if d.Class != identify.ClassUnknown {
		parts = append(parts, string(d.Class))
	}
	if len(parts) == 0 {
		return dim("unidentified")
	}
	return fmt.Sprintf("%s  %s", strings.Join(parts, " · "),
		dim(fmt.Sprintf("(%.0f%% confident)", d.Confidence()*100)))
}

func serviceList(svcs []*identify.Service) string {
	var out []string
	for i, s := range svcs {
		if i == 8 {
			out = append(out, fmt.Sprintf("+%d more", len(svcs)-8))
			break
		}
		label := fmt.Sprintf("%d", s.Port)
		if s.AppProto != "" {
			label += "/" + s.AppProto
		}
		out = append(out, label)
	}
	return strings.Join(out, " ")
}

func printSummary(devices []*identify.Device) {
	byClass := map[identify.Class]int{}
	identified, withNames, withUsers := 0, 0, 0
	for _, d := range devices {
		byClass[d.Class]++
		if d.Class != identify.ClassUnknown {
			identified++
		}
		if len(d.Hostnames) > 0 {
			withNames++
		}
		if len(d.Users) > 0 {
			withUsers++
		}
	}
	fmt.Printf("  %s\n", bold("SUMMARY"))
	fmt.Printf("  %d devices · %d identified · %d named · %d with known users\n\n",
		len(devices), identified, withNames, withUsers)

	type kv struct {
		c identify.Class
		n int
	}
	var rows []kv
	for c, n := range byClass {
		if c != identify.ClassUnknown {
			rows = append(rows, kv{c, n})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	for _, r := range rows {
		fmt.Printf("    %-14s %d\n", r.c, r.n)
	}
	if n := byClass[identify.ClassUnknown]; n > 0 {
		fmt.Printf("    %-14s %d\n", dim("unidentified"), n)
	}
	fmt.Println()
}

func dedupeEvidence(in []identify.Evidence) []identify.Evidence {
	seen := map[string]bool{}
	var out []identify.Evidence
	for _, e := range in {
		k := e.Signal + "|" + e.Value + "|" + e.Conclusion
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func comma(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// Colour is disabled when output is redirected, so reports stay readable.
var colour = func() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func bold(s string) string {
	if !colour {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

func dim(s string) string {
	if !colour {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

// cmd styles a runnable command so it stands out as something to copy.
func cmd(s string) string {
	if !colour {
		return s
	}
	return "\033[36m" + s + "\033[0m"
}
