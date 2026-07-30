// Command tarsier-diff compares two inventory snapshots and reports what
// changed on the network between them.
//
// An inventory answers "what is on my network". That is interesting once. This
// answers "what changed since Friday", which is the question worth asking every
// week — and it is the form in which the genuinely alarming things surface. A
// new device on a segment that should be closed, a printer that started
// answering on 3389, a controller whose firmware version moved without a change
// window: none of those are visible in any single scan, however good it is.
//
//	tarsier-scan -json monday.json  /var/log/suricata/eve.json
//	tarsier-scan -json friday.json  /var/log/suricata/eve.json
//	tarsier-diff monday.json friday.json
//
// Exit status is 0 when nothing changed and 1 when something did, so it can be
// run from cron and only speak up when it has something to say.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"tarsier/internal/inventory"
)

func main() {
	asJSON := flag.Bool("json", false, "emit the diff as JSON instead of text")
	quiet := flag.Bool("q", false, "print nothing; use the exit status alone")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 2 {
		usage()
		os.Exit(2)
	}

	before, err := load(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarsier-diff:", err)
		os.Exit(2)
	}
	after, err := load(flag.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tarsier-diff:", err)
		os.Exit(2)
	}

	d := inventory.Compare(before, after)

	switch {
	case *quiet:
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			fmt.Fprintln(os.Stderr, "tarsier-diff:", err)
			os.Exit(2)
		}
	default:
		printDiff(before, after, d)
	}

	if d.Empty() {
		return
	}
	os.Exit(1)
}

func load(path string) (inventory.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	defer f.Close()
	snap, err := inventory.Read(f)
	if err != nil {
		return snap, fmt.Errorf("%s: %w", path, err)
	}
	return snap, nil
}

func printDiff(before, after inventory.Snapshot, d inventory.Diff) {
	fmt.Println()
	fmt.Printf("  %s → %s\n",
		before.Generated.Format("2 Jan 2006 15:04"),
		after.Generated.Format("2 Jan 2006 15:04"))
	fmt.Printf("  %d devices → %d devices\n\n", len(before.Devices), len(after.Devices))

	if d.Empty() {
		fmt.Println("  Nothing changed.")
		fmt.Println()
		return
	}

	// Appeared first. A device that was not there before is the single thing
	// most likely to need action today.
	if len(d.Appeared) > 0 {
		fmt.Printf("  %d NEW\n\n", len(d.Appeared))
		for _, c := range d.Appeared {
			fmt.Printf("    + %-15s %s\n", c.IP, c.Label)
			if c.Detail != "" {
				fmt.Printf("      %s\n", c.Detail)
			}
		}
		fmt.Println()
	}

	if len(d.Changed) > 0 {
		fmt.Printf("  %d CHANGED\n\n", len(d.Changed))
		for _, c := range d.Changed {
			fmt.Printf("    ~ %-15s %s\n", c.IP, c.Label)
			for _, f := range c.Fields {
				if f.List {
					// An additive change: these items joined or left a set, so
					// there is no "from" value to show.
					v := f.To
					if v == "" {
						v = f.From
					}
					fmt.Printf("      %-18s %s\n", f.Field, v)
					continue
				}
				// A scalar always shows both sides, so that a value appearing
				// for the first time does not read as an addition to a list.
				fmt.Printf("      %-18s %s → %s\n", f.Field, orNone(f.From), orNone(f.To))
			}
		}
		fmt.Println()
	}

	// Gone last, and phrased carefully. A device missing from the second scan
	// was very often just switched off, or talking to nothing the sensor could
	// see. Reporting that as a disappearance without saying so invites people
	// to chase machines that were only asleep.
	if len(d.Disappeared) > 0 {
		fmt.Printf("  %d NO LONGER SEEN\n\n", len(d.Disappeared))
		for _, c := range d.Disappeared {
			fmt.Printf("    - %-15s %s\n", c.IP, c.Label)
		}
		fmt.Println("      These were silent for the whole second capture. Powered off and")
		fmt.Println("      decommissioned look identical from here.")
		fmt.Println()
	}

	if len(d.NewFindings) > 0 {
		fmt.Printf("  %d NEW FINDINGS\n\n", len(d.NewFindings))
		for _, f := range d.NewFindings {
			fmt.Printf("    %-9s %-15s %s\n", f.Severity, f.Device, f.Title)
		}
		fmt.Println()
	}

	if len(d.FixedFindings) > 0 {
		fmt.Printf("  %d RESOLVED\n\n", len(d.FixedFindings))
		for _, f := range d.FixedFindings {
			fmt.Printf("    %-9s %-15s %s\n", f.Severity, f.Device, f.Title)
		}
		fmt.Println()
	}
}

// orNone renders an absent value, so "(none) → workstation" reads as an
// identification that was made rather than one that changed.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func usage() {
	fmt.Fprint(os.Stderr, `
tarsier-diff — what changed on the network between two scans

  tarsier-diff BEFORE.json AFTER.json

Snapshots come from tarsier-scan -json:

  tarsier-scan -json monday.json /var/log/suricata/eve.json
  tarsier-scan -json friday.json /var/log/suricata/eve.json
  tarsier-diff monday.json friday.json

Options:
  -json    emit the diff as JSON
  -q       print nothing, use the exit status alone

Exit status is 0 when nothing changed and 1 when something did, so this can run
from cron and stay quiet until it has something to report.

`)
}
