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
		if err := inventory.WriteText(os.Stdout, before, after, d); err != nil {
			fmt.Fprintln(os.Stderr, "tarsier-diff:", err)
			os.Exit(1)
		}
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
