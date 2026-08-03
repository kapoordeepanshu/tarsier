package inventory

import (
	"fmt"
	"io"
)

// WriteText renders a diff for a person to read.
//
// It lives here rather than in a command so that the tool you run by hand and
// the watcher that mails you at 7am describe the same change in the same words.
// Two renderers would drift, and the one nobody looks at would drift first.
func WriteText(w io.Writer, before, after Snapshot, d Diff) error {
	p := &printer{w: w}

	p.printf("\n  %s → %s\n",
		before.Generated.Format("2 Jan 2006 15:04"),
		after.Generated.Format("2 Jan 2006 15:04"))
	p.printf("  %d devices → %d devices\n\n", len(before.Devices), len(after.Devices))

	if d.Empty() {
		p.printf("  Nothing changed.\n\n")
		return p.err
	}

	// Appeared first. A device that was not there before is the single thing
	// most likely to need action today.
	if len(d.Appeared) > 0 {
		p.printf("  %d NEW\n\n", len(d.Appeared))
		for _, c := range d.Appeared {
			p.printf("    + %-15s %s\n", c.IP, c.Label)
			if c.Detail != "" {
				p.printf("      %s\n", c.Detail)
			}
		}
		p.printf("\n")
	}

	if len(d.Changed) > 0 {
		p.printf("  %d CHANGED\n\n", len(d.Changed))
		for _, c := range d.Changed {
			p.printf("    ~ %-15s %s\n", c.IP, c.Label)
			for _, f := range c.Fields {
				if f.List {
					// An additive change: these items joined or left a set, so
					// there is no "from" value to show.
					v := f.To
					if v == "" {
						v = f.From
					}
					p.printf("      %-18s %s\n", f.Field, v)
					continue
				}
				// A scalar always shows both sides, so that a value appearing
				// for the first time does not read as an addition to a list.
				p.printf("      %-18s %s → %s\n", f.Field, orNone(f.From), orNone(f.To))
			}
		}
		p.printf("\n")
	}

	// Gone last, and phrased carefully. A device missing from the second scan
	// was very often just switched off, or talking to nothing the sensor could
	// see. Reporting that as a disappearance without saying so invites people
	// to chase machines that were only asleep.
	if len(d.Disappeared) > 0 {
		p.printf("  %d NO LONGER SEEN\n\n", len(d.Disappeared))
		for _, c := range d.Disappeared {
			p.printf("    - %-15s %s\n", c.IP, c.Label)
		}
		p.printf("      These were silent for the whole second capture. Powered off and\n")
		p.printf("      decommissioned look identical from here.\n\n")
	}

	if len(d.NewFindings) > 0 {
		p.printf("  %d NEW FINDINGS\n\n", len(d.NewFindings))
		for _, f := range d.NewFindings {
			p.printf("    %-9s %-15s %s\n", f.Severity, f.Device, f.Title)
		}
		p.printf("\n")
	}

	if len(d.FixedFindings) > 0 {
		p.printf("  %d RESOLVED\n\n", len(d.FixedFindings))
		for _, f := range d.FixedFindings {
			p.printf("    %-9s %-15s %s\n", f.Severity, f.Device, f.Title)
		}
		p.printf("\n")
	}
	return p.err
}

// printer keeps the first write error and stops bothering the writer after it,
// so the body above stays readable instead of checking every line.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

// orNone renders an absent value, so "(none) → workstation" reads as an
// identification that was made rather than one that changed.
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
