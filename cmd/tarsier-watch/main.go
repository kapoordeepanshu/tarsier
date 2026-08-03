// tarsier-watch keeps an inventory current by following eve.json as Suricata
// writes it.
//
// The scanner reads a file and exits, which means someone has to remember to run
// it. This does not: it attaches to the live log, folds each record in as it
// arrives, and rewrites the report on a timer. The useful question stops being
// "what was on the network when I last looked" and becomes "what is on it now,
// and what changed".
//
// It holds a rolling window rather than everything ever seen. Raw traffic stays
// what it already is — a short-lived buffer that Suricata and logrotate manage —
// and what survives here is the conclusions, which are small enough that a month
// of them fits comfortably in memory on a mini-PC.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tarsier/internal/eve"
	"tarsier/internal/identify"
	"tarsier/internal/inventory"
	"tarsier/internal/report"
	"tarsier/internal/tail"
)

func main() {
	var (
		htmlOut = flag.String("html", "", "rewrite this HTML report as events arrive")
		jsonOut = flag.String("json", "", "rewrite this JSON inventory as events arrive")
		every   = flag.Duration("every", time.Minute, "how often to rewrite the outputs")
		poll    = flag.Duration("poll", 2*time.Second, "how often to check the log for new data")
		retain  = flag.String("retain", "30d", "forget devices silent for longer than this (0 to keep everything)")
		catchup = flag.Bool("catchup", true, "replay the rotated logs beside the live file on start")
		quiet   = flag.Bool("q", false, "only report problems")

		notify   = flag.Duration("notify", time.Hour, "how often to report what changed (0 to disable)")
		changes  = flag.String("changes", "", "append each change report to this file as JSON")
		onChange = flag.String("on-change", "", "run this command when something changes, report on stdin")
		zones    = flag.String("zones", "", "check traffic against a segmentation policy file")
	)
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}
	path := flag.Arg(0)

	if *htmlOut == "" && *jsonOut == "" {
		die("nothing to write — pass -html, -json, or both")
	}
	retention, err := parseSpan(*retain)
	if err != nil {
		die("-retain: " + err.Error())
	}

	// Fail now rather than in an hour. A watcher that silently follows a path
	// that will never exist is worse than one that refuses to start.
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		die("cannot read " + filepath.Dir(path) + ": " + err.Error())
	}

	res := identify.NewResolver()
	if *zones != "" {
		f, err := os.Open(*zones)
		if err != nil {
			die("-zones: " + err.Error())
		}
		policy, err := identify.ParsePolicy(f)
		f.Close()
		if err != nil {
			die("-zones: " + err.Error())
		}
		res.SetPolicy(policy)
	}

	w := &watcher{
		path:        path,
		res:         res,
		htmlOut:     *htmlOut,
		jsonOut:     *jsonOut,
		retention:   retention,
		quiet:       *quiet,
		notifyEvery: *notify,
		changesOut:  *changes,
		onChange:    *onChange,
	}

	if *catchup {
		w.replayRotated()
	}
	w.run(*poll, *every)
}

type watcher struct {
	path string
	res  *identify.Resolver

	htmlOut, jsonOut string
	retention        time.Duration
	quiet            bool

	// Change reporting. baseline is the inventory as it stood at the last
	// report, so each one answers "what changed since I last told you" rather
	// than "what changed since the process started".
	notifyEvery time.Duration
	changesOut  string
	onChange    string
	baseline    inventory.Snapshot

	events  int
	skipped int
	// dirty records that something arrived since the last write, so a quiet
	// network does not have its report rewritten identically every minute.
	dirty bool
}

// replayRotated rebuilds the picture from the logs already on disk.
//
// Restarting must not amount to forgetting the network. Rather than persisting
// our own state — one more thing to corrupt, and stale in a way nobody would
// notice — the history is rebuilt from what Suricata already wrote. Whatever
// rotation has kept is the window we start with.
func (w *watcher) replayRotated() {
	files := rotatedSiblings(w.path)
	if len(files) == 0 {
		return
	}
	for _, p := range files {
		in, err := openLog(p)
		if err != nil {
			warn("skipping " + p + ": " + err.Error())
			continue
		}
		rd := eve.NewReader(in)
		for rec := rd.Next(); rec != nil; rec = rd.Next() {
			w.res.Add(rec)
		}
		t, s := rd.Stats()
		w.events += t
		w.skipped += s
		in.Close()
	}
	w.say(fmt.Sprintf("replayed %d rotated %s — %s events",
		len(files), plural(len(files), "log", "logs"), comma(w.events)))
}

func (w *watcher) run(poll, every time.Duration) {
	f := tail.New(w.path)
	defer f.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	pollTick := time.NewTicker(poll)
	defer pollTick.Stop()
	writeTick := time.NewTicker(every)
	defer writeTick.Stop()

	w.say("following " + w.path + " — writing " + strings.Join(w.outputs(), " and ") +
		" every " + every.String())

	// Read what is already in the live file before writing anything. Waiting a
	// full interval before producing output makes a working watcher look broken,
	// but publishing an empty report first is worse — someone will open it.
	if _, err := f.Poll(w.consume); err != nil {
		warn("reading " + w.path + ": " + err.Error())
	}
	w.refresh()

	// The first report compares against the network as we found it, not against
	// nothing — otherwise every device on site would be announced as new.
	w.baseline = w.snapshot()

	var notifyTick <-chan time.Time
	if w.notifyEvery > 0 {
		t := time.NewTicker(w.notifyEvery)
		defer t.Stop()
		notifyTick = t.C
	}

	rotations, truncations := 0, 0
	for {
		select {
		case <-stop:
			w.say("stopping")
			w.refresh()
			return

		case <-pollTick.C:
			n, err := f.Poll(w.consume)
			if err != nil {
				warn("reading " + w.path + ": " + err.Error())
			}
			if n > 0 {
				w.dirty = true
			}
			// Rotation is routine, but a burst of it says something about the
			// sensor's disk, so it is reported rather than swallowed.
			if f.Rotations != rotations {
				rotations = f.Rotations
				w.say("log rotated")
			}
			if f.Truncations != truncations {
				truncations = f.Truncations
				w.say("log truncated in place")
			}

		case <-writeTick.C:
			if !w.dirty {
				continue
			}
			w.refresh()
			w.dirty = false

		case <-notifyTick:
			w.report()
		}
	}
}

// consume folds one line into the model. A line that will not parse is counted
// and dropped: half a record caught mid-write is normal and must never stop us.
func (w *watcher) consume(line []byte) {
	if len(bytes.TrimSpace(line)) == 0 {
		return
	}
	w.events++
	rec := eve.ParseLine(line)
	if rec == nil {
		w.skipped++
		return
	}
	w.res.Add(rec)
}

func (w *watcher) refresh() {
	if w.retention > 0 {
		if dropped := w.res.Prune(time.Now().Add(-w.retention)); dropped > 0 {
			w.say(fmt.Sprintf("forgot %d %s silent for over %s",
				dropped, plural(dropped, "device", "devices"), w.retention))
		}
	}

	devices := w.res.Devices()
	findings := w.res.Findings()

	if w.htmlOut != "" {
		rep := report.Build(w.path, w.events, w.skipped, devices, findings,
			w.res.EventCounts(), w.res.First, w.res.Last)
		if err := writeAtomic(w.htmlOut, func(f io.Writer) error {
			return report.Write(f, rep)
		}); err != nil {
			warn("writing " + w.htmlOut + ": " + err.Error())
		}
	}
	if w.jsonOut != "" {
		snap := inventory.Build(w.path, w.events, w.skipped, devices, findings,
			w.res.First, w.res.Last, time.Now())
		if err := writeAtomic(w.jsonOut, func(f io.Writer) error {
			return inventory.Write(f, snap)
		}); err != nil {
			warn("writing " + w.jsonOut + ": " + err.Error())
		}
	}

	w.say(fmt.Sprintf("%d %s · %d %s · %s events",
		len(devices), plural(len(devices), "device", "devices"),
		len(findings), plural(len(findings), "finding", "findings"),
		comma(w.events)))
}

func (w *watcher) snapshot() inventory.Snapshot {
	return inventory.Build(w.path, w.events, w.skipped, w.res.Devices(), w.res.Findings(),
		w.res.First, w.res.Last, time.Now())
}

// report says what changed since the last time it said anything.
//
// Silence when nothing changed is the point. A notification that arrives every
// hour regardless teaches people to filter it, and then the one that mattered
// gets filtered too.
//
// One honest limit: a device is only reported as no longer seen once retention
// forgets it, which at the default is thirty days. Devices go quiet for a night
// all the time, and reporting that hourly would be noise pretending to be
// signal.
func (w *watcher) report() {
	current := w.snapshot()
	d := inventory.Compare(w.baseline, current)
	if d.Empty() {
		w.baseline = current
		return
	}

	var body strings.Builder
	if err := inventory.WriteText(&body, w.baseline, current, d); err != nil {
		warn("rendering changes: " + err.Error())
		return
	}

	w.say(summarise(d))
	if w.changesOut != "" {
		w.appendChanges(d)
	}
	if w.onChange != "" {
		w.runHook(body.String(), d)
	}
	// Only advance once it has been reported. If a hook fails the change is
	// still news next time round rather than silently spent.
	w.baseline = current
}

func summarise(d inventory.Diff) string {
	var parts []string
	if n := len(d.Appeared); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new", n))
	}
	if n := len(d.Changed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", n))
	}
	if n := len(d.Disappeared); n > 0 {
		parts = append(parts, fmt.Sprintf("%d gone", n))
	}
	if n := len(d.NewFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new %s", n, plural(n, "finding", "findings")))
	}
	if n := len(d.FixedFindings); n > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", n))
	}
	return "changed: " + strings.Join(parts, ", ")
}

// appendChanges writes one JSON object per report, which is the shape anything
// that tails a file already expects.
func (w *watcher) appendChanges(d inventory.Diff) {
	f, err := os.OpenFile(w.changesOut, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		warn("opening " + w.changesOut + ": " + err.Error())
		return
	}
	defer f.Close()

	rec := struct {
		At     time.Time `json:"at"`
		Source string    `json:"source"`
		inventory.Diff
	}{time.Now().UTC(), w.path, d}

	if err := json.NewEncoder(f).Encode(rec); err != nil {
		warn("writing " + w.changesOut + ": " + err.Error())
	}
}

// runHook hands the report to whatever the operator wants to do with it. We
// deliberately do not speak SMTP, Slack or webhooks: that would mean holding
// credentials for a network we are only supposed to be watching, and every site
// already has a way to send a message.
//
// It runs through the shell, because that is what anyone typing -on-change
// expects, and with a timeout, because a hung mail command must not stall the
// watcher indefinitely.
func (w *watcher) runHook(body string, d inventory.Diff) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := hookCommand(ctx, w.onChange)
	cmd.Stdin = strings.NewReader(body)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	// Counts in the environment, so a script can decide whether to page someone
	// without parsing the text we just handed it.
	cmd.Env = append(os.Environ(),
		"TARSIER_NEW="+strconv.Itoa(len(d.Appeared)),
		"TARSIER_CHANGED="+strconv.Itoa(len(d.Changed)),
		"TARSIER_GONE="+strconv.Itoa(len(d.Disappeared)),
		"TARSIER_NEW_FINDINGS="+strconv.Itoa(len(d.NewFindings)),
		"TARSIER_TOTAL="+strconv.Itoa(d.Total()),
		"TARSIER_SOURCE="+w.path,
	)

	if err := cmd.Run(); err != nil {
		warn("-on-change command failed: " + err.Error())
	}
}

func (w *watcher) outputs() []string {
	var out []string
	if w.htmlOut != "" {
		out = append(out, w.htmlOut)
	}
	if w.jsonOut != "" {
		out = append(out, w.jsonOut)
	}
	return out
}

func (w *watcher) say(msg string) {
	if w.quiet {
		return
	}
	fmt.Fprintf(os.Stderr, "%s  %s\n", time.Now().Format("15:04:05"), msg)
}

// writeAtomic writes through a temporary file and renames it into place, so a
// browser reloading the report never catches it half-written.
func writeAtomic(path string, write func(io.Writer) error) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// rotatedSiblings lists the rotated logs beside the live file, oldest first.
//
// Ordered by modification time rather than by name. Rotation schemes name files
// in at least four different ways — a counter, a date, a Unix timestamp, plus
// .gz on some of them — and none of those sort chronologically as strings.
func rotatedSiblings(live string) []string {
	matches, err := filepath.Glob(live + "*")
	if err != nil {
		return nil
	}
	type entry struct {
		path string
		mod  time.Time
	}
	var found []entry
	for _, m := range matches {
		if filepath.Clean(m) == filepath.Clean(live) {
			continue
		}
		fi, err := os.Stat(m)
		if err != nil || fi.IsDir() {
			continue
		}
		found = append(found, entry{m, fi.ModTime()})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].mod.Before(found[j].mod) })

	out := make([]string, 0, len(found))
	for _, e := range found {
		out = append(out, e.path)
	}
	return out
}

func openLog(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".gz") {
		return f, nil
	}
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

// parseSpan accepts what a person would write: 24h, 7d, 30m. "0" disables.
func parseSpan(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("not a number of days: %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func comma(n int) string {
	s := strconv.Itoa(n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func warn(msg string) { fmt.Fprintln(os.Stderr, "tarsier-watch: "+msg) }

func die(msg string) {
	warn(msg)
	os.Exit(2)
}

func usage() {
	fmt.Fprint(os.Stderr, `tarsier-watch — keep the inventory current by following eve.json

usage:
  tarsier-watch [flags] <eve.json>

examples:
  tarsier-watch -html /var/www/survey.html /var/log/suricata/eve.json
  tarsier-watch -html survey.html -json inventory.json -every 5m /var/log/suricata/eve.json
  tarsier-watch -retain 7d -q -json inventory.json /var/log/suricata/eve.json

  # mail a change report, but only when there is one
  tarsier-watch -html survey.html -notify 1h \
    -on-change 'mail -s "network changed" you@example.com' /var/log/suricata/eve.json

flags:
  -html FILE      rewrite this HTML report as events arrive
  -json FILE      rewrite this JSON inventory as events arrive
  -every 1m       how often to rewrite the outputs
  -poll 2s        how often to check the log for new data
  -retain 30d     forget devices silent for longer than this (0 keeps everything)
  -catchup        replay the rotated logs beside the live file on start (default true)
  -notify 1h      how often to report what changed (0 disables)
  -changes FILE   append each change report to this file, one JSON object per line
  -on-change CMD  run this when something changes, with the report on stdin
  -q              only report problems

Change reports are silent when nothing changed. The command given to -on-change
runs through the shell with the readable report on stdin and the counts in the
environment — TARSIER_NEW, TARSIER_CHANGED, TARSIER_GONE, TARSIER_NEW_FINDINGS,
TARSIER_TOTAL and TARSIER_SOURCE — so a script can decide whether to wake
somebody without parsing anything.

Nothing here speaks SMTP, Slack or webhooks on your behalf. Holding credentials
for a network we are only meant to be watching is not a trade worth making, and
your site already has a way to send a message.

It follows the live file across rotation, both by rename and by copy-truncate,
and holds a partial last line until the writer finishes it. Nothing is written
back to the log directory and Suricata is never blocked: if we cannot keep up we
fall behind and say so, rather than applying backpressure to the sensor.

Outputs are written through a temporary file and renamed into place, so a
browser reloading the report never catches it half-written.
`)
}
