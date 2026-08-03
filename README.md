# Tarsier — every device on your network, from the logs you already have

**Point it at Suricata's `eve.json` and it tells you every device on your network, what each one
is, and what's wrong with it.** One binary, one file, no agents, no scanning, no credentials.

Suricata already parses DHCP, ARP, TLS, Kerberos, SMB, SNMP, SSH, Modbus and twenty other
protocols. Almost every deployment uses the `alert` records and treats the rest as log volume.
That rest is a complete, continuously updated inventory of your network. Tarsier reads it.

<sub>Open-source **Suricata dashboard** and **eve.json analyser** for **passive network discovery**,
**network asset inventory** and **device fingerprinting** — a free, self-hosted **Suricata web UI**
and **IDS visibility** tool. Runs on OPNsense, pfSense, Docker, bare metal and cloud traffic
mirrors.</sub>

---

> ### What works today
> **The scanner and the watcher.** Point `tarsier-scan` at an `eve.json` for a one-shot report, or
> leave `tarsier-watch` following the live log to keep one current. Both are real and you can run
> them in two minutes.
>
> **Not yet built:** a server, a web UI, and a remote agent. Those are described under
> [Where this is going](#where-this-is-going), in future tense, with no commands — because none of
> them exist yet and pretending otherwise would waste your afternoon.
>
> **Wanted:** people to run it on a real network and tell us what it got wrong. Wrong
> identifications are worth more to us than right ones — see [Contributing](#contributing).

---

## What it looks like

<!-- This is a drawing of the interface, not a screenshot. Replace it with real
     captures as soon as you have them — nothing sells a tool like the real thing:
       tarsier-scan -html survey.html testdata/demo-week.json
     Then capture at ~1400px wide, browser chrome cropped:
       docs/img/survey-dark.png   — the whole dashboard. THIS ONE MATTERS MOST:
                                    GitHub uses the first image for link previews,
                                    so it is what people see shared on Slack and social.
       docs/img/findings.png      — the findings pane
       docs/img/evidence.png      — one device expanded, showing the evidence table -->

![The Tarsier dashboard: device inventory with confidence rings, findings with fixes, and an activity
timeline used as a time-range selector](docs/img/dashboard.png)

<sub>*Illustration of the report, not a screenshot. Left: every device, what it is, and how confident
we are — the ring around each icon fills to its confidence. Right: what's actually wrong, each with a
fix and, where one exists, a command to copy. Top: the time range — it opens on the last 24 hours,
and you can pick 3, 7, 14 or 30 days, or drag the chart for any window.*</sub>

**The whole report is one self-contained HTML file.** No server, no internet, no dependencies — it
opens from a USB stick on a machine that has never been online, which is often exactly where this
work happens.

---

## Before you install

**What this touches:** one log file, read-only. Tarsier runs as an unprivileged user, is never in
the traffic path, never transmits, and never modifies Suricata or its configuration. Stop it and
nothing on your network notices. Removing it is deleting one binary and one directory.

**What you need:**

| | |
|---|---|
| **Suricata** | any version — 6.0 and up are tested in CI. ARP events need 8.0+, JA4 needs 7.0.7+. Older builds work, they just tell you less. |
| **Event types** | more than `alert`. See [Configure Suricata](#configure-suricata) — `tarsier-scan` reports what's missing, so you don't have to guess. |
| **Access** | read permission on the log directory, usually `/var/log/suricata/`. |
| **Disk** | none for the scanner. It reads and exits. |
| **Not needed** | root, a database, Docker, internet access, an agent on anything. |

If SELinux or AppArmor is enforcing, the reading process needs access to the Suricata log directory.
On a stock RHEL-family box, running as a user in the `suricata` group is enough.

---

## Install

Prebuilt binaries, no toolchain:

```bash
base=https://github.com/kapoordeepanshu/tarsier/releases/latest/download
for tool in tarsier-scan tarsier-watch tarsier-diff; do
  curl -fLO "$base/${tool}-linux-amd64"
done
curl -fLO "$base/SHA256SUMS.txt"
sha256sum --ignore-missing -c SHA256SUMS.txt

for tool in tarsier-scan tarsier-watch tarsier-diff; do
  sudo install -m 0755 "${tool}-linux-amd64" "/usr/local/bin/${tool}"
done
```

Three tools, and you can stop after the first if all you want is a report:
`tarsier-scan` reads a log and exits, `tarsier-watch` follows one and keeps a report current, and
`tarsier-diff` compares two snapshots.

Builds are published for `linux/amd64`, `linux/arm64`, `linux/armv7`, **`freebsd/amd64`**
(OPNsense and pfSense, where most of the world's dormant Suricata installs live), macOS on both
architectures, and Windows.

**Air-gapped?** Copy the one binary across. It has no dependencies and never calls out.

<details>
<summary>Building from source instead</summary>

Needs [Go 1.22+](https://go.dev/dl/). Nothing else — no dependencies, no database, no Docker.

```bash
git clone https://github.com/kapoordeepanshu/tarsier.git
cd tarsier
go build ./cmd/tarsier-scan ./cmd/tarsier-watch ./cmd/tarsier-diff
```

Every tool is published for every target, so building is for contributors rather than operators.

</details>

---

## Verify it works

A week of realistic sample traffic ships with the repo, so you can see the output before touching
anything of your own:

```bash
tarsier-scan -html survey.html testdata/demo-week.json
```

```
wrote survey.html — 18 devices, 15 findings
```

Open `survey.html` in any browser. It opens on the **last 24 hours**, because that's the window
anyone actually checks — click **All** for the whole week: 18 devices and 15 things wrong with them,
each with a fix.

> **On Windows**, run it from PowerShell as `.\tarsier-scan.exe` — the leading `.\` is required,
> because Windows does not look in the current folder by default. Double-clicking will not work: it
> is a command-line tool and needs a file to read, so it would open and close instantly.

---

## Run it on your network

```bash
tarsier-scan /var/log/suricata/eve.json               # print to the terminal
tarsier-scan -v eve.json                              # show the evidence for every identification
tarsier-scan -last 24h /var/log/suricata/             # every rotated log, last day
tarsier-scan -since 2026-07-28 -until 2026-07-30 'eve.json.*'
tarsier-scan -html survey.html /var/log/suricata/     # shareable report
tarsier-scan -json monday.json /var/log/suricata/     # machine-readable inventory
tarsier-scan -netbox ips.csv /var/log/suricata/       # NetBox ipam.ip_addresses import
```

**Rotation is handled for you.** Point it at the directory and it finds every rotated log itself,
reading `.gz` files directly. You never pick files by hand. Read order doesn't matter either —
where a device reports something that changes over time, like a firmware version, the newest
observation wins regardless of which file was parsed first.

Flags: `-v`, `-min-confidence 0.5`, `-html`, `-json`, `-netbox`, `-last`, `-since`, `-until`. Run
`tarsier-scan -h` for the full list.

### What changed since last week

No server and no database — two snapshots and a diff:

```bash
tarsier-scan -json monday.json /var/log/suricata/
tarsier-scan -json friday.json /var/log/suricata/
tarsier-diff monday.json friday.json
```

It reports devices that appeared, devices that went quiet, and devices that changed — a new
listening port, a new user, a new VLAN, a firmware version that moved. Findings are matched on kind
rather than wording, so rewording a message doesn't present the whole network as newly broken.

Exit status is 0 when nothing changed and 1 when something did, so it runs from cron and stays
silent until it has something to say:

```cron
# Weekday mornings: snapshot, compare with yesterday, mail only on a change.
30 7 * * 1-5  tarsier-scan -json /var/lib/tarsier/today.json /var/log/suricata/ \
              && tarsier-diff /var/lib/tarsier/yesterday.json /var/lib/tarsier/today.json \
              || mail -s "network changed" you@example.com
```

---

## Keep it running

`tarsier-scan` reads a file and exits, which means somebody has to remember to run it.
`tarsier-watch` doesn't: it follows the live log and rewrites the report as events arrive.

```bash
tarsier-watch -html /var/www/survey.html /var/log/suricata/eve.json
```

```
14:02:11  replayed 4 rotated logs — 1,284,902 events
14:02:11  following /var/log/suricata/eve.json — writing /var/www/survey.html every 1m0s
14:02:11  214 devices · 11 findings · 1,284,902 events
```

**Rotation is handled, both kinds.** logrotate's default renames the file and creates a new one; a
lot of setups instead copy it and truncate it in place. Those need different handling, and assuming
only the first is how a log reader silently loses a chunk of every rotation. The file we hold is
drained to EOF before we let go of it, so the bytes written just before a rename are not lost. A
partial last line is held until the writer finishes it, so the parser never sees half a record.

**It holds a rolling window**, thirty days by default (`-retain`). A device silent for longer than
that is forgotten — otherwise "what is on my network" quietly becomes "what has ever been on my
network", and those are different questions. Raw traffic is never copied or kept: `eve.json` stays a
short-lived buffer that Suricata and logrotate manage, and what survives here is the conclusions,
which are small.

**It cannot affect Suricata.** We open the log read-only, never write to the log directory, and
never apply backpressure — if we fall behind we fall behind and say so. On Windows the handle is
opened so that rotation still works, because a reader that blocks logrotate has broken the thing it
was only supposed to watch.

Restarting is safe and needs no saved state: it replays the rotated logs still on disk to rebuild
the picture, then attaches to the live file. Whatever your rotation kept is the window you get back.

```ini
# /etc/systemd/system/tarsier.service
[Unit]
Description=Tarsier network inventory
After=suricata.service

[Service]
ExecStart=/usr/local/bin/tarsier-watch -html /var/www/survey.html /var/log/suricata/eve.json
User=tarsier
Restart=on-failure
ProtectSystem=strict
ReadOnlyPaths=/var/log/suricata
ReadWritePaths=/var/www
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

`tarsier-watch -h` for the full set of flags. It writes through a temporary file and renames into
place, so a browser reloading the report never catches it half-written.

### Being told, instead of remembering to look

The watcher already knows what changed. `-on-change` runs a command when something does — hourly by
default, and **silent when nothing did**:

```bash
tarsier-watch -html /var/www/survey.html \
  -on-change 'mail -s "network changed" you@example.com' \
  /var/log/suricata/eve.json
```

```
14:58:02  changed: 1 new, 1 changed

  3 Aug 2026 14:02 → 3 Aug 2026 14:58
  17 devices → 18 devices

  1 NEW

    + 10.0.20.9       plc-line-2
      10.0.20.9  00:1d:9c:aa:31:07  Rockwell Automation  ports 502
```

The report arrives on the command's stdin, and the counts arrive in its environment —
`TARSIER_NEW`, `TARSIER_CHANGED`, `TARSIER_GONE`, `TARSIER_NEW_FINDINGS`, `TARSIER_TOTAL`,
`TARSIER_SOURCE` — so a script can decide whether to wake somebody without parsing anything:

```bash
-on-change 'if [ "$TARSIER_NEW_FINDINGS" -gt 0 ]; then page-oncall; else cat >> /var/log/tarsier-changes.txt; fi'
```

`-changes FILE` appends one JSON object per report, which is the shape anything that tails a file
already expects. Every list is present even when empty, so `jq '.appeared | length'` works on a quiet
night instead of erroring on `null`.

**Nothing here speaks SMTP, Slack or webhooks on your behalf.** Holding credentials for a network we
are only meant to be watching is not a trade worth making, and your site already has a way to send a
message. Silence when nothing changed is the point: a notification that arrives every hour regardless
teaches people to filter it, and then the one that mattered gets filtered too.

**One honest limit.** A device is only reported as *no longer seen* once retention forgets it, which
at the default is thirty days. Devices go quiet for a night constantly, and reporting that hourly
would be noise wearing the costume of signal.

---

## Configure Suricata

Most installs log alerts only. Tarsier needs the metadata. One file, one restart, fully reversible —
in `suricata.yaml`:

```yaml
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes          # TLS fingerprinting for device identification

outputs:
  - eve-log:
      enabled: yes
      types:
        - alert
        - flow                       # which device serves which port
        - dns                        # friendly device names
        - http                       # operating systems, browsers, embedded devices
        - tls: {extended: yes}       # certificates, fingerprints, shadow IT
        - dhcp: {extended: yes}      # names, MACs, vendor — the single best signal
        - arp                        # every device on the segment, Suricata 8.0+
        - smb                        # Windows hostnames and usernames
        - krb5                       # usernames and AD realm
        - ssh
        - snmp
        - anomaly
```

`tarsier-scan` reports which of these are missing every time you run it, so you never have to guess
what you forgot.

**No Suricata at all?** The sensor image contains it, pre-configured for exactly this:

```bash
cd deploy/sensor && docker compose up -d
```

It auto-detects the capture interface, enables promiscuous mode, disables NIC offloading (which
corrupts protocol parsing), validates the config with `suricata -T` before starting, and drops every
Linux capability except the two it needs. Hardware: a spare VM, an old desktop, or a €150 Intel N100
mini-PC for a 1 Gbps network.

The image installs Suricata from OISF's own stable repository rather than the distribution's, so you
get a current release — **8.0.6 at the time of writing**. Distribution packages lag badly: Debian
bookworm ships 6.0, which has no ARP events and no JA4. Once built, the image is **pinned** and
nothing upgrades itself behind your back. **If you run your own Suricata, we never touch it.**

---

## What it can and can't see

Worth knowing before you deploy, not after.

**It sees:** every device that speaks, including the ones you can't install software on — printers,
cameras, badge readers, PLCs, the contractor's laptop. Names, hardware addresses, vendors, operating
systems, usernames, certificates, served ports, and what talks to the outside world.

**It cannot see three things, and no passive tool can:**

**TLS 1.3 hides certificates.** In TLS 1.2 the server's certificate crossed the wire in clear text.
TLS 1.3 encrypts it. Verified against real Suricata 8 output: of seven TLS 1.3 connections, zero
exposed a certificate. So certificate findings — expiring, expired, self-signed — only fire on TLS
1.2 and below. In practice that's still where they matter most: internal NAS boxes, printers,
cameras and management interfaces are exactly the things running older TLS and exactly the
certificates nobody tracks. But we won't see your TLS 1.3 web server's certificate, and any tool
claiming otherwise without a proxy is misleading you.

**Only what crosses the sensor.** Two devices talking to each other on the same switch, in traffic
that never reaches your mirror port, are invisible for flow purposes. Broadcast protocols — DHCP,
ARP, mDNS, NBNS — reach the mirror regardless, so those devices are still discovered and identified;
it's their conversations you'd miss. Placement matters, which is why we push the uplink between the
access switch and the router.

**Encrypted payloads stay encrypted.** We read metadata — SNI, JA4, certificates where visible, DNS,
flow. Never content. That's a deliberate limit, not a gap we intend to close.

---

## Why this exists

**Nobody knows what's on their network.** Ask any IT manager how many devices they have and the
answer will be wrong — usually by two or three times. The forgotten Windows 7 machine running a
lathe. The camera with a default password. The contractor's laptop from four months ago that never
left. You cannot protect, patch or decommission what you don't know exists, which is why every
security framework on earth opens with "maintain an asset inventory" — CIS Control 1, NIS2, PCI-DSS,
Essential Eight.

Three reasons it stays unsolved:

**Scanning is banned where it matters most.** You do not run Nmap against a hospital or a factory
floor — active scans crash medical devices and PLCs. In OT, healthcare and utilities, passive
discovery is the *only* lawful option.

**Agents don't reach the things you're worried about.** You can install software on a managed laptop.
You cannot install it on a printer, a camera, a badge reader or a PLC — and those are exactly the
devices nobody has inventoried.

**The tools that do solve it cost a fortune.** Armis, Axonius, runZero and Forescout all work, and
all make you deploy *their* collectors and pay per asset. That's fine for an enterprise and
impossible for a 60-person company.

Meanwhile the answer is already on your disk. Suricata writes it every second. Where it's kept at
all, it's kept as searchable logs — retained, billed per gigabyte, and never turned into an
inventory. Nobody joins the DHCP vendor class to the SNMP description to the served ports and says
"that's a Zebra label printer on firmware 6.4."

### Against everything else

| | What everyone else does | What Tarsier does |
|---|---|---|
| **Discovery** | Scan the network, or install agents | Listens to traffic that's already flowing. Nothing is scanned, probed or connected to. |
| **Coverage** | Managed devices only | Every device that speaks — printers, cameras, PLCs, the unmanaged laptop |
| **Where the data comes from** | A collector you buy and deploy | The Suricata you already run, or a €150 mini-PC |
| **What it reads** | Suricata's `alert` events | Everything else — DHCP, ARP, TLS, Kerberos, SMB, SNMP, flow |
| **Risk of deploying it** | Inline device, agents, change windows | **Zero.** Never in the traffic path. If it dies, nothing notices. |
| **When it's wrong** | A label you can't question | Every identification shows its confidence *and the evidence behind it* |

The Suricata front-ends — [EveBox](https://evebox.org),
[SELKS](https://www.stamus-networks.com/selks), [Security Onion](https://securityonionsolutions.com)
— are built on the `alert` stream. They're genuinely good. If you want an alert inbox, use EveBox.
If you want a full SOC distribution, use Security Onion. Use Tarsier if your question is *"what is
on this network and what's wrong with it?"*

**We are not** an IDS UI, a SIEM, a firewall, or an OT security platform.

---

## How it identifies devices

By listening to what they already say. Every device announces more than people realise:

| What it says | Where | What it reveals |
|---|---|---|
| DHCP request | `dhcp` | hostname, MAC, vendor class, OS |
| ARP | `arp` | every device on the segment, including static IPs |
| Kerberos / SMB login | `krb5`, `smb` | usernames, AD realm, Windows hostname |
| TLS handshake | `tls` | certificates, expiry, JA3/JA4 client fingerprint |
| HTTP header | `http` | operating system, browser, embedded device |
| SNMP `sysDescr` | `snmp` | exact model and firmware |
| SSH banner | `ssh` | distribution and version |
| Ports it answers on | `flow` | its role — printer, database, PLC, domain controller |
| EtherNet/IP, Modbus, DNP3 | `enip`, `modbus`, `dnp3` | vendor, model, firmware, serial, station address |

Individually weak; combined, conclusive. Signals accumulate as noisy-OR, so two independent 0.5
signals give 0.75 — **nothing ever reaches certainty from accumulation alone**, because passive
identification is inference, not proof. Every device shows its confidence and the exact evidence
behind it, so you can check the working.

That last part isn't decoration. An identification you can't audit is one you won't trust, and the
first thing a competent operator does with a tool like this is try to catch it out.

**On JA4.** Tarsier decodes the first ten characters of every JA4 fingerprint it sees, because they
are a documented structure rather than a hash: TLS version offered, whether the client sent a server
name, and the negotiated protocol. That works on every TLS client on the network with no database at
all, and it's how a device that speaks nothing but encrypted traffic still gets identified. A client
still offering TLS 1.0 becomes a finding in its own right — distinct from a server that accepts it,
because the offer happens before anything is negotiated.

**On OT.** An EtherNet/IP List Identity response volunteers vendor, product name, firmware revision
and serial number in one unauthenticated reply. That's four of the five fields IEC 62443-3-2 asks
for, from a network where scanning is forbidden. Nothing on the IT side of a network is anywhere
near this forthcoming.

---

## The Open Device Fingerprint Database

Identifying *"this is a Hikvision camera on firmware 5.x"* needs a mapping from observable signals to
device identity. The commercial platforms have one. It's proprietary, and it's most of what they're
worth.

**We're building the open one, and giving it away under CC0.**

Everything lives as plain text under
[`internal/identify/data/`](internal/identify/data/), not Go source. That's deliberate: the person
who knows exactly how a Zebra label printer announces itself on DHCP is very often not a Go
programmer, and requiring a code change to record that fact is a guaranteed way never to hear from
them. Editing a `.tsv` and opening a pull request is the whole contribution process.

| File | What it holds | Size |
|---|---|---|
| `oui.tsv` | MAC prefix → vendor, from the public IEEE MA-L/MA-M/MA-S registries | 52,843 |
| `oui_override.tsv` | Curated prefixes IEEE cannot express — QEMU, VirtualBox, Docker | hand-maintained |
| `fingerprints.tsv` | DHCP vendor class, User-Agent, SSH and service banners, hostnames | hand-maintained |
| `ports.tsv` | Listening port → role, including the ICS protocols | hand-maintained |
| `ja4.tsv` | JA4 TLS fingerprint → device | **empty, by design** — see below |

Regenerate the IEEE table with `go run ./tools/genoui -fetch`.

**Provenance rule, and it is not optional.** Entries must come from your own observations, vendor
documentation, or other public-domain sources. Do **not** copy rows out of Fingerbank: their data is
ODbL, which is share-alike, and anything derived from it must also be ODbL — which would silently
destroy the CC0 licence this database carries.

`ja4.tsv` is empty because a fingerprint cannot be derived from a specification; each row has to come
from someone observing a device they can positively identify. A wrong row there is worse than a
missing one. Only **JA4** itself is used — it is BSD-3-Clause. The JA4+ family (JA4S, JA4H, JA4X,
JA4SSH) is under the FoxIO License 1.1 and is deliberately not implemented.

---

## Where this is going

No dates. A roadmap with dates on it is a promise, and missing one costs more trust than making it
ever bought. Nothing below exists yet — there are no commands here because there is nothing to run.

**The rolling window on disk.** `tarsier-watch` already keeps one in memory and rebuilds it from
your rotated logs on restart, which is enough for thirty days on any sensor that retains that much.
Persisting it would let the window outlive your log rotation instead of being bounded by it. The
conclusions are small — a device record and an hourly activity byte — so this is tens of megabytes,
not hundreds of gigabytes.

**Segmentation policy** — declare the zones you intended, get told where reality disagrees.

**The identity graph** — user → devices → services, from the Kerberos, LDAP and SMB names already
being collected.

**A server**, eventually, so history outlives one sensor's local logs. It is last on purpose: the
first four need no server, and adding one turns a five-minute deployment into a project.

**Deliberately not doing yet** — multi-tenancy, SSO, compliance packs. They matter to some people,
but not before the basics are proven on real networks.

---

## Security

Tarsier holds a complete map of your network, and we treat a compromise of it as catastrophic for
you. The scanner is self-hosted, reads one file, and talks to nothing. There is no cloud service, no
account, no phone-home and no telemetry. The HTML report is a single offline file.

For what's coming: per-sensor mTLS with single-use enrolment tokens, no default credentials, audit
logging, signed releases with SBOM, and a published disclosure policy before v1.0. Any future LLM
feature will be opt-in, bring-your-own-key, local-model capable, and will redact internal IPs and
hostnames before sending anything.

Reporting a vulnerability: see [SECURITY.md](SECURITY.md).

---

## FAQ

<details>
<summary><b>Will this fill my disk?</b></summary>

The scanner writes nothing but the report you asked for. It reads and exits.

If you use the **Tarsier sensor**, `eve.json` is a buffer, not an archive: Suricata rotates it
hourly and a guard loop enforces a hard ceiling — default 2 GB, set with `TARSIER_MAX_LOG_MB`. When
it's hit, the oldest rotated files are deleted, never the file being written. Deleting the oldest
data is the correct failure mode: recent events matter more, and the alternative is a full disk that
stops capture entirely.

If you run your own Suricata, your logrotate config stays yours. We never rotate, truncate or delete
your logs.
</details>

<details>
<summary><b>Suricata releases often. Will an upgrade break this?</b></summary>

Frequent releases, but rarely breaking ones — Suricata ships a major roughly annually and the rest
are bugfixes that don't touch the EVE schema. So you're facing about one compatibility event a year.

Five things handle it:

1. **Nothing parses strictly.** Records are read by path, not unmarshalled into fixed structs. A new
   field in a future release is a no-op, not an error.
2. **The original line is always kept.** When a field turns out to matter later, it's backfilled
   across history rather than lost.
3. **Fields that moved are looked up under every known spelling.**
4. **Feature detection, not version checks.** Distributions backport, so the presence of a field is
   the only trustworthy signal.
5. **CI runs real Suricata 6.0 / 7.0 / 8.0 / `master` containers** against a fixed pcap on every
   commit. The nightly `master` run means a breaking upstream change turns the build red weeks before
   it reaches anyone.
</details>

<details>
<summary><b>How does a Docker container see my whole network?</b></summary>

Three things, all in the shipped compose file:

**`network_mode: host`** — the container uses the host's real interfaces rather than Docker's private
bridge. Without this it would only ever see Docker's own traffic.

**`cap_add: NET_ADMIN, NET_RAW`** — permission to put the interface into promiscuous mode and read
raw packets. Every other Linux capability is dropped: a box holding a map of your network should
hold no privilege it doesn't use.

**A mirror (SPAN) port on your switch** — the part that isn't Docker. Normally a switch only sends a
machine traffic addressed *to* it. You configure the switch to copy traffic from other ports to the
port your sensor sits on. That's a five-minute change in the switch's web UI, and it can't break
anything.

No mirror port available? Run the sensor as a VM with the virtual switch in promiscuous mode — no
hardware needed at all.
</details>

<details>
<summary><b>Do devices connect to it? Does anything get installed on them?</b></summary>

No, and no. **Nothing on your network knows Tarsier exists.**

Nothing is installed on any laptop, server, printer or PLC. No credentials, no agents, no scanning.
You tell your **switch** to send a copy of traffic to one spare port, and the sensor listens on it.

```
   your devices ──► [ switch ] ──copy──► [ sensor ]  listens only
                        │
                        ▼
                    the internet
```

The sensor cannot transmit onto the monitored network. If it crashes, nothing notices — there's no
failure domain, no maintenance window and no change-control battle. It's also why this is usable in
hospitals and factories, where active scanning is banned because it crashes medical devices and PLCs.
</details>

<details>
<summary><b>Is this a firewall? Does it block anything?</b></summary>

No. Tarsier never sits in the traffic path and blocks nothing. If you have no firewall, you still
need one.

What it gives you is the thing you almost certainly don't have: knowing what's on your network and
being told when something changes. It can also generate blocklists for the router you already own —
detect here, block there — without ever becoming a device that can break your network.
</details>

<details>
<summary><b>Will it slow my network down?</b></summary>

It cannot. It isn't in the path — it receives a copy of traffic and can't transmit. Even a completely
saturated sensor has no effect on the network it's watching.

If the sensor can't keep up it drops packets and tells you so, from Suricata's own counters. A
partially-blind sensor is more dangerous than an offline one, so that's surfaced rather than hidden.
</details>

<details>
<summary><b>Does my data leave my network?</b></summary>

No. Tarsier is self-hosted. There is no cloud service, no account, no phone-home and no telemetry you
didn't switch on. The HTML report is a single offline file.
</details>

---

## Contributing

**We're looking for people to run this on a real network and say what's wrong with it** — anyone
running Suricata, anyone who manages networks for other people, anyone who has ever tried to answer
"what's actually on this network?"

Most useful right now:

- **Devices we identify wrongly.** Those are worth more to us than the ones we get right, and there
  is an [issue template](.github/ISSUE_TEMPLATE/wrong-identification.yml) for exactly this.
- **`eve.json` samples** with `flow`, `dns`, `tls`, `dhcp` enabled, tagged with your Suricata version.
- **Device fingerprints** from your network — one `.tsv` line, public domain, helps everyone.
- What you tried to build around Suricata yourself, and what it cost you.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## What it costs

**Tarsier is free. All of it.**

Not a trial, not a limited tier, not free-until-we-change-our-minds. Unlimited devices, unlimited
sensors, every feature, no account required. Self-hosted, so your network data never leaves your
building.

It's free because it's built on Suricata, which is free, and because the thing it needs most is for
people to use it and contribute device fingerprints back.

**If you want something we haven't built** — a custom integration, a report shaped for your
regulator, help deploying it across a large or unusual estate — that's paid work, quoted per
engagement. Ask.

| Component | Licence |
|---|---|
| Scanner and server | **AGPL-3.0** — free to self-host and modify |
| Agent and sensor image | **Apache-2.0** — install it anywhere, embed it in anything |
| Device fingerprint database | **CC0** — public domain, no strings, use it in your own tools |

---

<sub>Built on [Suricata](https://suricata.io) by the [OISF](https://oisf.net). Tarsier is an
independent project — **not affiliated with, sponsored by, or endorsed by OISF** — and simply reads
the output Suricata already produces. Suricata is a registered trademark of the Open Information
Security Foundation. The sensor image installs Suricata (GPL-2.0) from OISF's repository at build
time; the two run as separate programs and no Suricata code is included in this repository. Device
vendor and product names are used only to identify equipment observed on a network.</sub>
