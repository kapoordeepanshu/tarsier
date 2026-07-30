# Tarsier — passive network asset intelligence from Suricata

### Your IDS already knows everything on your network. It just never told you.

Tarsier turns **Suricata** into a passive asset intelligence engine. Every device, user, service,
certificate and application on your network — discovered from traffic.

**No agents. No scanning. No credentials. No firewall.** It reads the `eve.json` you already have.

**Runs on the Suricata you already have. One binary. No server.** That sentence is as true for a
home lab as it is for a hospital — this is described by how little it takes to deploy, not by how
big you are.

<sub>Open-source **Suricata dashboard** and **eve.json analyser** for **passive network discovery**,
**network asset inventory** and **device fingerprinting** — a free, self-hosted **Suricata web UI**
and **IDS visibility** tool that replaces an ELK stack. Runs on OPNsense, pfSense, Docker, bare metal
and cloud traffic mirrors.</sub>

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

<sub>*Illustration of the report. Left: every device, what it is, and how confident we are — the ring
around each icon fills to its confidence. Right: what's actually wrong, each with a fix and, where
one exists, a command to copy. Top: drag the timeline to filter everything below it to that window.*</sub>

**The whole report is one self-contained HTML file.** No server, no internet, no dependencies — it
opens from a USB stick on a machine that has never been online, which is often exactly where this
work happens.

> **What works today:** the scanner. Point it at an `eve.json` and you get the inventory, the
> findings and the report above — that part is real and you can run it in two minutes.
>
> **What doesn't yet:** live monitoring, the server, and change detection — listed plainly under
> [what works, and what doesn't](#what-works-and-what-doesnt).
>
> **Wanted:** people to run it on a real network and tell us what it got wrong. Wrong
> identifications are worth more to us than right ones — see [Get involved](#get-involved).

---

## Quick start

You need [Go 1.22+](https://go.dev/dl/). Nothing else — no dependencies, no database, no Docker.

```bash
git clone https://github.com/kapoordeepanshu/tarsier.git
cd tarsier
go build ./cmd/tarsier-scan
```

**No `eve.json` of your own?** A week of realistic sample traffic ships with the repo:

```bash
# Linux / macOS
./tarsier-scan -html survey.html testdata/demo-week.json

# Windows  (go build produces tarsier-scan.exe)
.\tarsier-scan.exe -html survey.html testdata\demo-week.json
```

Open `survey.html` in any browser. That's 18 devices and 15 things wrong with them, each with a fix.

> **On Windows**, `go build` produces `tarsier-scan.exe`. Run it from PowerShell or Command Prompt
> with `.\tarsier-scan.exe` — the leading `.\` is required, because Windows does not look in the
> current folder by default. Double-clicking it will not work: it is a command-line tool and needs a
> file to read, so it would open and close instantly.

<details>
<summary>Running it on your own network</summary>

```bash
./tarsier-scan /var/log/suricata/eve.json             # print to the terminal
./tarsier-scan -v eve.json                            # show the evidence for every identification
./tarsier-scan -last 24h /var/log/suricata/           # every rotated log, last day
./tarsier-scan -since 2026-07-28 -until 2026-07-30 'eve.json.*'
./tarsier-scan -html survey.html /var/log/suricata/   # shareable report
./tarsier-scan -json monday.json /var/log/suricata/   # machine-readable inventory
./tarsier-scan -netbox ips.csv /var/log/suricata/     # NetBox ipam.ip_addresses import
```

It accepts single files, globs, or a whole directory of rotated logs, and reads `.gz` directly.

**What changed since last week?** Two snapshots and a diff — no server, no database:

```bash
go build ./cmd/tarsier-diff

./tarsier-scan -json monday.json /var/log/suricata/
./tarsier-scan -json friday.json /var/log/suricata/
./tarsier-diff monday.json friday.json
```

It reports devices that appeared, devices that went quiet, and devices that changed — a new
listening port, a new user, a new VLAN, a firmware version that moved. Findings are matched on kind
rather than wording, so rewording a message does not present the whole network as newly broken.
Exit status is 0 when nothing changed and 1 when something did, so it can run from cron and stay
silent until it has something to say.

**No Suricata at all?** The sensor image contains it, pre-configured:

```bash
cd deploy/sensor && docker compose up -d
```

</details>

Prebuilt binaries for Linux, FreeBSD (OPNsense/pfSense), macOS and ARM are on the
[releases page](../../releases) — **your users never need Go installed**, only you do.

---

## The problem

**Nobody knows what's on their network.** Ask any IT manager how many devices they have and the
answer will be wrong — usually by two or three times. The forgotten Windows 7 machine running a
lathe. The camera with a default password. The contractor's laptop from four months ago that never
left. You cannot protect, patch or decommission what you don't know exists, which is why every
security framework on earth opens with "maintain an asset inventory" — CIS Control 1, NIS2, PCI-DSS,
Essential Eight.

Four reasons it stays unsolved:

**Scanning is banned where it matters most.** You do not run Nmap against a hospital or a factory
floor — active scans crash medical devices and PLCs. In OT, healthcare and utilities, passive
discovery is the *only* lawful option.

**Agents don't reach the things you're worried about.** You can install software on a managed laptop.
You cannot install it on a printer, a camera, a badge reader or a PLC — and those are exactly the
devices nobody has inventoried.

**The tools that do solve it cost a fortune.** Armis, Axonius, runZero and Forescout all work, and
all make you deploy *their* collectors and pay per asset. That's fine for an enterprise and
impossible for a 60-person company.

**And the answer is already sitting on your disk, being deleted.** Suricata writes it every second —
and every deployment in the world keeps the `alert` records and throws the rest away, because
storing it on Elastic or a per-GB SIEM costs more than anyone thinks it's worth.

---

## Why Tarsier

| | What everyone else does | What Tarsier does |
|---|---|---|
| **Discovery** | Scan the network, or install agents | Listens to traffic that's already flowing. Nothing is scanned, probed or connected to. |
| **Coverage** | Managed devices only | Every device that speaks — printers, cameras, PLCs, the unmanaged laptop |
| **Where the data comes from** | A collector you buy and deploy | The Suricata you already run, or a €150 mini-PC |
| **What it reads** | Suricata's `alert` events (~5% of output) | The other 95% — DHCP, ARP, TLS, Kerberos, SMB, SNMP |
| **Cost at 1 Gbps, 90 days** | Four figures a month | **≈ €50/month, and €0 for the software** |
| **Risk of deploying it** | Inline device, agents, change windows | **Zero.** Never in the traffic path. If it dies, nothing notices. |
| **When it's wrong** | A label you can't question | Every identification shows its confidence *and the evidence behind it* |

**Three things follow from that, and they're the whole pitch:**

**It works in ten minutes, on minute one.** No rules to write, no baseline period, no tuning. Plug it
in and the inventory appears — including the devices you'd forgotten.

**It's allowed everywhere.** No agents, no credentials, no scanning, no inline hardware. Deploying it
is a five-minute mirror-port change, not a project. That's why it works in the environments where
nothing else is permitted.

**It admits what it doesn't know.** Passive identification is inference, not proof — so every device
carries a confidence score and the exact signals behind it. You can check our working, which is the
first thing any competent operator will want to do.

---

## The idea

Suricata is the most widely deployed passive protocol parser on earth. It parses **DHCP, Kerberos,
SMB, DNS, TLS, HTTP, SSH, SNMP, RDP, FTP, SIP, MQTT, DCERPC, NFS** — and **Modbus, DNP3, ENIP**.
All of it goes to `eve.json`.

**Every deployment in the world keeps the `alert` records and deletes the rest.**

That deleted 95% is a complete, continuously updated inventory of your network. Nobody uses it.
Tarsier does.

```
eve.json ──►  dhcp · krb5 · smb · dns · tls · http · ssh · snmp · flow · modbus
                                      │
                                      ▼
              every device · every user · every service · every certificate
                        with confidence scores and the evidence
```

---

## What you see ten minutes after install

> **1,247 devices. 312 you've never inventoried.**
>
> - A Windows 7 host in the finance VLAN — `ACCTS-PC-04`, via DHCP, signing in as `jsmith` via Kerberos
> - 46 IoT devices phoning home to three countries
> - An expired certificate in production, in use, right now
> - 23 SaaS applications nobody approved, identified by TLS SNI and JA4
> - Two devices in the card-data VLAN talking to the corporate VLAN — **your segmentation is not what you think it is**

No rules to write. No baseline period. No tuning. It works on minute one.

---

## The Open Device Fingerprint Database

Identifying *"this is a Hikvision camera on firmware 5.x"* needs a mapping from observable signals to
device identity. Armis has one. It's proprietary, and it's most of what they're worth.

**We're building the open one, and giving it away under CC0.**

```
DHCP vendor class + option-55 · MAC OUI · JA3/JA4/JA4S · HTTP UA + Server
mDNS/NBNS names · SSH banner · SNMP sysDescr · served-port profile
                              ↓
              vendor · model · OS · device class · role
```

Contribute a fingerprint from your network with one command. Public domain — usable by anyone,
including our competitors. Every deployment makes identification better for everyone else.

**Where it lives.** Everything above is plain text under [`internal/identify/data/`](internal/identify/data/),
not Go source. That is deliberate: the person who knows exactly how a Zebra label printer announces
itself on DHCP is very often not a Go programmer, and requiring a code change to record that fact is
a guaranteed way never to hear from them. Editing a `.tsv` and opening a pull request is the whole
contribution process.

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

**On JA4.** Tarsier decodes the first ten characters of every JA4 fingerprint it sees, because they
are a documented structure rather than a hash: TLS version offered, whether the client sent a server
name, and the negotiated protocol. That works on every TLS client on the network with no database at
all, and it is how a device that speaks nothing but encrypted traffic still gets identified. A client
still offering TLS 1.0 becomes a finding in its own right — distinct from a server that accepts it,
because the offer happens before anything is negotiated.

`ja4.tsv` is empty because a fingerprint cannot be derived from a specification; each row has to come
from someone observing a device they can positively identify. A wrong row there is worse than a
missing one. Only **JA4** itself is used — it is BSD-3-Clause. The JA4+ family (JA4S, JA4H, JA4X,
JA4SSH) is under the FoxIO License 1.1 and is deliberately not implemented.

---

## Why this isn't another Suricata dashboard

The whole ecosystem built on the `alert` stream. We inverted it.

| | Uses only `alert`? | What it is |
|---|---|---|
| [EveBox](https://evebox.org) | yes | Alert inbox. Excellent — **use it** if that's what you need. |
| [SELKS](https://www.stamus-networks.com/selks) / Scirius | mostly | Alerts + rule management |
| [Security Onion](https://securityonionsolutions.com) | mostly | Full SOC distribution |
| **Tarsier** | **no — inverts it** | **Asset intelligence from the other 95%** |

And unlike Armis, Axonius, runZero or Forescout — all of which make you deploy *their* collector and
charge per asset — Tarsier is **open source, self-hosted, and runs on Suricata you already have.**

**We are not** an IDS UI, a SIEM, a firewall, or an OT security platform. We're never in the traffic
path — which is exactly why deploying us is a five-minute mirror-port job that cannot break anything,
rather than a change-control project.

---

## Cost

| | Per-GB SIEM | Commercial asset discovery | **Tarsier** |
|---|---|---|---|
| Sensor | your own | vendor collector | **Suricata you already run** |
| Ingest pricing | per GB | per asset | **none** |
| 1 Gbps network, 90-day retention, **full metadata** | four figures/month | — | **≈ €40–80/month** |
| Licence | five–six figures/year | five figures/year | **€0 self-hosted** |

ClickHouse compresses EVE roughly 15:1, so ~100 GB/day of raw metadata becomes ~7 GB/day stored.
Per-GB pricing is the reason everyone throws this data away — removing it is what makes the product
possible.

---

## Stack

**What exists today is Go, and nothing else.** `tarsier-scan` and `tarsier-diff` are static binaries
with no dependencies, no database and no runtime. The fingerprint database is embedded as plain text.
That is the entire build:

```bash
go build ./cmd/tarsier-scan ./cmd/tarsier-diff
```

**Planned, and not yet built:** a server for history beyond the sensor's local logs, using
**ClickHouse** as the only datastore and **React + TypeScript** embedded in the binary. It is
described here because it is the intended shape, not because you can run it — see
[What works, and what doesn't](#what-works-and-what-doesnt).

Agent cross-compiles to `linux/amd64`, `linux/arm64`, `linux/arm` and **`freebsd/amd64`** — because
OPNsense and pfSense are where most of the world's dormant Suricata installs live.

**Suricata version:** the sensor image installs from **OISF's own stable repository, not from the
distribution**, so building it gets whatever Suricata is current — **8.0.6 at the time of writing.**
Distribution packages lag badly: Debian bookworm ships 6.0, which has no ARP events (8.0+) and no
JA4 (7.0.7+), and would reject this config outright.

Once built, the image is **pinned** — it keeps that version until you pull a new one. Nothing
upgrades itself behind your back: silently changing the engine that produces your security data is
how you get a Monday morning where nothing works and nobody knows why. Upgrading is
`docker compose pull`, on your schedule, after our CI has tested that release. **If you run your own
Suricata, we never touch it.**

Parsing supports current major, previous major, and whatever OPNsense/pfSense ship.
Parsing is schema-tolerant (unknown fields never cause a drop), the original line is always retained
so new fields can be backfilled, and CI runs real Suricata 6.0/7.0/8.0/`master` containers against a
fixed pcap on every commit.

---

## How you'll use it

**Path A — you already run Suricata**

```
1. Start the server              docker compose up -d
2. Open http://localhost:8080    first-run password is printed to the logs
3. Add a sensor in the UI        → gives you a one-time enrolment token
4. On the Suricata box           tarsier-agent enroll --server … --token …
5. Enable metadata logging       one-time suricata.yaml change — see below
6. Wait ~10 minutes              your network appears
```

**Path B — you don't have Suricata**

```
1. Start the server              docker compose up -d
2. Flash the sensor image        to a €150 mini-PC, or import the VM
3. Boot it                       wizard asks: which interface, which token
4. Plug into a mirror port       on your switch — nothing ever goes inline
5. Wait ~10 minutes              your network appears
```

Then: **day one**, the inventory. **Week one**, the baseline settles. **After that**, a short list of
changes — a new device, an expiring certificate, a machine doing something it never did before.
**Monthly**, a report you can hand to an insurer, an auditor, or a customer.

### Step 5 is the one everyone misses

Most Suricata installs log alerts only. Tarsier needs the metadata — in `suricata.yaml`:

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
        - smb                        # Windows hostnames and usernames
        - krb5                       # usernames and AD realm
        - ssh
        - snmp
        - anomaly
```

`tarsier-scan` reports which of these are missing when you run it, so you never have to guess.

### The agent — designed, not yet built

This describes the intended behaviour of the agent, which does not exist in this repository yet.

It will tail `eve.json`, detect rotation by **inode** rather than filename, persist its read offset
so a restart resumes exactly where it stopped, and spool to disk when the server is unreachable —
with a hard size cap, so it can never fill your sensor's disk. It will never block Suricata. It is
also intended to accept Suricata's `redis` and `unix_stream` EVE outputs, for people who would
rather not tail a file at all.

**Until then**, `tarsier-scan -json` on a schedule plus `tarsier-diff` gives you change detection
with no agent and no server at all.

---

## What works, and what doesn't

No dates. A roadmap with dates on it is a promise, and missing one costs more trust than making it
ever bought.

**Working today**

- Reads every event type Suricata emits, tolerantly — unknown fields and new event types never break it
- Identifies devices from 12+ signals, each with a confidence score and the evidence behind it
- 52,843 hardware vendors from the IEEE registry, with curated overrides for the virtualisation
  prefixes IEEE cannot express
- JA4 structural decoding — TLS version, SNI and ALPN for every encrypted client, no database needed
- Randomised MACs recognised as such, rather than inflating the device count forever
- **Change detection** — `tarsier-diff` reports what appeared, vanished or changed between two scans
- **Machine-readable output** — versioned JSON, plus a NetBox `ipam.ip_addresses` CSV
- OT/ICS identity: vendor, model, firmware and serial from EtherNet/IP, Modbus unit IDs, DNP3
  station addresses — the fields IEC 62443-3-2 asks for, from a network where scanning is forbidden
- Findings with a plain-language fix, and a command to copy where one exists
- Self-contained HTML report with time filtering — no server, opens offline
- Reads single files, globs, whole directories of rotated logs, and `.gz`
- Sensor image bundling Suricata pre-configured for full metadata logging

**Next, roughly in order**

- **Live monitoring** — follow `eve.json` as it is written, handling rotation
- Segmentation policy: declare the zones you intended, get told where reality disagrees
- The identity graph — user → devices → services, from the Kerberos, LDAP and SMB names already collected
- A server, so history outlives the sensor's local logs
- Growing the fingerprint database, which is what makes identification better for everyone

**Deliberately not doing yet** — multi-tenancy, SSO, compliance packs. They matter to some people, but
not before the basics are proven on real networks.

---

## What it costs

**Tarsier is free. All of it.**

Not a trial, not a limited tier, not free-until-we-change-our-minds. Unlimited devices, unlimited
sensors, every feature, no account required, no telemetry you didn't ask for. Self-hosted, so your
network data never leaves your building.

It's free because it's built on Suricata, which is free, and because the thing it needs most is for
people to use it and contribute device fingerprints back.

**If you want something we haven't built** — a custom integration, a report shaped for your regulator,
help deploying it across a large or unusual estate, or a feature your organisation specifically needs
— that's paid work, quoted per engagement. Ask.

**Licences:** core **AGPL-3.0** · agent and sensor **Apache-2.0** · fingerprint database **CC0**.

---

## How the interface is built

Four screens. The design rule: **never show a log.** Logs are the raw material, not the product.

**1 · Your network** — the landing screen, and the one that produces the reaction.
A device list and a map. Every row is a *thing*, not an event: what it is, what it's called, who uses
it, what it talks to. Filter by type, segment, or "things that appeared this week."

```
  214 devices                                    [ all ] [ new ] [ unknown ] [ risky ]

  ● 10.0.1.20    ACCTS-PC-04      Windows 7 · workstation    jsmith        ⚠ end of life
  ● 10.0.4.87    BRN3A1C44        Brother · printer                        
  ● 10.0.7.31    IPCAM-LOBBY      Hikvision · camera         →  3 countries ⚠
  ● 10.0.20.9    PLC-LINE-2       Modbus · industrial                      
  ○ 10.0.0.42    nas01            Synology · NAS             12 shares      ⚠ cert 11 days
```

**2 · Device detail** — everything known about one thing, and *why* we believe it.
Identity with confidence and the evidence behind it. Timeline of what it did. Who logged in. What it
serves. Where it connected. **The evidence panel is not optional** — an identification you can't
audit is one you won't trust.

**3 · Things worth looking at** — the findings list, severity first.
Not alerts. Conclusions, in plain language, each with what it means and what to do about it. This is
the screen people check on Monday morning.

**4 · What changed** — the diff.
New devices, new services, first-ever connections, expiring certificates, segment boundaries crossed.
This is the recurring value once the inventory stops being novel.

Underneath all four, a full-text search and the raw events — reachable in one click from any
conclusion, never the default view.

---

## Security

Tarsier holds a complete map of your network. We treat a compromise of it as catastrophic for you:
per-sensor mTLS with single-use enrolment tokens, no default credentials, audit logging, signed
releases with SBOM, and a published disclosure policy before v1.0. Any future LLM feature will be
opt-in, bring-your-own-key, local-model capable, and will redact internal IPs and hostnames before
sending anything.

---

## FAQ

<details>
<summary><b>Suricata produces enormous amounts of data. Won't this fill my disk?</b></summary>

No, and it's designed around that problem rather than ignoring it.

**On the sensor**, `eve.json` is a buffer, not an archive. Suricata rotates it hourly, the agent
ships events onward within seconds, and a guard loop enforces a hard ceiling — default 2 GB, set with
`TARSIER_MAX_LOG_MB`. When it's hit, the oldest rotated files are deleted, never the file being
written. Deleting the oldest data is the correct failure mode: recent events matter more, and the
alternative is a full disk that stops capture entirely.

**On the server**, ClickHouse compresses EVE roughly 15:1. A 1 Gbps network producing ~100 GB/day of
raw metadata stores about 7 GB/day. Ninety days is ~600 GB — a single NVMe drive, around €40–80 a
month. Retention is per-severity and handled by the database's own TTL rules, so old data ages out
without a cleanup job.

For comparison: per-GB SIEM pricing is exactly why most teams disable `flow` and `dns` logging, and
therefore throw away the data this tool is built on. Removing that cost is what makes the product
possible.
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

If you use the **Tarsier sensor**, the Suricata version is pinned inside the image and only moves
when we've tested it — so upgrades stop being your problem entirely.
</details>

<details>
<summary><b>How does it identify devices without scanning them?</b></summary>

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

Individually weak; combined, conclusive. Signals accumulate as noisy-OR, so two independent 0.5
signals give 0.75 — **nothing ever reaches certainty from accumulation alone**, because passive
identification is inference, not proof. Every device shows its confidence and the exact evidence
behind it, so you can check the working.
</details>

<details>
<summary><b>I don't have Suricata. Can I still use this?</b></summary>

Yes — that's the main case. The **Tarsier sensor** Docker image contains Suricata, the tuned
configuration and the agent. You need nothing on the host but Docker.

```bash
cd deploy/sensor && docker compose up -d
```

It auto-detects the capture interface, enables promiscuous mode, disables NIC offloading (which
corrupts protocol parsing), validates the config with `suricata -T` before starting, and drops every
Linux capability except the two it needs.

Hardware: a spare VM (free), an old desktop, or a €150 Intel N100 mini-PC for a 1 Gbps network.
</details>

<details>
<summary><b>How does a Docker container see my whole network?</b></summary>

Three things make it work, and they're all in the shipped compose file:

**`network_mode: host`** — the container uses the host's real network interfaces rather than Docker's
private bridge. Without this it would only ever see Docker's own traffic.

**`cap_add: NET_ADMIN, NET_RAW`** — permission to put the interface into promiscuous mode and read
raw packets. Every other Linux capability is dropped: a box holding a map of your network should
hold no privilege it doesn't use.

**A mirror (SPAN) port on your switch** — this is the part that isn't Docker. Normally a switch only
sends a machine traffic addressed *to* it. You configure the switch to copy traffic from other ports
to the port your sensor sits on. That's a five-minute change in the switch's web UI, and it can't
break anything.

The entrypoint auto-detects the capture interface, enables promiscuous mode, and disables NIC
offloading (which corrupts protocol parsing by hiding real packet boundaries).

No mirror port available? Run the sensor as a VM on your hypervisor with the virtual switch in
promiscuous mode — no hardware needed at all.
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
<summary><b>How is this different from EveBox, SELKS or Security Onion?</b></summary>

They read Suricata's `alert` events. Tarsier reads **everything else** — the ~95% of EVE output
that every other tool discards — and builds an asset inventory from it.

They're genuinely good tools. If you have one sensor and want an alert inbox, use
[EveBox](https://evebox.org). If you want a full SOC distribution, use
[Security Onion](https://securityonionsolutions.com). Use Tarsier if your actual question is
*"what is on this network and what's wrong with it?"*
</details>

<details>
<summary><b>What can't it see?</b></summary>

Worth knowing up front, because passive monitoring has real limits and we'd rather you hear them
from us.

**TLS 1.3 hides certificates.** In TLS 1.2 the server's certificate crossed the wire in clear text,
so a passive observer could read its subject and expiry. **TLS 1.3 encrypts it.** Verified on real
Suricata 8 output: of seven TLS 1.3 connections, zero exposed a certificate.

So certificate findings — expiring, expired, self-signed — only fire on **TLS 1.2 and below**. In
practice that's still where they matter most: internal NAS boxes, printers, cameras, appliances and
management interfaces are exactly the things running older TLS and exactly the certificates nobody
tracks. But we won't see your TLS 1.3 web server's certificate, and any tool claiming otherwise
without a proxy is misleading you.

**We only see what crosses the sensor.** Two devices talking to each other on the same switch, in
traffic that never reaches your mirror port, are invisible for flow purposes. Broadcast protocols —
DHCP, ARP, mDNS, NBNS — reach the mirror regardless, so devices are still *discovered and
identified*; it's their conversations you'd miss. Placement matters, which is why the docs push the
uplink between the access switch and the router.

**Encrypted payloads stay encrypted.** We read metadata — SNI, JA4, certificates where visible, DNS,
flow. Never content. That's a deliberate limit, not a gap we intend to close.
</details>

<details>
<summary><b>Does my data leave my network?</b></summary>

No. Tarsier is self-hosted. There is no cloud service, no account, no phone-home and no telemetry
you didn't switch on. The HTML report is a single offline file.

Tarsier holds a complete map of your network, so we treat a compromise of it as catastrophic for
you: per-sensor mTLS, single-use enrolment tokens, no default credentials, audit logging, signed
releases with SBOM.
</details>

<details>
<summary><b>Will it slow my network down?</b></summary>

It cannot. It isn't in the path — it receives a copy of traffic and can't transmit. Even a completely
saturated sensor has no effect on the network it's watching.

If the sensor can't keep up it drops packets and tells you so, from Suricata's own counters. A
partially-blind sensor is more dangerous than an offline one, so that's surfaced rather than hidden.
</details>

---

## Get involved

**We're looking for people to run a pre-release and say what's wrong with it** — anyone running
Suricata, anyone who manages networks for other people, anyone who has ever tried to answer "what's
actually on this network?"

Most useful right now:

- **`eve.json` samples** with `flow`, `dns`, `tls`, `dhcp` enabled, tagged with your Suricata version
- **Device fingerprints** from your network — one command, public domain, helps everyone
- Devices we identify **wrongly**. Those are worth more to us than the ones we get right.
- What you tried to build around Suricata yourself, and what it cost you

---

## License

| Component | Licence |
|---|---|
| Server and web UI | **AGPL-3.0** — free to self-host and modify |
| Agent and sensor image | **Apache-2.0** — install it anywhere, embed it in anything |
| Device fingerprint database | **CC0** — public domain, no strings, use it in your own tools |

The whole product is free. If you need something we haven't built — a custom integration, a report
shaped for your regulator, help across a large or unusual estate — that's paid work, quoted per
engagement.

---

<sub>Built on [Suricata](https://suricata.io) by the [OISF](https://oisf.net). Tarsier is an
independent project — **not affiliated with, sponsored by, or endorsed by OISF** — and simply reads
the output Suricata already produces. Suricata is a registered trademark of the Open Information
Security Foundation. The sensor image installs Suricata (GPL-2.0) from OISF's repository at build
time; the two run as separate programs and no Suricata code is included in this repository. Device
vendor and product names are used only to identify equipment observed on a network.</sub>
