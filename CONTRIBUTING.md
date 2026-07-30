# Contributing

The most useful thing you can send is **a device Tarsier got wrong**.

A correct identification confirms nothing new. A wrong one points straight at the rule that needs
fixing, and fixing it improves the result for everyone running the tool. That is genuinely the
highest-value contribution here, and it needs no Go.

---

## Telling us something was misidentified

Run with `-v` so the evidence comes with it:

```bash
tarsier-scan -v /var/log/suricata/eve.json
```

Open an issue with:

- what Tarsier said (`Brother · printer  (99% confident)`)
- what it actually is (`a label printer, but it's a Zebra, not a Brother`)
- the **evidence block** from `-v` for that device
- your Suricata version (`suricata -V`)

**Do not paste a raw `eve.json`.** It contains your internal addresses, MAC addresses, hostnames,
usernames and every domain your machines looked up. Redact it, or send only the evidence lines.

---

## Adding a device fingerprint

`internal/identify/rules.go` is deliberately plain data. Adding a device means adding a line.

```go
{"hikvision", "class=camera", 0.9, 1},
//  ^ lowercase substring to match
//                ^ what it implies
//                                ^ weight, 0..1
//                                     ^ specificity: 2 if it refines a vaguer answer
```

**On weights, which is where judgement matters:**

| Weight | Means |
|---|---|
| 0.9 | the device effectively announced what it is (DHCP vendor class, SNMP sysDescr) |
| 0.7 | strong and rarely wrong |
| 0.5 | good, with known false positives |
| 0.3 | suggestive only — meant to combine with other signals |

Be honest with these. Inflated weights produce confident wrong answers, which is worse than saying
"unidentified". The tool's only real claim is that it admits what it does not know.

**Specificity (the last field)** is `2` when a conclusion refines a vaguer one — `Windows 7` over
`Windows`. A specific answer wins even against a higher-weighted generic one, because an
out-of-support machine is the finding, not "it's a Windows box".

Every rule needs a test in `internal/identify/identify_test.go`. Copy an existing one.

---

## Code

```bash
go test ./...    # must pass
go vet ./...     # must be clean
gofmt -l .       # must print nothing
```

**Zero dependencies.** The standard library only. This is not negotiable — it is why the binary
drops onto an OPNsense box with nothing to install, and why the supply-chain surface is just Go.

**Conventions that are load-bearing, not style:**

- **Never parse EVE strictly.** Read fields by path, tolerate absence, and use `FirstStr` where a
  field has been renamed between versions. An unknown field must be a no-op, never an error.
- **Feature-detect, don't version-check.** Distributions backport, so `rec.Has("tls.ja4")` is the
  only trustworthy signal that JA4 is available.
- **Every conclusion carries evidence.** If you add an identification path, call `note()` so the
  user can audit it.
- **Repeated sightings of one signal count once.** Seeing SMTP on a host 500 times is one piece of
  evidence, not 500. `noteSpec` handles this — don't work around it.

---

## Findings

A finding without a fix is homework, and homework gets ignored. Every one needs:

- `Title` — what it is, in words a non-specialist reads without stopping
- `Detail` — what it means and why it matters
- `Fix` — **what to actually do**
- `Command` — only where a real one exists

**If the fix genuinely depends on the device, leave `Command` empty.** A plausible-looking command
that silently fails destroys more trust than offering none.

---

## Things we are not doing

So you don't spend time on them:

- **Blocking traffic.** Tarsier is never in the path. That constraint is the product — it is why
  deployment cannot break anything and why it is permitted where scanning is not.
- **Inventorying public addresses.** External hosts are destinations, not assets.
- **Dependencies.** See above.
- **Sending anything anywhere.** No cloud, no telemetry, no account.

---

## Licences

Core is AGPL-3.0, the agent and sensor are Apache-2.0, and the fingerprint data is CC0 — public
domain, so anyone can use it, including competitors. That last part is deliberate: it is meant to be
a genuine contribution to the ecosystem, not a moat with a gate on it.

By contributing you agree your work is released under those terms.
