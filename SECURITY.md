# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not as a public issue.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository. If that is
unavailable to you, open a normal issue saying only that you have a security report and asking for a
contact — no details.

What to expect:

- Acknowledgement within **72 hours**
- An assessment and a plan within **7 days**
- Credit in the release notes, unless you would rather not be named

Please give a reasonable window to fix before disclosing publicly. There is no bug bounty — this is
an unfunded project — but reports are taken seriously and answered.

## Why this matters more than usual here

Tarsier holds **a complete map of a network**: every device, the users who log into them, the
services they run, the names they resolve, and the certificates they present. A compromise of a
Tarsier deployment is worse for its owner than a compromise of most applications, because the
attacker inherits reconnaissance that would otherwise take weeks.

That shapes how it is built:

- **Nothing leaves the network.** No cloud service, no account, no phone-home, no telemetry.
- **The report is a single offline file.** It never fetches anything external, and CI fails the
  build if it starts to.
- **The sensor is never in the traffic path.** It receives a copy and cannot transmit onto the
  monitored network, so compromising it does not give an attacker a position on the wire.
- **No default credentials.** Anything requiring auth generates a password on first run and prints
  it once.
- **Zero dependencies.** The Go code uses the standard library only, so the supply-chain surface is
  Go itself.

## Handling captured data

If you are reporting a bug, **do not attach a real `eve.json`.** It contains internal addresses, MAC
addresses, hostnames, usernames and every name your machines looked up — publishing one is a data
leak, and a public issue is publishing.

Redact it, or describe the shape of the record instead. `testdata/demo-week.json` in this repository
is synthetic and safe to reference.

## Supported versions

Only the latest release is supported. This is a pre-1.0 project; fixes land on `main` and go out in
the next release.
