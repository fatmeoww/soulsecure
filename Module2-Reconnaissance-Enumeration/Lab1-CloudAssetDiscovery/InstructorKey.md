# Module 2 — Lab 1: Cloud Asset Discovery — Instructor Key

**Target host:** dynamic IP, `tester`/`password` SSH (see
[Module2-Docker-Ops.md](../Docker-Ops.md) for full deployment details)
**Zone:** `soulsecure.lab`, served by CoreDNS
**Access model:** almost everything is HTTPS-only through one nginx front door on 443,
reverse-proxying to backend containers by hostname (SNI/Host header) — see "Access
architecture" below before running any verification commands.

## Access architecture (read this first)

As of the harder-mode rework, **api, storage, vpn, and backup-eu are no longer
published on their own ports.** They're reverse-proxied through the `www` nginx
container on port 443 only, routed by hostname — matching how a real
gateway/ingress-fronted cloud environment looks, and meaning a port scan of the bare
IP shows far fewer open ports than it used to.

**Still on dedicated, DNS-less ports (deliberately — this is the Lab 1 "shadow IT /
found by port scan, not DNS" lesson, and it would be pointless to hide it behind the
gateway):**
- `jenkins-old` — port 9090
- `grafana-decoy` — port 3000 (harder-mode addition, found via `/shodan-search`)
- `honeypot` — port 2121 (harder-mode addition, decoy, no flag)
- `mail` — port 25 (SMTP; has a DNS name, `mail.soulsecure.lab`, but can't be
  reverse-proxied through HTTP)
- `osint` (OSINT Sandbox) — port 9091 (lab utility, not a target asset)
- `dns` (CoreDNS) — port 53

**TLS:** one CA-signed cert, 100-year validity on both the CA and the server cert,
covers every hostname in the environment (SAN list grows with `LAB_LEVEL`, same gating
pattern as everything else — see Docker-Ops doc). Port 80 exists only to redirect to
443 and to serve `/ca.crt` in the clear. Generated fresh by
`nginx/entrypoint.sh` on every container start.

## Flags (ground truth)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `http://<TARGET_IP>:9090/` (HTML comment) | `flag{cdad904c3f229c8a33f6b9a37b2ec64b}` |
| Flag 2 | `https://vpn.soulsecure.lab/` (HTML comment) | `flag{553edeb5b994421a80636e7556fab1b4}` |
| Flag 3 | `https://backup-eu.soulsecure.lab/` (HTML comment) | `flag{5ff49b3a254b1781f99d3e60f185b706}` |
| Flag 4 (harder-mode) | `http://<TARGET_IP>:3000/` (Grafana lookalike, HTML comment) | `flag{24d7fbca483d726d1ae7ba4c745acd2b}` |

## Verification commands

Run from a box with the target set as its nameserver (or use `curl --resolve
<host>:443:<TARGET_IP>` to skip DNS setup for a quick check):

```bash
curl -sk https://vpn.soulsecure.lab/ | grep flag                    # Flag 2
curl -sk https://backup-eu.soulsecure.lab/ | grep flag               # Flag 3
curl -s "http://<TARGET_IP>:9091/shodan-search?query=soulsecure"
curl -s http://<TARGET_IP>:3000/ | grep flag                          # Flag 4
curl -s http://<TARGET_IP>:9090/ | grep flag                          # Flag 1
echo | nc <TARGET_IP> 2121                                            # banner only, no flag
nmap -p- -sV <TARGET_IP>                                              # should show far fewer open ports now
```

### Harder-mode addition: Shodan-style search + honeypot decoy

- **`grafana-decoy`** (port 3000) — a fake Grafana login page. Not findable via DNS or
  the client scope doc; the *intended* discovery path is the OSINT Sandbox's
  `/shodan-search?query=soulsecure` endpoint (simulates a Shodan/Censys-style
  internet-wide scan result), though a plain `nmap -p-` still finds the open port too.
- **`honeypot`** (port 2121) — a **deliberate false lead**, no flag. Banner is
  `220 (vsFTPd 2.3.4)`, the real-world version tied to a famous 2011 backdoor
  (CVE-2011-2523). Purely a banner, no actual FTP service behind it. If a student
  reports this as a finding without verifying, that's a teachable moment, not a
  scored point.

Both are always present (`LAB_LEVEL >= 1`, same as the rest of Lab 1's core services).

## Grading rubric (out of 100)

| Criterion | Points |
|---|---|
| Correctly used OSINT Sandbox (RDAP + ASN + CT-log) and recorded findings | 15 |
| Correct DNS enumeration of the real hostnames | 15 |
| Ran a **full** port scan (not just top-1000) and found `jenkins-old` on 9090 | 20 |
| Correct service/technology fingerprint notes per asset | 15 |
| Correct cloud-provider indicators identified (AWS-flavored headers/hostnames) | 10 |
| Complete, clean inventory table deliverable | 10 |
| Flags 1-3 captured | 10 |
| Flag 4 captured + honeypot correctly identified as a non-finding | 5 |

## Design notes / narrative threads

Also seeded for later modules (not graded here, just narrative continuity):
- HTML comment on `www` leaks bucket name `soulsecure-prod-assets` → pays off in Lab 4
  (Object Storage Enumeration)
- `api.soulsecure.lab/version` leaks `ip-10-0-1-15.ec2.internal` and `/status` leaks
  the `jenkins-old` name in plaintext as a secondary path to the same discovery, for
  students who prefer log/response-mining over raw port scanning
- RDAP response on the OSINT Sandbox explicitly notes it's "flagged...as an AWS-style
  direct allocation" and several response headers (`X-Amzn-Trace-Id`,
  `x-amz-request-id`, CloudFront `Via` header) are deliberately AWS-flavored so students
  practice cloud-provider fingerprinting even without a real cloud account.

## File locations

- `/opt/soulsecure-labs/nginx/conf/lab1.conf` — `www`/`backup-eu` static vhosts +
  `api`/`storage`/`vpn` `proxy_pass` blocks, all on `listen 443 ssl`
- `/opt/soulsecure-labs/nginx/entrypoint.sh` — CA + server cert generation (SAN list
  built per `LAB_LEVEL`), port-80 redirect + `/ca.crt` serving
- `/opt/soulsecure-labs/apps/grafana_app.py`, `/opt/soulsecure-labs/honeypot/`
- `/opt/soulsecure-labs/apps/osint_app.py` — `SHODAN_RESULTS` dict, `/shodan-search` route.
  This file also serves a browser GUI at `/` (one card per lookup type, shows the
  equivalent curl command per result) — added so students who aren't yet comfortable
  with curl have an easier on-ramp. The JSON API is unchanged and still the primary
  interface for Labs 2–5 (which have no GUI); the old JSON index moved from `/` to
  `/api`.

## Known limitations

- This is a single VM playing multiple "assets" behind one gateway rather than
  separate IPs — called out explicitly in the guide so students don't misread the
  topology as unrealistic.
- `ufw` is inactive on this host (everything is reachable) — intentional, it mirrors
  the "everything overexposed" reality of a lot of real cloud misconfigurations, but
  worth a one-line callout in class discussion if a student notices and asks.
