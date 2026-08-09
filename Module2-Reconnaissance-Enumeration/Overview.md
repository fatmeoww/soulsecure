# Module 2: Reconnaissance & Enumeration — Overview

**Course:** Cloud Pentest
**Fictional target:** SoulSecure Inc., domain `soulsecure.lab`
**Architecture:** Docker Compose stack (`labctl`), reverse-proxied HTTPS gateway on
one port — see [Module2-Docker-Ops.md](Docker-Ops.md) for full detail

All 5 labs share **one continuous scenario** on **one target host**: an authorized
cloud pentest engagement against SoulSecure Inc. Findings from earlier labs feed later
ones (a leaked bucket name in Lab 1 pays off in Lab 4; an API hint in Lab 2 pays off in
Lab 3; fake AWS keys surface in both Lab 3 and Lab 4, foreshadowing Module 4). Students
should work the labs in order.

## The 5 labs

| # | Lab | Focus | Docs |
|---|---|---|---|
| 1 | Cloud Asset Discovery | OSINT (RDAP/ASN/CT-log/Shodan), DNS enumeration, full port scanning, shadow IT | [StudentGuide](Lab1-CloudAssetDiscovery/StudentGuide.md) · [InstructorKey](Lab1-CloudAssetDiscovery/InstructorKey.md) |
| 2 | DNS & Virtual Host Enumeration | DNS record types (incl. CAA/SRV/AXFR), TLS-SNI vhost brute forcing, TLS SAN enumeration | [StudentGuide](Lab2-DNS-VHost-Enumeration/StudentGuide.md) · [InstructorKey](Lab2-DNS-VHost-Enumeration/InstructorKey.md) |
| 3 | API Reconnaissance | Spec discovery, endpoint enumeration, version brute forcing, verbose errors, GraphQL introspection | [StudentGuide](Lab3-API-Reconnaissance/StudentGuide.md) · [InstructorKey](Lab3-API-Reconnaissance/InstructorKey.md) |
| 4 | Object Storage Enumeration | Bucket permutation, existence oracles, public bucket looting, multi-cloud (S3 + GCS) | [StudentGuide](Lab4-Object-Storage-Enumeration/StudentGuide.md) · [InstructorKey](Lab4-Object-Storage-Enumeration/InstructorKey.md) |
| 5 | CDN, Origin & Technology Fingerprinting | CDN header fingerprinting, origin bypass, robots.txt/security.txt, JS secret leaks, WAF fingerprinting | [StudentGuide](Lab5-CDN-Origin-Tech-Fingerprinting/StudentGuide.md) · [InstructorKey](Lab5-CDN-Origin-Tech-Fingerprinting/InstructorKey.md) |

**20 flags total** (3 core + 1 harder-mode bonus per lab), format `flag{md5-hash}`.
Full ground-truth list is in **[Module2-Flags-สรุปทั้งหมด.md](Flags-สรุปทั้งหมด.md)**
(Thai) — the master answer key.

A Thai-language step-by-step playthrough for all 5 labs is at
**[Module2-คู่มือเล่นแลป-TH.md](คู่มือเล่นแลป-TH.md)**.

## Access model: one HTTPS gateway, hostname-routed

Almost every asset is reachable **only** via `https://<hostname>.soulsecure.lab/`
through one nginx gateway on port 443 (port 80 exists solely to redirect to 443 and
serve `/ca.crt`). A handful of assets are deliberately **not** behind the gateway,
each for a specific pedagogical reason — see the table below and
[Module2-Docker-Ops.md](Docker-Ops.md) for the full rationale.

## Full asset map (all 5 labs combined)

| Host/path | Reached via | What it is | Found in |
|---|---|---|---|
| `www.soulsecure.lab` / apex | `https://www.soulsecure.lab/` | Marketing site, CDN-fronted | Lab 1 (given) |
| `api.soulsecure.lab` | `https://api.soulsecure.lab/` | REST + GraphQL API | Lab 1 (given) → deepened in Lab 3 |
| `storage.soulsecure.lab` | `https://storage.soulsecure.lab/` | S3-style + GCS-style object storage | Lab 1 (fingerprint only) → deepened in Lab 4 |
| `vpn.soulsecure.lab` | `https://vpn.soulsecure.lab/` | VPN gateway | Lab 1 |
| `backup-eu.soulsecure.lab` | `https://backup-eu.soulsecure.lab/` | Backup portal | Lab 1 |
| `mail.soulsecure.lab` | port 25 (SMTP, not proxyable via HTTP) | SMTP banner | Lab 1 |
| `jenkins-old` (no DNS) | port 9090 (IP-direct) | Shadow-IT CI server | Lab 1 (port scan only) |
| Grafana decoy (no DNS) | port 3000 (IP-direct) | Fake monitoring dashboard | Lab 1 harder-mode (Shodan-style search) |
| Honeypot (no DNS, no flag) | port 2121 (IP-direct) | vsFTPd 2.3.4 banner, deliberate false lead | Lab 1 harder-mode |
| OSINT Sandbox (utility) | port 9091 (IP-direct) | Local RDAP/ASN/CT-log/Shodan/DNS-history stand-in | Lab 1, extended in Lab 5 |
| `app.soulsecure.lab` | `https://app.soulsecure.lab/` | CNAME alias of www | Lab 2 |
| `old-www.soulsecure.lab` | `https://old-www.soulsecure.lab/` | Stale site version | Lab 2 |
| `internal-tools.soulsecure.lab` (no DNS) | vhost brute force | Internal tools page | Lab 2 |
| `legacy-portal.soulsecure.lab` (no DNS, TLS SAN only) | vhost brute force | Legacy partner portal | Lab 2 |
| `beta.soulsecure.lab` (no DNS + header-gated) | vhost brute force + `X-Beta-Access` header | Beta feature flag demo | Lab 2 harder-mode |
| 5 S3-style + 1 GCS-style buckets | under `storage.soulsecure.lab` | See Lab 4 InstructorKey | Lab 4 |
| `origin-direct.soulsecure.lab` (no DNS) | vhost brute force / DNS history | True origin, bypasses CDN | Lab 5 |
| `search.soulsecure.lab` (no DNS, no flag) | vhost brute force | WAF fingerprinting exercise | Lab 5 harder-mode |
| `/robots.txt`, `/staging-notes/`, `/.well-known/security.txt`, `/assets/js/main.js` | under `www.soulsecure.lab` | Recon-via-well-known-files | Lab 5 |

## TLS

One CA-signed certificate (100-year validity, both CA and server cert) covers every
active hostname — SAN list grows with `LAB_LEVEL`. Fetch and trust it before anything
else:
```bash
curl -s http://www.soulsecure.lab/ca.crt -o ca.crt
```
Full detail in [Module2-Docker-Ops.md](Docker-Ops.md).

## Deployment: Docker + `labctl`

The whole module runs as **one Docker Compose stack**, with a `LAB_LEVEL` (1–5)
environment variable controlling how much content each service exposes — so an
instructor can run "just Lab 3" in isolation, or the full cumulative state
(`labctl start 5`). See **[Module2-Docker-Ops.md](Docker-Ops.md)** for the
control script, the reverse-proxy/TLS architecture, and one-time host setup.

Dynamic IP detection works unmodified on a static VM or a freshly-launched EC2
instance — a `soulsecure-boot.service` systemd unit re-detects the IP and starts the
appliance's assigned lab level automatically on every boot, no SSH required.

## Per-lab OVA exports

Five standalone VMware appliance files (one per lab, each self-configuring its IP and
lab level on first boot — no setup needed after import) are in
**[OVA-Exports/](OVA-Exports/)**. See that folder's README for import instructions and
how to regenerate them if lab content changes later.

Module 2 is fully complete: 5 labs, 20 flags, Docker-based HTTPS-gateway deployment
with `labctl`, and 5 distributable OVA appliances.
