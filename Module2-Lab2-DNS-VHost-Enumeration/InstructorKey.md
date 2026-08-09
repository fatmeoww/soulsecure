# Module 2 — Lab 2: DNS & Virtual Host Enumeration — Instructor Key

Runs on the **same target host** as Lab 1. Adds new DNS records and new nginx vhosts —
**all vhosts in this lab are on port 443 only** (see Lab 1 InstructorKey's "Access
architecture" section for why: everything routes through one gateway now, no more
per-service ports for anything except the intentionally-exposed Lab 1 decoys).

**GUI:** the Recon Toolkit (`http://<TARGET_IP>:9091/`, part of the `osint` service)
gained three real (not simulated) tools that cover this entire lab: DNS Lookup (wraps
`dig`), an HTTP(S) Request tool (a small Postman/Burp-Repeater-style panel, wraps
`curl`, used for all vhost/header testing here), and a TLS Certificate Viewer (wraps
`openssl s_client`+`x509`). Backend implementation: `apps/osint_app.py`,
`/tools/dns-lookup`, `/tools/http-request`, `/tools/tls-cert`. Not gated by
`LAB_LEVEL` (always visible) since they're generic tools, not lab-specific content —
the underlying target content is still gated as normal.

## What's new vs. Lab 1

| Name | In DNS? | Type | Discovery method | Notes |
|---|---|---|---|---|
| `app.soulsecure.lab` | Yes | CNAME → `www.soulsecure.lab` | Given/DNS sweep | Teaches CNAME following |
| TXT records on `soulsecure.lab` | Yes | TXT (SPF + site-verification) | DNS sweep | Realism / OSINT flavor, no flag |
| MX record on `soulsecure.lab` | Yes | MX → `mail.soulsecure.lab` | DNS sweep | Realism, no flag |
| CAA record on `soulsecure.lab` | Yes | CAA (`letsencrypt.org`) | DNS sweep | Realism, no flag |
| SRV record `_autodiscover._tcp` | Yes | SRV → `www.soulsecure.lab:443` | DNS sweep | Realism, no flag |
| AXFR attempt | n/a | — | `dig soulsecure.lab AXFR` | CoreDNS's `file` plugin refuses (no `transfer` plugin configured) — expected "Transfer failed", teaches the habit |
| `old-www.soulsecure.lab` | Yes | A (host-record) | DNS brute force | **Flag 1** |
| `internal-tools.soulsecure.lab` | **No** | — | vhost brute force via `curl --resolve` | **Flag 2**; content hints at Lab 3's `/api/internal/` |
| `legacy-portal.soulsecure.lab` | **No** | — | TLS certificate SAN list only | **Flag 3** |
| `beta.soulsecure.lab` | **No** | — | vhost brute force, THEN header `X-Beta-Access: enabled` | **Flag 4** (harder mode) |

## Flags (ground truth)

| Flag | Trigger | Value |
|---|---|---|
| Flag 1 | `https://old-www.soulsecure.lab/` | `flag{9b1f3a2e6c4d8017f5a3b9e2d4c6f108}` |
| Flag 2 | `https://internal-tools.soulsecure.lab/` (no DNS record) | `flag{3867f231921ee17428ff92e577a8bbc3}` |
| Flag 3 | `https://legacy-portal.soulsecure.lab/` (TLS SAN-only) | `flag{e8808bcfa5107695bfee0ee615665001}` |
| Flag 4 (harder-mode) | `https://beta.soulsecure.lab/` + header `X-Beta-Access: enabled` | `flag{ac12390cdf07e028f08aaf263e19d595}` |

## Verification commands

```bash
dig +short old-www.soulsecure.lab                    # -> LAB_IP
dig +short internal-tools.soulsecure.lab               # -> empty (by design)
dig +short legacy-portal.soulsecure.lab                # -> empty (by design)
dig +short beta.soulsecure.lab                          # -> empty (by design)
dig +short TXT soulsecure.lab
dig +short MX soulsecure.lab
dig +short CAA soulsecure.lab
dig +short SRV _autodiscover._tcp.soulsecure.lab
dig soulsecure.lab AXFR                                  # expect "Transfer failed"

curl -sk --resolve old-www.soulsecure.lab:443:<LAB_IP> https://old-www.soulsecure.lab/ | grep flag
curl -sk --resolve internal-tools.soulsecure.lab:443:<LAB_IP> https://internal-tools.soulsecure.lab/ | grep flag

echo | openssl s_client -connect <LAB_IP>:443 -servername www.soulsecure.lab 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
curl -sk --resolve legacy-portal.soulsecure.lab:443:<LAB_IP> https://legacy-portal.soulsecure.lab/ | grep flag

curl -sk --resolve beta.soulsecure.lab:443:<LAB_IP> https://beta.soulsecure.lab/                                        # denied teaser
curl -sk --resolve beta.soulsecure.lab:443:<LAB_IP> https://beta.soulsecure.lab/ -H 'X-Beta-Access: enabled' | grep flag  # Flag 4
```

## Grading rubric (out of 100)

| Criterion | Points |
|---|---|
| Correctly queried TXT/MX/CAA/SRV/CNAME and interpreted results | 10 |
| Attempted AXFR and correctly interpreted the refusal | 5 |
| Re-ran/expanded DNS brute force and found `old-www` | 15 |
| Correctly performed vhost brute forcing (via `--resolve` or equivalent) and found `internal-tools` | 20 |
| Correctly pulled and read the TLS cert SAN list, found `legacy-portal` | 20 |
| Found `beta.soulsecure.lab`, read the hint, and sent the right header | 15 |
| Inventory table updated with discovery method per new host | 15 |

## File/config changes made on the host (delta from Lab 1)

- `/opt/soulsecure-labs/dns/zone-lab2.tmpl` — `old-www` A record, `app` CNAME, TXT x2,
  MX, CAA, SRV records
- `/opt/soulsecure-labs/nginx/conf/lab2.conf` — vhost blocks for `app`, `old-www`,
  `internal-tools`, `legacy-portal` (all `listen 443 ssl;`, no port-80 versions
  anymore), plus the `beta` vhost + its `map $http_x_beta_access $beta_root` gate
- `/opt/soulsecure-labs/nginx/content/{old-www,internal-tools,legacy-portal,beta,beta-denied}/`
- TLS: the shared cert's SAN list is built incrementally by `nginx/entrypoint.sh` —
  `legacy-portal` and `beta` only get added to the SAN once `LAB_LEVEL >= 2`, so a
  cert pulled at `LAB_LEVEL=1` doesn't leak either name ahead of time.

No new systemd/Docker services were needed — everything rides on the existing `www`
(nginx) container from Lab 1.

## Known limitations

- The TLS cert is self-signed (well, CA-signed by a private lab CA) — `curl` needs
  `-k` or `--cacert <path-to-ca.crt>` (fetchable at `http://<any-hostname>/ca.crt`
  before trusting anything). That's expected; call it out if a student is confused by
  it rather than treating it as a bug in the lab.
- `curl -H "Host: X"` without `--resolve` will NOT correctly set TLS SNI when
  connecting to a bare IP — it happens to still work here because every vhost shares
  one cert, but this is worth flagging to students as something that would behave
  differently against a real target with per-vhost certificates.
