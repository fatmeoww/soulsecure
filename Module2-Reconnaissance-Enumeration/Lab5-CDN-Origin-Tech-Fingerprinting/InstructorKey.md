# Module 2 — Lab 5: CDN, Origin & Technology Fingerprinting — Instructor Key

Runs on the **same target host** as Labs 1–4. Adds: two new static paths under the
`www` root, one new `origin-direct` vhost, one new `search` vhost (WAF fingerprint),
one new OSINT Sandbox endpoint, and one new error handler on the API. No new
systemd/Docker services. **Access changed** since the harder-mode rework:
`origin-direct` and `search` used to be on their own ports (8090 and plain-80
respectively) — both are now `listen 443 ssl;` vhosts through the shared `www` nginx
container, same as everything else (see Lab 1 InstructorKey's "Access architecture").

## What's new vs. Labs 1–4

| Item | Where | In DNS? | Discovery method | Notes |
|---|---|---|---|---|
| `Age` / `X-Cache` headers | `www` response | n/a | Header inspection | CDN-shaped headers, static/fake values |
| `/robots.txt` | `www` | n/a | Direct request | Discloses `/staging-notes/`, `/internal-tools/`, `/api/internal/` |
| `/staging-notes/` | `www` | n/a | robots.txt | **Flag 2**; also plaintext-hints `origin-direct.soulsecure.lab` |
| `/.well-known/security.txt` | `www` | n/a | Direct request | Harder-mode addition; hints at `/assets/js/` |
| `/assets/js/main.js` | `www` | n/a | security.txt hint | Harder-mode addition; **Flag 4** |
| `/dns-history?domain=www.soulsecure.lab` | OSINT Sandbox (port 9091) | n/a | Given in lab guide | Reveals `origin-direct.soulsecure.lab` as historical CNAME/A target |
| `origin-direct.soulsecure.lab` | 443 vhost | **No** | DNS history OR staging-notes hint, then vhost brute force | **Flag 1**; no CDN headers, no `SoulSecure-CDN` Server override, has `X-Debug-Mode: true` |
| `search.soulsecure.lab` (WAF fingerprint) | 443 vhost | **No** | vhost brute force | Harder-mode addition, no flag — technique only |
| API custom 404 handler | `api.soulsecure.lab`, any unknown path | n/a | Probing unknown paths | **Flag 3**; leaks fake stack details |

## Flags (ground truth)

| Flag | Trigger | Value |
|---|---|---|
| Flag 1 | `https://origin-direct.soulsecure.lab/` (via `--resolve` or DNS) | `flag{8290248cac3247ccf5288ee3f79e39c7}` |
| Flag 2 | `https://www.soulsecure.lab/staging-notes/` | `flag{d79d7cee7f1e1f4bcdc26fcee00ce18a}` |
| Flag 3 | `https://api.soulsecure.lab/<any unknown path>` | `flag{ea97648f7c958c3e5c750862b4ab4519}` |
| Flag 4 (harder-mode) | `https://www.soulsecure.lab/assets/js/main.js` | `flag{6f15fea713da8d4e53e704437a6b436a}` |

## Verification commands

```bash
curl -skI https://www.soulsecure.lab/ | grep -iE 'Server|Age|X-Cache'
curl -sk https://www.soulsecure.lab/robots.txt
curl -sk https://www.soulsecure.lab/staging-notes/ | grep flag                          # Flag 2
curl -sk https://www.soulsecure.lab/.well-known/security.txt
curl -sk https://www.soulsecure.lab/assets/js/main.js | grep flag                       # Flag 4
curl -s "http://<LAB_IP>:9091/dns-history?domain=www.soulsecure.lab"

curl -sk --resolve origin-direct.soulsecure.lab:443:<LAB_IP> https://origin-direct.soulsecure.lab/ | grep flag   # Flag 1
curl -skI --resolve origin-direct.soulsecure.lab:443:<LAB_IP> https://origin-direct.soulsecure.lab/ | grep -iE 'Server|Age|X-Cache|X-Debug'

curl -sk --resolve search.soulsecure.lab:443:<LAB_IP> "https://search.soulsecure.lab/search?q=hello"
curl -sk --resolve search.soulsecure.lab:443:<LAB_IP> "https://search.soulsecure.lab/search?q=1%20union%20select" -i | head -6

curl -sk https://api.soulsecure.lab/doesnotexist                                         # Flag 3
```

## Known quirk: duplicate `Server` header on the edge — intentional, not a bug

`nginx`'s `add_header Server "SoulSecure-CDN" always;` does **not** replace nginx's own
built-in `Server` header (that requires the third-party `headers-more` module, which
isn't in this build) — it *adds* a second one. `curl -I` against `www` shows **both**
`Server: nginx/1.31.3` and `Server: SoulSecure-CDN`. Rather than installing
`nginx-extras` to suppress it, this lab leans into it as a real, common
misconfiguration class: **a reverse proxy/CDN that forwards the origin's own `Server`
header unchanged instead of stripping it.** On the *real* `origin-direct` vhost there
is only ever one `Server` header (no `SoulSecure-CDN` override), which is what makes
the edge-vs-origin comparison meaningful.

## Grading rubric (out of 100)

| Criterion | Points |
|---|---|
| Correctly identified CDN-indicating headers on the edge | 10 |
| Checked `robots.txt` and retrieved `/staging-notes/` | 10 |
| Checked `security.txt` and found the JS bundle leak | 10 |
| Used DNS history (or the staging-notes hint) to find `origin-direct` | 15 |
| Successfully bypassed the CDN and reached the origin directly, captured Flag 1 | 15 |
| Correctly compared edge vs. origin headers in the deliverable table | 10 |
| Tested for and correctly identified the WAF via canary payloads | 10 |
| Found the API 404 tech-fingerprint disclosure | 10 |
| Complete, clean **final consolidated** asset inventory (all 5 labs) | 10 |

## File locations

- `/opt/soulsecure-labs/nginx/content/www/robots.txt`,
  `/opt/soulsecure-labs/nginx/content/www/staging-notes/index.html`,
  `/opt/soulsecure-labs/nginx/content/www/.well-known/security.txt`,
  `/opt/soulsecure-labs/nginx/content/www/assets/js/main.js`
- `/opt/soulsecure-labs/nginx/content/origin-direct/index.html`
- `/opt/soulsecure-labs/nginx/conf/lab5.conf` — `origin-direct` and `search` vhosts
  (both `listen 443 ssl;`), `Age`/`X-Cache` injected via
  `nginx/conf/lab5-extra-headers.conf` (included into the `www` block's
  `snippets/www-extra-headers.conf` only at `LAB_LEVEL >= 5`)
- `/opt/soulsecure-labs/apps/osint_app.py` — `DNS_HISTORY` dict + `/dns-history` route
- `/opt/soulsecure-labs/apps/api_app.py` — `@app.errorhandler(404)` at the bottom

## Module 2 complete — full flag list (all 5 labs, for quick reference)

20 flags total: 3 core + 1 harder-mode add-on per lab. Harder-mode flags marked ⭐.

| Lab | Flag | Value |
|---|---|---|
| 1 | jenkins-old (shadow IT, port scan only, port 9090) | `flag{cdad904c3f229c8a33f6b9a37b2ec64b}` |
| 1 | vpn gateway (DNS brute force, `https://vpn.soulsecure.lab/`) | `flag{553edeb5b994421a80636e7556fab1b4}` |
| 1 | backup-eu (CT log, `https://backup-eu.soulsecure.lab/`) | `flag{5ff49b3a254b1781f99d3e60f185b706}` |
| 1 ⭐ | Grafana decoy, port 3000 (Shodan-style search) | `flag{24d7fbca483d726d1ae7ba4c745acd2b}` |
| 2 | old-www (DNS brute force, `https://old-www.soulsecure.lab/`) | `flag{9b1f3a2e6c4d8017f5a3b9e2d4c6f108}` |
| 2 | internal-tools (vhost brute force, no DNS) | `flag{3867f231921ee17428ff92e577a8bbc3}` |
| 2 | legacy-portal (TLS SAN only) | `flag{e8808bcfa5107695bfee0ee615665001}` |
| 2 ⭐ | beta.soulsecure.lab (vhost + `X-Beta-Access` header) | `flag{ac12390cdf07e028f08aaf263e19d595}` |
| 3 | /api/internal/debug (spec leak) | `flag{3555384be5128ee4c26ffc4992d2c1e1}` |
| 3 | /api/v2/status (version brute force) | `flag{76616423d4eeb78183ccfbf84092b179}` |
| 3 | /api/v1/orders verbose error | `flag{7c8934797877b254b9db3695a84cbf8b}` |
| 3 ⭐ | /graphql introspection → internalSecret | `flag{b1579ebf26c0e4de304a77b01879d801}` |
| 4 | soulsecure-prod-assets config leak | `flag{c3909083d936385564ffe54a86c340b9}` |
| 4 | soulsecure-backups-eu notes | `flag{bb244e7d9025c5600bdc019ad5c726dc}` |
| 4 | soulsecure-terraform-state | `flag{e21e4a4043ae07729741ef42be7dc9af}` |
| 4 ⭐ | GCS-style bucket soulsecure-gcs-assets | `flag{b091f26222ff3e2e245ee90a35927202}` |
| 5 | origin-direct bypass | `flag{8290248cac3247ccf5288ee3f79e39c7}` |
| 5 | staging-notes via robots.txt | `flag{d79d7cee7f1e1f4bcdc26fcee00ce18a}` |
| 5 | API 404 tech fingerprint | `flag{ea97648f7c958c3e5c750862b4ab4519}` |
| 5 ⭐ | security.txt → JS source leak | `flag{6f15fea713da8d4e53e704437a6b436a}` |

Non-flag harder-mode techniques (graded on whether the student attempted/documented
them, not a captured value): Lab 1 honeypot decoy (port 2121, verify-before-reporting
lesson), Lab 2 CAA/SRV records + AXFR attempt, Lab 5 WAF fingerprinting
(`search.soulsecure.lab/search`).

## Ports that still exist outside the 443 gateway (full reference)

| Port | Service | Has DNS name? |
|---|---|---|
| 22 | SSH (host management, out of scope) | n/a |
| 25 | `mail` (SMTP) | Yes, `mail.soulsecure.lab` |
| 53 | `dns` (CoreDNS) | n/a |
| 80 | `www` (redirect-to-443 + `/ca.crt` only) | — |
| 443 | `www` (everything else — all vhosts) | — |
| 2121 | `honeypot` (decoy) | No |
| 3000 | `grafana-decoy` | No |
| 9090 | `jenkins-old` (shadow IT) | No |
| 9091 | `osint` (OSINT Sandbox, lab utility, not a target) | No |

Everything else (api, storage, vpn, backup-eu, old-www, app, internal-tools, beta,
legacy-portal, origin-direct, search) is reachable **only** via hostname on 443.
