# Module 2 — Lab 5: CDN, Origin & Technology Fingerprinting

**Course:** Cloud Pentest — Module 2: Reconnaissance & Enumeration
**Target:** SoulSecure Inc. (simulated engagement — final lab of this module)
**Target:** same host as Labs 1–4 — make sure your DNS/CA setup from Lab 1 Section 0
is still in place
**Estimated time:** 60–90 minutes

---

## 1. Recap & scenario

This is the last recon lab. You've built a full asset inventory (Lab 1), mapped DNS and
virtual hosts (Lab 2), enumerated the API (Lab 3), and looted object storage (Lab 4).
The last piece is understanding **what's actually sitting in front of what you've been
scanning** — most cloud-hosted sites today are behind a CDN/WAF, and attacking the CDN
edge is not the same as attacking the real server behind it. Finding the true origin is
often the single highest-value recon result in a real engagement, because origin
servers frequently skip protections (rate limiting, WAF rules) that only apply to CDN
traffic.

> **Scope reminder:** `soulsecure.lab` and its subdomains only. Passive/non-destructive
> only.

## 2. Learning objectives

- Recognize CDN-shaped HTTP response headers (`Age`, `X-Cache`, custom `Server` values)
- Use passive DNS history to find an origin hostname that predates a CDN migration
- Confirm and access an origin server directly, bypassing the CDN edge
- Compare response headers between an edge and its origin to prove which is which
- Use `robots.txt` and `security.txt` as recon sources, not just SEO/compliance files
- Read a site's shipped JavaScript for hardcoded secrets
- Test for the presence of a WAF using canary payloads
- Recognize stack/technology fingerprints leaking through default error handling

## 3. Tasks

### 3.1 — Fingerprint the edge

Pull full response headers from `www.soulsecure.lab` and note anything that looks
CDN-specific (values that only make sense for a caching layer, not an origin
webserver):

```bash
curl -skI https://www.soulsecure.lab/
```

### 3.2 — Check robots.txt and security.txt

Don't skip either — they're often the fastest recon steps available and both get
ignored anyway:

```bash
curl -sk https://www.soulsecure.lab/robots.txt
curl -sk https://www.soulsecure.lab/.well-known/security.txt
```

Visit whatever `robots.txt` tells search engines *not* to index (`Disallow` is a
request to crawlers, not access control). Read `security.txt` closely too — there's a
comment in it that shouldn't really be there.

### 3.3 — Read the site's actual JS bundle

Production JavaScript ships to the browser in full — anyone can read it. Hardcoded
tokens, leftover TODOs, and internal comments are extremely common findings in real
assessments:

```bash
curl -sk https://www.soulsecure.lab/assets/js/main.js
```

### 3.4 — Find a historical origin hostname

Passive DNS history services (SecurityTrails, ViewDNS, and similar) keep old DNS
records even after an organization changes them — including the period *before* a CDN
was put in front of a site. This lab's OSINT Sandbox simulates one:

```bash
curl -s "http://<TARGET_IP>:9091/dns-history?domain=www.soulsecure.lab"
```

### 3.5 — Reach the origin directly

You now have a hostname that's never been in current DNS. Combine it with what you
learned in Lab 2 (vhost brute forcing doesn't require DNS):

```bash
curl -sk --resolve <the-historical-hostname>:443:<TARGET_IP> https://<the-historical-hostname>/
```

Compare its response headers against `www`'s from 3.1. What's present on one and
missing from the other? What does that prove?

### 3.6 — Test for a WAF

Brute-force one more vhost (`search`), then compare a normal request against a canary
payload:

```bash
curl -sk --resolve search.soulsecure.lab:443:<TARGET_IP> \
  "https://search.soulsecure.lab/search?q=hello"
curl -sk --resolve search.soulsecure.lab:443:<TARGET_IP> \
  "https://search.soulsecure.lab/search?q=1%20union%20select%20password%20from%20users"
```

A different response (status code, headers, or body) between the two tells you
there's a WAF in front — and sometimes which product, straight from the response.
This is one of the first things a real assessment checks, before sending anything that
might actually get blocked.

### 3.7 — Provoke a fingerprint via error handling

Hit a path on `api.soulsecure.lab` that you're confident doesn't exist. Read the error
response closely.

### 3.8 — Final consolidated asset map

This is the deliverable for the whole module, not just this lab: merge everything from
Labs 1–5 into one final table. Include the CDN/origin relationship you just proved.

## 4. Deliverable

**CDN/Origin comparison:**

| | Edge (`www`) | Origin (historical hostname) |
|---|---|---|
| `Server` header(s) | | |
| `Age` / `X-Cache` present? | | |
| Other notable headers | | |

**Final consolidated asset inventory** — one table covering every host and service
found across all five labs, each row noting which lab/technique found it.

**Flags found:**
- [ ] Flag 1 (origin bypass): `flag{________________________________}`
- [ ] Flag 2 (robots.txt → staging-notes): `flag{________________________________}`
- [ ] Flag 3 (API error-handler tech fingerprint): `flag{________________________________}`
- [ ] Flag 4 (harder mode — security.txt → JS leak): `flag{________________________________}`

## 5. Hints

<details>
<summary>Hint 1 — what CDN headers look like</summary>

`Age` (seconds since the response was cached) and `X-Cache` (`HIT`/`MISS`) don't mean
anything for an origin server generating a response fresh every time — their mere
presence is itself a strong CDN signal, regardless of the actual values.
</details>

<details>
<summary>Hint 2 — you might notice something odd about the Server header</summary>

Look closely at `www` — you may see the response include *two* different `Server`
values. That's not a trick question: it happens in the real world when a CDN/reverse
proxy fails to strip or overwrite the origin's own `Server` header before forwarding
the response. If you see it, that's itself a finding worth writing up — it means the
origin's real software banner is leaking straight through the CDN.
</details>

<details>
<summary>Hint 3 — the historical hostname</summary>

The OSINT Sandbox's DNS history for `www.soulsecure.lab` shows the same hostname
appearing twice, once as a `CNAME` target and once as a pre-CDN `A` record. That
repetition is the answer. (The `staging-notes` page from `robots.txt` also mentions it
directly, if you want a second confirmation source.)
</details>

<details>
<summary>Hint 4 — security.txt</summary>

There's a comment in it pointing at exactly where the JS bundle lives.
</details>

## 6. Module 2 wrap-up

You've now fully enumerated SoulSecure Inc.'s external footprint: DNS, virtual hosts,
API surface, object storage, and CDN/origin topology — across 5 labs, 20 flags total.
Module 3 (Initial Access & Storage Exploitation) starts putting some of this to use,
beginning with that public `soulsecure-prod-assets` bucket from Lab 4.
