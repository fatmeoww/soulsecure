# Module 2 — Lab 1: Cloud Asset Discovery

**Course:** Cloud Pentest — Module 2: Reconnaissance & Enumeration
**Target:** SoulSecure Inc. (simulated engagement)
**Estimated time:** 60–90 minutes

---

## 0. One-time setup: point your DNS at the lab, trust the lab CA

This entire module (all 5 labs) is served over HTTPS through one nginx front door using
a private CA the instructor generated for this environment. Two one-time steps before
you touch anything else:

**1) Point your resolver at the target host.** Your instructor will give you
`<TARGET_IP>` for today's session. Edit `/etc/resolv.conf` on your attack machine:

```bash
sudo bash -c 'echo "nameserver <TARGET_IP>" > /etc/resolv.conf'
```

From now on, every `*.soulsecure.lab` name resolves automatically — no more typing
raw IPs or `--resolve` tricks.

**2) Trust the lab's CA certificate** (so you stop seeing TLS warnings on every
request). It's served in the clear specifically so you can fetch it before trusting
anything else on this host:

```bash
curl -s http://www.soulsecure.lab/ca.crt -o soulsecure-ca.crt
# use it explicitly per-request:
curl --cacert soulsecure-ca.crt https://www.soulsecure.lab/
# ...or install it system-wide (Debian/Kali):
sudo cp soulsecure-ca.crt /usr/local/share/ca-certificates/soulsecure-lab.crt
sudo update-ca-certificates
```

If you'd rather skip cert validation entirely for speed, `curl -k` works everywhere
in this module too — your choice.

## 1. Scenario

You are performing an authorized cloud penetration test against **SoulSecure Inc.**, a
fictional cybersecurity SaaS company. This is Recon Module — before touching anything,
your first job is to map the organization's external cloud footprint: what hosts, IPs,
and services exist, and what cloud provider(s) they run on.

> **Rules of Engagement (reminder from Module 1):** Your authorized scope is limited to
> `<TARGET_IP>` and any hostname under `soulsecure.lab`. Do not scan or touch
> anything outside this scope. All activity should be passive/non-destructive
> reconnaissance only — no exploitation in this lab.

## 2. What the client gave you

SoulSecure's IT contact sent over this scoping email before the engagement started:

> Hi — here's what we'd like assessed. Our main environment sits on `<TARGET_IP>`.
> The externally-facing stuff we know about is:
> - `soulsecure.lab` (corporate site)
> - `www.soulsecure.lab`
> - `api.soulsecure.lab`
>
> We think that's everything customer-facing, but honestly our cloud footprint has
> grown organically over a few years and nobody has a full inventory anymore — that's
> partly why we hired you. Let us know what else you find.
>
> — SoulSecure IT

That last line is the whole point of this lab: **the client's own list is incomplete.**
Your job is to build the *real* asset inventory.

## 3. Learning objectives

By the end of this lab you will be able to:

- Use RDAP/WHOIS-style and ASN lookups to identify an organization's IP allocation
- Use Certificate Transparency (CT) logs to discover subdomains that were never
  publicly announced
- Brute-force DNS to find hosts missing from CT logs and client-provided scope
- Recognize that **DNS enumeration alone is not enough** — full port scans of in-scope
  IPs can reveal assets with no DNS record at all ("shadow IT")
- Fingerprint services to infer which cloud provider they run on
- Produce a clean, client-ready cloud asset inventory

## 4. Tools you'll want

- `dig` / `nslookup` — DNS queries
- `curl` — HTTP banner/header inspection, and querying the OSINT sandbox (see below)
- `nmap` — full TCP port scan (`-p-`), service/version detection (`-sV`)
- A subdomain wordlist (a short starter list is suggested in Hint 2 if you get stuck)

### The OSINT Sandbox

This lab network is isolated (no internet), so real-world sources like `whois`,
a BGP looking-glass, `crt.sh`, or Shodan aren't reachable. A local stand-in — the
**OSINT Sandbox** — runs on the target host on its own port,
`http://<TARGET_IP>:9091/` (it's infrastructure for the lab, not an in-scope asset,
which is exactly why it doesn't have a hostname), and mimics those exact workflows
with realistic data.

**Easiest way to use it: open `http://<TARGET_IP>:9091/` in a browser.** It's a small
GUI — one card per lookup type, with an input box and a button. Every result also
shows you the **exact curl command** it's equivalent to, so you learn the CLI form at
the same time (you'll need it — Labs 2–5 don't have a GUI).

If you'd rather use the command line directly:
```bash
curl -s "http://<TARGET_IP>:9091/rdap?ip=<TARGET_IP>/24"
curl -s "http://<TARGET_IP>:9091/asn?query=soulsecure"
curl -s "http://<TARGET_IP>:9091/ct-log?domain=soulsecure.lab"
```

> Note: the OSINT Sandbox is a **lab utility**, not an in-scope target asset — don't
> include it in your asset inventory.

## 5. Tasks

1. **Passive recon.** Query the OSINT Sandbox for RDAP/ASN info on the target's IP
   range, then pull the CT log for `soulsecure.lab`. What subdomains show up that
   *weren't* in the client's scoping email?
2. **DNS enumeration.** Resolve every hostname you now know about. Then brute-force a
   wordlist of common subdomain names against `soulsecure.lab` — does anything else
   resolve that wasn't in the CT log either?
   ```bash
   for h in www api mail storage backup backup-eu vpn dev staging jenkins jenkins-old admin portal cdn ftp; do
     echo "== $h =="; dig +short "$h.soulsecure.lab"
   done
   ```
3. **Full port scan.** Run a full TCP port scan against `<TARGET_IP>` itself (not a
   hostname — you want every open port on the box, regardless of what resolves to it).
   ```bash
   nmap -p- -sV <TARGET_IP>
   ```
   Compare what you find to the hostnames you've resolved so far. You'll notice most
   business services live behind just two ports (80/443, everything routed by
   hostname) — that's realistic; a handful of things *don't* follow that pattern.
   Is there anything listening that has **no matching DNS record at all**?
4. **Fingerprint everything.** For each hostname, grab HTTP headers
   (`curl -i https://<hostname>/`), and SMTP/other banners
   (`nc mail.soulsecure.lab 25`). Look for anything that hints at the underlying cloud
   provider (response headers, error message formats, internal hostnames,
   `Server` banners).
5. **Build your inventory.** Fill in the deliverable table (Section 8) with everything
   you found.
6. **Capture flags.** Three of the assets you find will contain a flag in the format
   `flag{md5-hash}` (usually in an HTML comment — view source, don't just eyeball the
   rendered page).

## 6. Reference: known hostnames so far

| Hostname | How you reach it |
|---|---|
| `www.soulsecure.lab` / `soulsecure.lab` | `https://www.soulsecure.lab/` |
| `api.soulsecure.lab` | `https://api.soulsecure.lab/` |
| `storage.soulsecure.lab` | `https://storage.soulsecure.lab/` |
| `vpn.soulsecure.lab` | `https://vpn.soulsecure.lab/` |
| `backup-eu.soulsecure.lab` | `https://backup-eu.soulsecure.lab/` |
| `mail.soulsecure.lab` | `nc mail.soulsecure.lab 25` (SMTP, not HTTP) |

## 7. Deliverable: Asset Inventory

Fill this in and submit it.

| Hostname / IP | Reached via | Discovered via | Service (fingerprint) | Cloud provider indicator | Notes |
|---|---|---|---|---|---|
| | | | | | |

**Flags found (paste all you capture):**

- [ ] Flag 1: `flag{________________________________}`
- [ ] Flag 2: `flag{________________________________}`
- [ ] Flag 3: `flag{________________________________}`
- [ ] Flag 4 (harder mode, see Section 8): `flag{________________________________}`

## 8. Harder mode: Shodan-style search + a decoy to watch out for

- **Faster asset discovery via internet-wide scan simulation.** Real internal
  dashboards often get found through Shodan/Censys before anyone bothers with a full
  port scan. Try:
  ```bash
  curl -s "http://<TARGET_IP>:9091/shodan-search?query=soulsecure"
  ```
  It points at a port running something worth a look — this one genuinely doesn't have
  a hostname, connect directly with `http://<TARGET_IP>:<port>/`.
- **Watch for a false lead.** Somewhere in your full port scan you'll find a banner
  `220 (vsFTPd 2.3.4)` — a famous version tied to a real 2011 backdoor
  (CVE-2011-2523). It's tempting to get excited. In this lab it's just a banner with
  nothing behind it and no flag. The lesson: a scary-looking banner is a lead to
  verify, not a finding to report on sight.

## 9. Hints

<details>
<summary>Hint 1 — stuck on where to start</summary>

Start passive, then go active: OSINT Sandbox first (RDAP → ASN → CT log), *then* DNS
resolution of what you've learned, *then* a full port scan of the IP itself. Each
technique should surface things the previous one missed.
</details>

<details>
<summary>Hint 2 — subdomain wordlist</summary>

A short starter wordlist to brute-force against `soulsecure.lab`:
`www, api, mail, storage, backup, backup-eu, vpn, dev, staging, jenkins, jenkins-old,
admin, portal, cdn, ftp`. Notice that not every one of these will resolve — that's
normal, and it's exactly what real subdomain brute-forcing looks like.
</details>

<details>
<summary>Hint 3 — the full port scan matters</summary>

If you only ever connect to hostnames you got from DNS, you will miss at least one
asset in this lab. `nmap -p- -sV <TARGET_IP>` against the bare IP is not optional
here — that's the whole lesson. Most of what you'll find behind non-standard ports in
this lab has *no hostname at all*, on purpose.
</details>

## 10. Next up

Lab 2 (DNS & Virtual Host Enumeration) picks up exactly where this one left off: many
of these hostnames actually share the same IP *and the same port* (443) and are
distinguished only by which name you ask for (TLS SNI / HTTP `Host` header) — you'll
learn to properly enumerate and interact with virtual hosts, including ones with no
DNS record whatsoever.
