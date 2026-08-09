# Module 2 — Lab 2: DNS & Virtual Host Enumeration

**Course:** Cloud Pentest — Module 2: Reconnaissance & Enumeration
**Target:** SoulSecure Inc. (simulated engagement, continued from Lab 1)
**Target:** same host as Lab 1 — make sure your nameserver and CA trust from Lab 1
Section 0 are still set up
**Estimated time:** 60–90 minutes

---

## 1. Recap & scenario

In Lab 1 you built an asset inventory for SoulSecure Inc. and noticed something
important: several hostnames (`www`, `api`, `storage`, `vpn`, `backup-eu`...) all
resolve to the **same IP and the same port (443)**. That's extremely common in modern
cloud environments — one gateway/ingress serving many logical "sites" distinguished
only by which hostname the client asks for (TLS SNI, then the HTTP `Host` header).

This lab is about that distinction mechanism specifically: **DNS record types beyond
simple A records**, and **virtual hosts over TLS** — how a single IP:port can serve
completely different content depending on the hostname a client presents.

> **Scope reminder:** `<TARGET_IP>` and `*.soulsecure.lab` only. Passive/non-destructive
> recon only.

**GUI available:** the Recon Toolkit at `http://<TARGET_IP>:9091/` has three cards
that cover everything in this lab — **DNS Lookup** (any record type), **HTTP(S)
Request Tool** (vhost brute forcing, custom headers), and **TLS Certificate Viewer**
(SAN list). Every result shows the equivalent CLI command, since Lab 3 onward you'll
need to run those commands yourself. Use whichever you're more comfortable with —
both are shown below.

## 2. Learning objectives

- Query and interpret DNS record types beyond `A`: `CNAME`, `TXT`, `MX`, `CAA`, `SRV`
- Understand how TLS SNI + HTTP virtual hosting work together, and why the same
  IP:port can return different content for different hostnames
- Brute-force virtual hosts directly against an IP, independent of DNS, using
  `curl --resolve` to control SNI without needing a real DNS record
- Extract hostnames from a TLS certificate's Subject Alternative Name (SAN) list —
  a source of hostname info that has nothing to do with DNS at all
- Recognize why DNS enumeration and vhost enumeration are two *separate* techniques
  that surface different assets

## 3. Tasks

### 3.1 — Full DNS record sweep

Lab 1 only had you resolve `A` records. Go back over `soulsecure.lab` and pull every
common record type:

```bash
dig soulsecure.lab TXT
dig soulsecure.lab MX
dig soulsecure.lab CAA
dig _autodiscover._tcp.soulsecure.lab SRV
dig app.soulsecure.lab        # CNAME -- what does it point to, and what does that resolve to?
```

**Always attempt a zone transfer too, even though it will almost certainly fail:**
```bash
dig soulsecure.lab AXFR
```
A correctly-configured DNS server refuses this (expect "Transfer failed"). It costs
one command to check, and on a misconfigured server it hands you the entire zone at
once — make it a habit on every real engagement.

Also re-run your Lab 1 subdomain wordlist brute force — SoulSecure added at least one
more real DNS record since Lab 1 that a plain `A`-record wordlist scan will catch.

### 3.2 — Virtual host brute forcing (no DNS required)

Not every vhost configured on the gateway has a DNS record. You can still discover one
by presenting different hostnames directly to the IP and watching for a different
response. Since everything here is HTTPS, use `curl --resolve` to pin a hostname to
the target IP without needing an actual DNS record — this sets both the TLS SNI *and*
the HTTP `Host` header correctly in one shot:

```bash
for h in old-www new-www dev staging test internal internal-tools admin-panel tools legacy legacy-portal portal intranet beta; do
  echo "== $h =="
  curl -sk --resolve "$h.soulsecure.lab:443:<TARGET_IP>" \
    -o /dev/null -w "%{http_code} %{size_download}\n" "https://$h.soulsecure.lab/"
done
```

Compare **response size**, not just HTTP status code — a lot of misconfigured servers
return `200` for everything (including the wrong page) so status code alone will
mislead you.

### 3.3 — Pull the TLS certificate and read its SAN list

```bash
echo | openssl s_client -connect <TARGET_IP>:443 -servername www.soulsecure.lab 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
```
(`nmap --script ssl-cert -p 443 <TARGET_IP>` gets you the same information.)

This cert covers a lot of hostnames — most of them you'll already recognize from DNS
or your vhost brute force. But at least one name in that list has **never appeared
anywhere else** in this engagement. Cross-reference every entry against what you
already know; the one that doesn't match anything is the lead worth chasing. Visit it
the same way you tested vhosts in 3.2.

### 3.4 — A vhost with a second gate

One of the vhosts you find in 3.2 responds — but not with the flag yet. Read what it
says carefully; it tells you exactly what else you need to send along with your
request to unlock the real content.

### 3.5 — Update your asset inventory

Add every new hostname/vhost you found in this lab to the inventory table you started
in Lab 1, and note **which technique** found each one (DNS brute force / vhost brute
force / TLS SAN). That "discovered via" column is exactly what a client report needs.

## 4. Deliverable

Extend your Lab 1 asset inventory table with the new rows, plus:

**Flags found:**
- [ ] Flag 1 (DNS brute force): `flag{________________________________}`
- [ ] Flag 2 (vhost brute force, no DNS): `flag{________________________________}`
- [ ] Flag 3 (TLS SAN only): `flag{________________________________}`
- [ ] Flag 4 (harder mode — vhost + header gate): `flag{________________________________}`

## 5. Hints

<details>
<summary>Hint 1 — CNAME chains</summary>

`dig` by default follows CNAMEs and shows you the final `A` record too — that's why
`dig app.soulsecure.lab` (no type specified) shows both the CNAME line and an IP.
</details>

<details>
<summary>Hint 2 — vhost wordlist</summary>

Try: `old-www, new-www, dev, staging, test, internal, internal-tools, admin-panel,
tools, legacy, legacy-portal, portal, intranet, beta`. Only a few of these will
return something different from the default site.
</details>

<details>
<summary>Hint 3 — why --resolve instead of just -H "Host:"</summary>

For plain HTTP this distinction barely matters. Over HTTPS it does: connecting to a
raw IP and setting only `-H "Host: X"` does **not** set the TLS SNI to `X` — and while
this particular lab's shared cert means the handshake will still succeed either way,
`--resolve host:443:IP` is the technique that generalizes correctly to real-world
targets where SNI-based routing actually depends on getting SNI right. Learn it now.
</details>

<details>
<summary>Hint 4 — the header</summary>

The "second gate" vhost's default response literally names the HTTP header it's
checking for and what value unlocks the real content. Add it with `curl -H`.
</details>

## 6. Next up

Lab 3 (API Reconnaissance) goes deep on `api.soulsecure.lab` — the `internal-tools`
vhost you found in this lab pointed at an internal API base path. Bring that note with
you.
