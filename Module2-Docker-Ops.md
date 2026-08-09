# Module 2 — Docker Deployment & `labctl` Operations

All 5 labs run as **one Docker Compose stack on one VM**, with a `LAB_LEVEL`
environment variable (1–5) controlling how much content each service exposes.

## Access architecture: one HTTPS gateway, hostname-routed

As of the harder-mode rework, almost everything lives behind **one nginx container
(`www`) on port 443**, reverse-proxying to backend services by hostname (TLS SNI +
HTTP `Host` header) — the way a real ingress/API-gateway-fronted cloud environment
looks. Port 80 exists only to redirect to 443 and to serve `/ca.crt` in the clear
(so clients can fetch and trust the lab's CA before speaking TLS to anything else).

**Reverse-proxied through `www` on 443 (no port of their own anymore):**
`www.soulsecure.lab`, `api.soulsecure.lab`, `storage.soulsecure.lab`,
`vpn.soulsecure.lab`, `backup-eu.soulsecure.lab`, `old-www.soulsecure.lab`,
`app.soulsecure.lab`, `internal-tools.soulsecure.lab`, `beta.soulsecure.lab`,
`legacy-portal.soulsecure.lab`, `origin-direct.soulsecure.lab`,
`search.soulsecure.lab`.

**Still on their own dedicated ports (deliberately — see below for why):**

| Port | Service | Has a DNS name? | Why it's not behind the gateway |
|---|---|---|---|
| 25 | `mail` | Yes, `mail.soulsecure.lab` | SMTP, not HTTP — can't be reverse-proxied through nginx |
| 53 | `dns` (CoreDNS) | n/a | It *is* the DNS server |
| 2121 | `honeypot` | No | Lab 1 decoy — the whole point is "found by port scan, not DNS" |
| 3000 | `grafana-decoy` | No | Lab 1 harder-mode — found via Shodan-style search, not DNS |
| 9090 | `jenkins-old` | No | Lab 1 core — shadow-IT / "port scan finds it, DNS doesn't" lesson |
| 9091 | `osint` (OSINT Sandbox) | No | Lab utility, not an in-scope target asset |

Removing the direct port mappings for api/storage/vpn/backup-eu also made a full port
scan of the target IP much more realistic — most business services no longer show up
as their own open port at all, matching how a well-run (if imperfect) cloud
environment actually looks.

## TLS: one CA, 100-year validity, generated fresh on every boot

`nginx/entrypoint.sh` generates, on every container start:
1. A self-signed **root CA** (`ca.crt`/`ca.key`), 36500-day (100-year) validity
2. A **server certificate** signed by that CA (`soulsecure.crt`/`soulsecure.key`),
   also 100-year validity, with a SAN list covering every currently-active vhost

The SAN list is built incrementally by `LAB_LEVEL` — same gating pattern as
everything else in this module — so a cert pulled at `LAB_LEVEL=1` doesn't leak
hostnames that only exist at higher levels.

Because every vhost shares the **same** certificate, clients don't need per-vhost
certs or even working DNS to test a hostname — `curl -k --resolve
<hostname>:443:<IP> https://<hostname>/` (or real DNS, once configured) both work
identically for content routing.

**Fetching the CA** (so `curl`/browsers stop warning about self-signed certs):
```bash
curl -s http://<any-hostname-or-IP>/ca.crt -o soulsecure-ca.crt
curl --cacert soulsecure-ca.crt https://www.soulsecure.lab/
# or install system-wide (Debian/Kali):
sudo cp soulsecure-ca.crt /usr/local/share/ca-certificates/soulsecure-lab.crt
sudo update-ca-certificates
```

## Location

Everything lives at `/opt/soulsecure-labs/` on the target host (`tester`/`password`,
same VM as before). Key files:

```
/opt/soulsecure-labs/
├── labctl                 # control script -- start here
├── docker-compose.yml      # one stack, 10 services
├── detect-ip.sh            # writes .env (LAB_IP / LAB_CIDR) each time labctl runs
├── .env                     # generated, don't hand-edit
├── lab.level                # which level the appliance boots into (used by soulsecure-boot.service)
├── lab.override              # optional: pin LAB_IP manually
├── dns/                     # CoreDNS
├── nginx/                   # www: reverse-proxy gateway + all static/proxied vhosts + TLS
├── apps/                    # shared Flask base: api, storage, jenkins, vpn, osint, grafana
└── mail/, honeypot/         # standalone decoy/utility services
```

## `labctl` — the control script

```bash
cd /opt/soulsecure-labs

./labctl start 3      # bring the stack up with only Lab 1-3 content exposed
./labctl switch 5      # same thing, different name -- switch to full (all 5 labs)
./labctl status         # show current LAB_LEVEL + container status
./labctl stop           # docker compose down -- stop everything
./labctl logs www       # follow logs for one service
./labctl rebuild        # rebuild all images from source after editing files
```

Switching levels does **not** require rebuilding images — `LAB_LEVEL` is read at
container *start* time (each service's entrypoint/app code branches on it), so
`labctl switch <N>` just recreates containers with a new env var. Takes a few seconds.

## How `LAB_LEVEL` gating works

| Service | LAB_LEVEL 1 | +2 | +3 | +4 | +5 |
|---|---|---|---|---|---|
| `dns` (CoreDNS) | 7 Lab-1 records | + old-www, app CNAME, TXT, MX, CAA, SRV | — | — | — |
| `www` (gateway) | www, api, storage, vpn, backup-eu vhosts | + app/old-www/internal-tools/beta/legacy-portal vhosts | — | — | + origin-direct, search vhosts; robots.txt, security.txt, JS leak, Age/X-Cache headers on `www` |
| `api` | /, /health, /version, /status | — | + openapi.json, /api/v1/*, /api/v2/*, /api/internal/*, /graphql | — | + custom 404 handler |
| `storage` | fingerprint-only (`/` → 403) | — | — | + S3-style + GCS-style bucket registries | — |
| `osint` | RDAP, ASN, CT-log, shodan-search | — | — | — | + /dns-history |
| `jenkins`, `vpn`, `mail`, `grafana-decoy`, `honeypot` | always on | | | | |

TLS cert SAN list and the DNS zone both grow in lockstep with the nginx vhost gating
above, via the same `LAB_LEVEL` checks in their respective entrypoint scripts.

## One-time host requirement: `systemd-resolved` must be disabled

This VM's `systemd-resolved` binds `127.0.0.53:53`. Docker's wildcard (`0.0.0.0`) port
publish for the `dns` container's port 53 fails at the kernel level while that's
present. Already done on this VM via:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm -f /etc/resolv.conf
printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf
```

**If you deploy this stack to a fresh EC2 instance or another VM**, run these same
three commands once before `labctl start`, or the `dns` container will fail to start
with `address already in use` on port 53.

We deliberately chose **CoreDNS** over dnsmasq for the `dns` service specifically
because dnsmasq has an additional default restriction ("local-service") that refuses
queries from outside its own container subnet — exactly the queries this lab needs to
answer, since students query it from a separate attack box. CoreDNS has no such
restriction, and its zone-file format is standard BIND syntax.

## Dynamic IP

`detect-ip.sh` (called automatically by every `labctl start`/`switch`/`restart`) tries,
in order:
1. `/opt/soulsecure-labs/lab.override` if present (instructor-pinned IP)
2. AWS IMDSv2 public IP (works automatically on a real EC2 instance)
3. Falls back to the host's own primary local IP (`hostname -I`)

The result is written to `.env` as `LAB_IP`/`LAB_CIDR`. Nothing needs to change to
move this whole stack to a freshly-launched EC2 instance with a brand-new IP — just
make sure `systemd-resolved` is disabled there too, then `./labctl start 5`.

## Boot-time auto-start (`soulsecure-boot.service`)

A systemd oneshot service runs `labctl start $(cat /opt/soulsecure-labs/lab.level)`
on every boot, `After=docker.service network-online.target`. This is what makes the
OVA appliances (see [OVA-Exports/README.md](OVA-Exports/README.md)) fully
self-configuring on import — no SSH required after power-on, the appliance detects
its new IP and starts at its assigned level automatically every time.

```bash
echo 3 | sudo tee /opt/soulsecure-labs/lab.level   # change which level this appliance boots into
sudo systemctl restart soulsecure-boot              # apply immediately without a reboot
```

## Verifying a deployment

```bash
cd /opt/soulsecure-labs
./labctl status
curl -sk https://www.soulsecure.lab/ -o /dev/null -w '%{http_code}\n'
curl -s http://<LAB_IP>:9090/ | grep flag
```

Or re-run the full 20-flag smoke test used to validate this build.

## Troubleshooting: containers up, ports listening, but connections hang/time out

If `docker compose ps` looks healthy and `ss -tulpn` shows `docker-proxy` listening on
the right ports, but `curl` to those ports hangs or times out (even from the host
itself, even to `127.0.0.1`), check for a stuck Docker bridge/iptables state:

```bash
ss -tnp | grep :443   # look for connections stuck in SYN-SENT to a container's
                        # internal bridge IP (e.g. 172.18.0.x) -- that's the tell
```

This has happened after many rapid `docker compose up`/`down` cycles in one session
(iptables rules for the bridge network can get out of sync). Fix:

```bash
sudo docker compose down
sudo docker network prune -f
sudo systemctl restart docker
sudo /opt/soulsecure-labs/labctl start <level>
```
