# soulsecure-labs — source code

This is the actual Docker Compose stack behind the SoulSecure Inc. cloud-pentest
labs (Modules 2–6, all built and verified). Everything here is what's already
deployed and verified on the shared VM — this folder exists so the team can
`git clone` and run their **own** independent copy on their **own** VM, instead of
everyone sharing one box.

For the story/scenario/flags behind each lab, see the docs one level up
(`Module2-Reconnaissance-Enumeration/`, `Module3-Initial-Access-Storage-Exploitation/`,
`Module4-IAM-Exploitation-Privilege-Escalation/`,
`Module5-Post-Exploitation-Persistence-Lateral-Movement/`,
`Module6-Cloud-Pentesting-Tools-Hands-on-Labs/`). This README is only about running
the stack itself.

## Prerequisites

- A VM running **Ubuntu 22.04** (anything with Docker support works, but this is what
  it's built/tested against)
- Docker + Docker Compose v2 (`docker compose`, not the old standalone `docker-compose`)
- `systemd-resolved` **disabled** on the host — it binds `127.0.0.53:53`, which blocks
  Docker's wildcard `0.0.0.0:53` publish for the `dns` container at the kernel level:
  ```bash
  sudo systemctl disable --now systemd-resolved
  sudo rm -f /etc/resolv.conf
  printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' | sudo tee /etc/resolv.conf
  ```
  (`fix-resolv.sh` in this folder does the last two steps for you.)
- Python 3 with `venv` (`sudo apt-get install python3-venv`) — needed once, only if
  you'll run Module 6 (`labctl` bootstraps `module6/venv/` automatically on first use)
- **Module 6 only**, real third-party security tools — not part of this repo, install
  separately: `trufflehog`, `gitleaks`, `tfsec` (official install scripts/binary
  releases), `checkov`/`prowler`/`pacu` via **`pipx`** specifically, not plain `pip`
  (`sudo apt-get install pipx && pipx ensurepath`) — installing these three into a
  shared `pip install --user` environment breaks their dependencies against each
  other (confirmed: it broke `botocore` imports across all three). `aws` CLI v2 (the
  official installer, not the `apt` package — the `apt` v1 package conflicts with
  the newer `botocore` these tools pull in).

## Quickstart

```bash
git clone https://github.com/fatmeoww/soulsecure.git
cd soulsecure/soulsecure-labs
chmod +x labctl detect-ip.sh
./labctl start 5          # Module 2, all 5 labs (default/simplest starting point)
```

That builds every image (first run takes a few minutes) and brings up the whole
stack. `./labctl status` shows what's currently running.

## Picking what to run: `LAB_MODULE` + `LAB_LEVEL`

Two axes control what's exposed:
- **`LAB_MODULE`** — which course module (2 through 6)
- **`LAB_LEVEL`** — how many labs *within* that module are unlocked (1–5, cumulative
  — level 3 means "labs 1–3 unlocked", not "only lab 3")

Earlier modules **never disappear** once you move past them — same tenant, doesn't
reset. Module 3 at any level still has all of Module 2 live; Module 4 still has all
of Module 2 and 3 live; Module 5/6 still have everything before them live. This is
deliberate (see each Overview.md's "Architecture" section) — it's why some later
labs can reuse credentials your team found in an earlier module (e.g. Module 5 Lab 1
extends Module 4's `iam-sim` registry directly, and several Module 5 flags depend on
Module 3 Lab 5's jump-host key).

**Module 6 is architecturally different**, not just "more of the same": Labs 1–2 run
against a separate, parallel `localstack` container (real AWS API emulation — see
"Module 6" below), Labs 3–4 are pure static-file downloads with no live backend at
all, and Lab 5 (capstone) reuses the full Module 3–5 stack after a `labctl reset`.

```bash
./labctl start <1-5>              # Module 2 shorthand, e.g. ./labctl start 3
./labctl startm <module> <level>   # explicit form, e.g. ./labctl startm 4 5
./labctl switch <1-5>              # alias for start
./labctl switchm <module> <level>  # alias for startm
./labctl stop                      # docker compose down
./labctl status                    # show current MODULE/LEVEL + container status
./labctl logs <service>            # follow logs for one container
./labctl rebuild                   # rebuild all images from source after editing files
./labctl reset                     # clear all student-created state back to canonical seed
                                    # (MODULE/LEVEL unchanged; at MODULE=6 this also
                                    # reseeds localstack -- see "Module 6" below)
./labctl module6-seed              # re-run the LocalStack seed manually (idempotent,
                                    # no-op below MODULE=6)
```

Switching level/module does **not** require a manual rebuild step — `labctl` always
passes `--build` to `docker compose up`, so edited source files get picked up
automatically; switching without any edits is just a few seconds (cached layers).

Examples:
```bash
./labctl startm 2 1     # Module 2, Lab 1 only
./labctl startm 3 4     # Module 2 (full, cumulative) + Module 3 Labs 1-4
./labctl startm 4 5     # Module 2 (full) + Module 3 (full) + Module 4, all 5 labs
./labctl startm 5 5     # Everything through Module 5, all 5 labs
./labctl startm 6 5     # Everything: Modules 2-5 (full) + Module 6, all 5 labs
                         # (this also brings up + seeds localstack)
```

## What's running

`docker compose ps` after a full `startm 5 5` should show 17 containers; `startm 6 5`
adds `localstack` for 18. Almost everything is reverse-proxied through one nginx
gateway (`www`) on port 443 by hostname (TLS SNI + `Host` header) — the realistic
"one ingress, many backends" shape. A handful of things stay on their own dedicated
port on purpose (decoys, utilities, non-HTTP services, `localstack` itself on 4566)
— see each module's `Docker-Ops.md` / `Overview.md` for the full breakdown and *why*
each one is where it is.

**Module 5 safety note:** `docker-proxy` (Lab 3) is a pure in-memory *simulation* of
a Docker Engine API subset — it never touches this host's real
`/var/run/docker.sock`, is never privileged, has no bind mounts, and has no
published port. If you ever extend this lab, keep it that way; it's a hard
build requirement, not a nicety (see that lab's InstructorKey).

## Module 6

Labs 1–2 need a real AWS-API-compatible backend — Modules 3–5's hand-rolled Flask
mocks are explicitly not request-signing/response-shape compatible with genuine
tools (Prowler, Pacu, the real `aws` CLI). `docker-compose.yml`'s `localstack`
service (`localstack/localstack:3.0`, community edition, `SERVICES=s3,iam,sts`)
fills that gap. `labctl startm/switchm/restartm 6 <level>` and `labctl reset` all
call `module6/seed_localstack.py` automatically (bootstrapping its own venv on
first use, see Prerequisites) — you shouldn't need to run it by hand, but
`./labctl module6-seed` is there if you do.

Point `aws`/Prowler/Pacu at `http://<VM_IP>:4566` (test credentials: access key
`test`, secret `test`, region `us-east-1`) — see each Module 6 lab's InstructorKey
for exact invocation commands and known tool-version quirks (several real tools
don't behave the way their own `--help` output might suggest; each key's "Bugs
found and fixed" section documents what was actually verified working).

Labs 3–4 are plain static files served for download at `https://module6.soulsecure.lab/`
once `LAB_MODULE=6` — no credentials, no live backend, just `curl`/`tar`.

**Target domain:** everything is served as `*.soulsecure.lab`. Point your attack
box's DNS at the VM's IP (`sudo bash -c 'echo "nameserver <VM_IP>" > /etc/resolv.conf'`)
or use `curl --resolve <hostname>:443:<VM_IP>` per-request without touching DNS at all.

**TLS:** self-signed CA + server cert, both 100-year validity, regenerated fresh on
every `www` container start (cheap, ~1s) so it always matches whichever vhosts are
currently active. Fetch and trust it once:
```bash
curl -sk https://<VM_IP>/ca.crt -o soulsecure-ca.crt
sudo cp soulsecure-ca.crt /usr/local/share/ca-certificates/soulsecure-lab.crt
sudo update-ca-certificates
```

## Dynamic IP — don't hand-edit `.env`

`detect-ip.sh` (called automatically by every `labctl` command) figures out the
VM's current IP itself — tries an override file (`lab.override`, if you want to pin
one manually), then AWS IMDSv2 (works automatically if this ever runs on EC2), then
falls back to the host's own primary local IP. Writes the result to `.env` as
`LAB_IP`/`LAB_CIDR`, which `docker-compose.yml` reads for every service that needs
it (**every service that displays the IP back to the student must receive `LAB_IP`
in its `environment:` block** — a service that's missing it will silently fall back
to a stale hardcoded default instead of erroring, which is a real bug we hit and
fixed once already; if you add a new service that needs to know the VM's IP, don't
forget this).

Never edit `.env` directly — it gets regenerated (and your edits wiped) on the next
`labctl` invocation.

## Auto-start on boot (optional, mainly for OVA-style appliances)

`soulsecure-boot.service` is a systemd unit that runs `labctl startm $(cat
lab.module) $(cat lab.level)` on every boot. Not required for local dev — only
install it if you want the stack to come up automatically without logging in:
```bash
sudo cp soulsecure-boot.service /etc/systemd/system/
echo 2 | sudo tee /opt/soulsecure-labs/lab.module   # only if installed at /opt/soulsecure-labs
echo 5 | sudo tee /opt/soulsecure-labs/lab.level
sudo systemctl enable --now soulsecure-boot
```

## Troubleshooting

**Containers up, ports listening, but connections hang/time out** — usually a stuck
Docker bridge/iptables state after many rapid `up`/`down` cycles:
```bash
docker compose down --remove-orphans
docker container prune -f
docker network prune -f
sudo systemctl restart docker
./labctl start <level>    # or startm <module> <level>
```

**`dns` container fails with `address already in use` on port 53`** — `systemd-resolved`
is still running; see Prerequisites above.

**Recon Toolkit GUI (port 9091) shows the wrong/stale IP in its example `curl`
commands** — check that the `osint` service in `docker-compose.yml` has `LAB_IP` in
its `environment:` block. This exact bug happened once (see commit history) and is
easy to reintroduce if `docker-compose.yml` is edited carelessly.

## Credentials

SSH into wherever you deploy this: `tester` / `password` (lab-only, not
internet-facing — never reuse this password anywhere real). Same convention used
throughout every lab's own login flows (VPN portal, backup portal, etc.) — see each
lab's InstructorKey for the specific values.
