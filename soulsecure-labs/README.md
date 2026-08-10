# soulsecure-labs — source code

This is the actual Docker Compose stack behind the SoulSecure Inc. cloud-pentest
labs (Modules 2–4 so far). Everything here is what's already deployed and verified
on the shared VM — this folder exists so the team can `git clone` and run their
**own** independent copy on their **own** VM, instead of everyone sharing one box.

For the story/scenario/flags behind each lab, see the docs one level up
(`Module2-Reconnaissance-Enumeration/`, `Module3-Initial-Access-Storage-Exploitation/`,
`Module4-IAM-Exploitation-Privilege-Escalation/`). This README is only about running
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
- **`LAB_MODULE`** — which course module (2, 3, or 4 so far)
- **`LAB_LEVEL`** — how many labs *within* that module are unlocked (1–5, cumulative
  — level 3 means "labs 1–3 unlocked", not "only lab 3")

Earlier modules **never disappear** once you move past them — same tenant, doesn't
reset. Module 3 at any level still has all of Module 2 live; Module 4 still has all
of Module 2 and 3 live. This is deliberate (see each Overview.md's "Architecture"
section) — it's why some of Module 4's labs can reuse credentials your team found
back in Module 3.

```bash
./labctl start <1-5>              # Module 2 shorthand, e.g. ./labctl start 3
./labctl startm <module> <level>   # explicit form, e.g. ./labctl startm 4 5
./labctl switch <1-5>              # alias for start
./labctl switchm <module> <level>  # alias for startm
./labctl stop                      # docker compose down
./labctl status                    # show current MODULE/LEVEL + container status
./labctl logs <service>            # follow logs for one container
./labctl rebuild                   # rebuild all images from source after editing files
```

Switching level/module does **not** require a manual rebuild step — `labctl` always
passes `--build` to `docker compose up`, so edited source files get picked up
automatically; switching without any edits is just a few seconds (cached layers).

Examples:
```bash
./labctl startm 2 1     # Module 2, Lab 1 only
./labctl startm 3 4     # Module 2 (full, cumulative) + Module 3 Labs 1-4
./labctl startm 4 5     # Module 2 (full) + Module 3 (full) + Module 4, all 5 labs
```

## What's running

`docker compose ps` after a full `startm 4 5` should show 13 containers. Almost
everything is reverse-proxied through one nginx gateway (`www`) on port 443 by
hostname (TLS SNI + `Host` header) — the realistic "one ingress, many backends"
shape. A handful of things stay on their own dedicated port on purpose (decoys,
utilities, non-HTTP services) — see each module's `Docker-Ops.md` /
`Overview.md` for the full breakdown and *why* each one is where it is.

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
