# SoulSecure Labs — Cloud Pentest Course

Hands-on labs for a Cloud Pentest training course, built around one continuous
fictional engagement against **SoulSecure Inc.** (`soulsecure.lab`). Six modules,
each with several labs; findings and credentials from earlier labs deliberately pay
off in later ones — work them in order.

## ✅ `main` now has real, runnable source code

As of this update, **`main` includes `soulsecure-labs/`** — the actual Docker
Compose stack, Dockerfiles, and app source, not just docs. Module 2 and Module 4 are
officially documented as built-and-verified here; see the status table below for
what that source actually supports beyond those two (more than the docs currently
advertise — see the note there).

```bash
git clone https://github.com/fatmeoww/soulsecure.git
cd soulsecure/soulsecure-labs
chmod +x labctl detect-ip.sh
./labctl startm 4 5      # Module 2 (full) + Module 4, all 5 labs
```

Full run instructions: [soulsecure-labs/README.md](soulsecure-labs/README.md).

## ⚠️ Read this before you try to "run" anything

Cloning this repo gets you the source, but not a running lab by itself — you still
need a Linux VM with Docker to run `soulsecure-labs/` on (your own, or a shared one
your team already has up). What actually gets you a runnable lab is one of the two
paths in [Module 2](#module-2--reconnaissance--enumeration-built--runnable) below —
Module 4 works the same way, just point `labctl` at `startm 4 <level>` instead.

## Repo structure

```
Module2-Reconnaissance-Enumeration/
├── Overview.md              # module summary, asset map
├── Docker-Ops.md             # labctl commands, deployment architecture
├── Flags-สรุปทั้งหมด.md        # master answer key (Thai)
├── คู่มือเล่นแลป-TH.md          # full Thai playthrough
├── Lab1-CloudAssetDiscovery/
│   ├── StudentGuide.md       # what students read
│   ├── InstructorKey.md      # ground truth, flags, grading rubric
│   └── Walkthrough-TH.md
├── Lab2-DNS-VHost-Enumeration/
├── Lab3-API-Reconnaissance/
├── Lab4-Object-Storage-Enumeration/
└── Lab5-CDN-Origin-Tech-Fingerprinting/

Module3-Initial-Access-Storage-Exploitation/
├── Overview.md
├── Build-Spec.md              # implementation checklist (not yet built)
└── Lab1-Object-Storage-Exploitation/ ... Lab5-VPN-Gateway-Exploitation/

Module4-IAM-Exploitation-Privilege-Escalation/     (same pattern)
Module5-Post-Exploitation-Persistence-Lateral-Movement/  (same pattern)
Module6-Cloud-Pentesting-Tools-Hands-on-Labs/      (same pattern)

OVA-Exports/README.md          # import instructions (the .ova files themselves
                                 are NOT in this repo -- see below)
```

Every lab folder has the same two core files: **StudentGuide.md** (what you actually
work through) and **InstructorKey.md** (answers, flags, grading — don't read this
first if you want to actually try the lab).

## Module status (on `main`)

| Module | Status on `main` | Runnable from `main` today? |
|---|---|---|
| 2 — Reconnaissance & Enumeration | ✅ Built, 5 labs, 20 flags | **Yes** — see below |
| 3 — Initial Access & Storage Exploitation | 📝 Docs only (StudentGuide + InstructorKey + Build-Spec, 5 labs) — **not officially merged yet, though see note** | Not officially — see note |
| 4 — IAM Exploitation & Privilege Escalation | ✅ Built, verified, merged — 5 labs, 20 flags, includes Thai walkthroughs | **Yes** — `./labctl startm 4 5` |
| 5 — Post-Exploitation, Persistence & Lateral Movement | 📝 Docs only on `main` — **not officially merged yet, though see note** | Not officially — see note |
| 6 — Cloud Pentesting Tools & Hands-on Labs | 📝 Fully drafted | No — not built anywhere yet |

**Note on Modules 3 and 5:** their actual source (`config-service`, `imds-sim`,
`bastion`, `docker-proxy`, `backup-admin`, etc.) came along as part of
`soulsecure-labs/` in this merge, since it's one shared Docker Compose stack with
Module 4 — so `./labctl startm 5 5` will, in practice, already work. Their course
docs on `main` haven't been updated to "built and verified" yet on purpose (that's a
separate merge, deliberately deferred) — treat Module 3/5 as **unofficially present,
not yet course-endorsed**: the containers exist and were verified on the branch they
came from, but this repo isn't vouching for their docs/status here yet. Module 4's
docs and merge were reviewed together and are fully official.

Module 4's spec held up well in practice — only one small bug turned up during
verification (a permission-check action-name mismatch in Lab 2, already fixed) and
it was independently re-verified live, multiple times, after this merge.

---

## Module 2 — Reconnaissance & Enumeration (built, runnable)

You need access to a **running VM** with the lab stack up. Two ways to get one:

### Path A — Import a standalone OVA (easiest, no shared VM needed)

Each of the 5 labs has its own self-contained VMware appliance (cumulative — the
"Lab 3" OVA includes Labs 1–3's content, etc.). **The `.ova` files themselves are
not in this git repo** (~4.5GB each, far past GitHub's file-size limit) — get them
from whoever has [OVA-Exports/](OVA-Exports/) (shared drive / direct transfer), then:

```
1. Import the .ova into VMware Workstation/Player/Fusion (File → Open) or ESXi.
2. Power it on -- no setup needed, it self-configures its IP and boot-time lab level.
3. Note the VM's IP (your hypervisor's network info, or SSH in and `cat /opt/soulsecure-labs/.env`).
```

Full detail: [OVA-Exports/README.md](OVA-Exports/README.md).

### Path B — SSH into a shared/persistent VM and drive it with `labctl`

If your team runs one long-lived VM instead of per-person OVAs:

```bash
ssh tester@<VM_IP>          # password: password
cd /opt/soulsecure-labs

./labctl status              # see current LAB_LEVEL + container health
./labctl start 5             # bring up the full stack (all 5 labs' content)
./labctl start 3             # or just Labs 1-3, if you want a narrower state
./labctl switch 5            # same as start, different name -- change level without downtime
./labctl stop                # docker compose down
./labctl logs www            # tail one service's logs
./labctl rebuild             # rebuild images after editing app source on the VM
```

Full detail, including one-time host setup (`systemd-resolved` must be disabled
before first run) and the TLS/DNS architecture:
[Module2-Reconnaissance-Enumeration/Docker-Ops.md](Module2-Reconnaissance-Enumeration/Docker-Ops.md).

### Once you have a `<TARGET_IP>` (either path)

Every lab assumes you've done this **one-time setup** first (full detail in
[Lab 1's StudentGuide](Module2-Reconnaissance-Enumeration/Lab1-CloudAssetDiscovery/StudentGuide.md), Section 0):

```bash
# 1. Point your resolver at the target so *.soulsecure.lab resolves
sudo bash -c 'echo "nameserver <TARGET_IP>" > /etc/resolv.conf'

# 2. Fetch and trust the lab's CA (served in cleartext specifically for this)
curl -s http://www.soulsecure.lab/ca.crt -o soulsecure-ca.crt
curl --cacert soulsecure-ca.crt https://www.soulsecure.lab/
# (or curl -k everywhere if you don't want to bother trusting it)
```

Then just open each lab's `StudentGuide.md` in order and work through it —
[Lab1-CloudAssetDiscovery](Module2-Reconnaissance-Enumeration/Lab1-CloudAssetDiscovery/StudentGuide.md) →
[Lab2-DNS-VHost-Enumeration](Module2-Reconnaissance-Enumeration/Lab2-DNS-VHost-Enumeration/StudentGuide.md) →
[Lab3-API-Reconnaissance](Module2-Reconnaissance-Enumeration/Lab3-API-Reconnaissance/StudentGuide.md) →
[Lab4-Object-Storage-Enumeration](Module2-Reconnaissance-Enumeration/Lab4-Object-Storage-Enumeration/StudentGuide.md) →
[Lab5-CDN-Origin-Tech-Fingerprinting](Module2-Reconnaissance-Enumeration/Lab5-CDN-Origin-Tech-Fingerprinting/StudentGuide.md).
Instructors: use each lab's `InstructorKey.md` to grade, or
[Flags-สรุปทั้งหมด.md](Module2-Reconnaissance-Enumeration/Flags-สรุปทั้งหมด.md) for the full answer key at a glance.

**Apple Silicon (M1/M2) note:** run the VM as native Ubuntu **arm64**, not through
Docker Desktop's x86 translation layer — every image this stack currently documents
(nginx, CoreDNS, Python/Flask) is multi-arch, so this should work unmodified. Not
independently verified on arm64 yet — if you hit an image that turns out to be
amd64-only, that's worth reporting back so it gets fixed before wider team rollout.

---

## Module 4 — IAM Exploitation & Privilege Escalation (built, runnable)

Same access model as Module 2 (OVA or shared VM + `labctl`, one-time DNS/CA setup —
see above). Once you have a `<TARGET_IP>`:

```bash
./labctl startm 4 5     # Module 2 (full) + Module 4, all 5 labs
```

Then work through [Lab1-Credential-Enumeration](Module4-IAM-Exploitation-Privilege-Escalation/Lab1-Credential-Enumeration/StudentGuide.md) →
[Lab2-Policy-Misconfiguration-Hunting](Module4-IAM-Exploitation-Privilege-Escalation/Lab2-Policy-Misconfiguration-Hunting/StudentGuide.md) →
[Lab3-Privilege-Escalation-IAM](Module4-IAM-Exploitation-Privilege-Escalation/Lab3-Privilege-Escalation-IAM/StudentGuide.md) →
[Lab4-Cross-Account-Role-Assumption](Module4-IAM-Exploitation-Privilege-Escalation/Lab4-Cross-Account-Role-Assumption/StudentGuide.md) →
[Lab5-Secrets-Manager-Exploitation](Module4-IAM-Exploitation-Privilege-Escalation/Lab5-Secrets-Manager-Exploitation/StudentGuide.md).
Each lab folder also has a `Walkthrough-TH.md`. Module 4 depends on credentials
harvested in Module 3 (Lab 1 re-derives them inline if you don't have Module 3's own
docs open) — the environment doesn't reset between modules, so this works even
though Module 3's docs aren't officially merged yet.

## Modules 3, 5, 6 — docs not merged yet

Module 3 and 5's **source code** already exists in `soulsecure-labs/` (see the note
in the status table above) — their **docs** on `main` are still the pre-build
planning versions, not yet reviewed/merged as "built and verified." Module 6 has
neither docs-merge nor is it built anywhere on `main`'s source yet.

If you want to see what's coming (or preview Module 3/5 ahead of their official
docs-merge — the containers already work), start with each module's `Overview.md`:
[Module 3](Module3-Initial-Access-Storage-Exploitation/Overview.md) ·
[Module 5](Module5-Post-Exploitation-Persistence-Lateral-Movement/Overview.md) ·
[Module 6](Module6-Cloud-Pentesting-Tools-Hands-on-Labs/Overview.md).

---

## Contributing / updating this repo

- Keep the `StudentGuide.md` / `InstructorKey.md` / (`Walkthrough-TH.md`) naming
  convention per lab folder — it's what every cross-reference in this repo expects.
- Never commit `.ova` files (GitHub's 100MB/file limit; these run 4.5GB+) — already
  excluded via `.gitignore`.
- When Module 3/5's docs get officially reviewed and merged (source is already
  here), or Module 6 gets built, update that module's `Overview.md` status banner
  and this README's status table together, same as Module 2 and 4 already reflect.
