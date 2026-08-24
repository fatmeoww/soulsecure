# SoulSecure Labs — Cloud Pentest Course

Hands-on labs for a Cloud Pentest training course, built around one continuous
fictional engagement against **SoulSecure Inc.** (`soulsecure.lab`). Six modules,
each with several labs; findings and credentials from earlier labs deliberately pay
off in later ones — work them in order.

## ✅ This repo has real, runnable source code

**This branch includes `soulsecure-labs/`** — the actual Docker Compose stack,
Dockerfiles, and app source for **all six modules**, not just docs. Modules 2–6 are
all built and verified on the shared VM.

```bash
git clone https://github.com/fatmeoww/soulsecure.git
cd soulsecure/soulsecure-labs
chmod +x labctl detect-ip.sh
./labctl startm 6 5      # everything: Modules 2-5 (full) + Module 6, all 5 labs
```

Full run instructions: [soulsecure-labs/README.md](soulsecure-labs/README.md).

## ⚠️ Read this before you try to "run" anything

Cloning this repo gets you the source, but not a running lab by itself — you still
need a Linux VM with Docker to run `soulsecure-labs/` on (your own, or a shared one
your team already has up, or one of the standalone [OVA-Exports/](OVA-Exports/)
appliances). What actually gets you a runnable lab is one of the two paths in
[Module 2](#module-2--reconnaissance--enumeration-built--runnable) below — every
later module works the same way, just point `labctl` at `startm <module> <level>`
instead.

> **Note on `main` vs. this branch:** as of this writing, `main` only has Module 2
> and Module 4 officially merged (see its own README) — Modules 3, 5, and 6 (and the
> Module 6 Lab 5 completion flag) exist here on `module3-4-build-docs-update` and
> haven't been merged yet. If you're reading this on `main`, the status table below
> won't match; check which branch you're actually on.

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
├── Build-Spec.md              # implementation checklist, ground truth per lab's InstructorKey
└── Lab1-Object-Storage-Exploitation/ ... Lab5-VPN-Gateway-Exploitation/

Module4-IAM-Exploitation-Privilege-Escalation/     (same pattern)
Module5-Post-Exploitation-Persistence-Lateral-Movement/  (same pattern)
Module6-Cloud-Pentesting-Tools-Hands-on-Labs/      (same pattern)

soulsecure-labs/                # the actual source: Dockerfiles, docker-compose.yml,
                                 # app code -- see soulsecure-labs/README.md to run it

OVA-Exports/README.md          # import instructions (the .ova files themselves
                                 are NOT in this repo -- see below)
```

**Docs status per module — only Module 2 has its own `Docker-Ops.md` written so
far** (Modules 3–6 are built and their `labctl startm <module> <level>` commands
work identically — see [soulsecure-labs/README.md](soulsecure-labs/README.md) for
the module-agnostic version of that doc — but each module's own dedicated
`Docker-Ops.md` is still on the to-write list).

Every lab folder has the same two core files: **StudentGuide.md** (what you actually
work through) and **InstructorKey.md** (answers, flags, grading — don't read this
first if you want to actually try the lab).

## Module status

| Module | Status | Runnable today? |
|---|---|---|
| 2 — Reconnaissance & Enumeration | ✅ Built & verified, 5 labs, 20 flags | **Yes** — see below, and merged to `main` |
| 3 — Initial Access & Storage Exploitation | ✅ Built & verified, 5 labs, 20 flags | **Yes**, `startm 3 <level>` — on this branch only |
| 4 — IAM Exploitation & Privilege Escalation | ✅ Built & verified, 5 labs, 20 flags | **Yes**, `startm 4 <level>` — merged to `main` |
| 5 — Post-Exploitation, Persistence & Lateral Movement | ✅ Built & verified, 5 labs, 20 flags | **Yes**, `startm 5 <level>` — on this branch only |
| 6 — Cloud Pentesting Tools & Hands-on Labs | ✅ Built & verified, 5 labs, 17 flags + 1 rubric-graded report | **Yes**, `startm 6 <level>` — on this branch only |

All six modules are built, source-complete, and live-verified end to end on the
shared VM, with a standalone per-lab OVA appliance exported for every one of the 25
labs (see [OVA-Exports/README.md](OVA-Exports/README.md)). "On this branch only"
above means the docs+source exist here on `module3-4-build-docs-update` but haven't
been merged into `main` yet — see the branch note above.

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

## Modules 3–6 — built and runnable (on this branch)

All four are fully built and live-verified against the shared VM, the same way
Module 2 and 4 are — same `soulsecure-labs/` stack, same `labctl startm <module>
<level>` pattern, same StudentGuide → InstructorKey → (Thai walkthrough) structure
per lab. Module 6 is architecturally different from the rest (three infrastructure
patterns — LocalStack, static files, and a full-stack capstone reset — instead of
one uniform mock pattern); see its own `Overview.md`/`Build-Spec.md` for why.

Run any of them exactly like Module 2, just swap the module number:
```bash
./labctl startm 3 5      # Module 2 (full) + Module 3, all 5 labs
./labctl startm 4 5      # + Module 4, all 5 labs
./labctl startm 5 5      # + Module 5, all 5 labs
./labctl startm 6 5      # + Module 6, all 5 labs (Lab 5 = capstone, needs `labctl reset` first for a clean run)
```
See each module's `Overview.md` for the story/scenario and `Build-Spec.md` for the
consolidated flag index: [Module 3](Module3-Initial-Access-Storage-Exploitation/Overview.md) ·
[Module 4](Module4-IAM-Exploitation-Privilege-Escalation/Overview.md) ·
[Module 5](Module5-Post-Exploitation-Persistence-Lateral-Movement/Overview.md) ·
[Module 6](Module6-Cloud-Pentesting-Tools-Hands-on-Labs/Overview.md).

**Still open / not yet done, tracked honestly rather than swept under the status
table above:**
- `Module3-Docker-Ops.md`, `Module4-Docker-Ops.md`, `Module5-Docker-Ops.md`,
  `Module6-Docker-Ops.md` — none written yet; only Module 2 has its own (the
  `labctl` commands work identically for every module in the meantime, see
  [soulsecure-labs/README.md](soulsecure-labs/README.md))
- `Module6-Lab5-Report-Template.md` — a starter document for the capstone report
  deliverable, referenced by that lab's StudentGuide but not yet built
- A dedicated "plant a full Module 5 attack chain's worth of state, `labctl reset`,
  verify every individual artifact is gone" pass — the reset mechanism itself is
  verified sound (see Module 6's Build-Spec), but this specific stronger test
  hasn't been run yet

---

## Contributing / updating this repo

- Keep the `StudentGuide.md` / `InstructorKey.md` / (`Walkthrough-TH.md`) naming
  convention per lab folder — it's what every cross-reference in this repo expects.
- Never commit `.ova` files (GitHub's 100MB/file limit; these run 4.5GB+) — already
  excluded via `.gitignore`.
- When a module's status changes (built, merged to `main`, etc.), update its
  `Overview.md`/`Build-Spec.md` status banner and this README's status table
  together — don't let one drift from the other, it already happened once.
