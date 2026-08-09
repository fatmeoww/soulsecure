# SoulSecure Labs — Cloud Pentest Course

Hands-on labs for a Cloud Pentest training course, built around one continuous
fictional engagement against **SoulSecure Inc.** (`soulsecure.lab`). Six modules,
each with several labs; findings and credentials from earlier labs deliberately pay
off in later ones — work them in order.

## ⚠️ Read this before you try to "run" anything

**This repository is documentation, not infrastructure-as-code.** It contains every
lab's StudentGuide/InstructorKey/build-spec — it does **not** contain the actual
Dockerfiles, `docker-compose.yml`, or application source that make the labs work.
That source lives on a separate target VM (`/opt/soulsecure-labs/` — see each
module's `Docker-Ops.md`/`Build-Spec.md`). Cloning this repo alone will not spin
anything up. What actually gets you a runnable lab is one of the two paths in
[Module 2](#module-2--reconnaissance--enumeration-built--runnable) below.

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

## Module status

| Module | Status | Runnable today? |
|---|---|---|
| 2 — Reconnaissance & Enumeration | ✅ Built, 5 labs, 20 flags | **Yes** — see below |
| 3 — Initial Access & Storage Exploitation | 📝 Fully drafted (StudentGuide + InstructorKey + Build-Spec, 5 labs) | No — not yet deployed to any VM |
| 4 — IAM Exploitation & Privilege Escalation | 📝 Fully drafted | No |
| 5 — Post-Exploitation, Persistence & Lateral Movement | 📝 Fully drafted | No |
| 6 — Cloud Pentesting Tools & Hands-on Labs | 📝 Fully drafted | No |

Modules 3–6 are ready to build against once Module 2 finishes internal testing.
Each one's `Build-Spec.md` is the implementation checklist for whoever stands it up.

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

## Modules 3–6 — not deployable yet

These four modules are fully **planned and drafted** — every lab has a complete
StudentGuide and InstructorKey, and every module has a `Build-Spec.md` with the
exact containers/routes/credentials someone needs to implement. What's missing is
the actual build: no Dockerfiles, no app code, no VM. There is currently no command
that brings any of Module 3–6 up, on this VM or any other.

If you want to see what's coming, start with each module's `Overview.md`:
[Module 3](Module3-Initial-Access-Storage-Exploitation/Overview.md) ·
[Module 4](Module4-IAM-Exploitation-Privilege-Escalation/Overview.md) ·
[Module 5](Module5-Post-Exploitation-Persistence-Lateral-Movement/Overview.md) ·
[Module 6](Module6-Cloud-Pentesting-Tools-Hands-on-Labs/Overview.md).

---

## Contributing / updating this repo

- Keep the `StudentGuide.md` / `InstructorKey.md` / (`Walkthrough-TH.md`) naming
  convention per lab folder — it's what every cross-reference in this repo expects.
- Never commit `.ova` files (GitHub's 100MB/file limit; these run 4.5GB+) — already
  excluded via `.gitignore`.
- When Module 3 (or later) actually gets built, update its `Overview.md` status
  banner and this README's status table together, same as Module 2 already reflects.
