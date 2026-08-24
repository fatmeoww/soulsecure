# OVA Exports

25 standalone VMware appliance files — one per lab, across Modules 2–6 — exported
from the same master VM (`Ubuntu 22 - labs master claude`) at a different
`LAB_MODULE`/`LAB_LEVEL` combination each time. Every file is genuinely
self-contained and independent: there is no cross-file dependency, and importing
one has no effect on any other.

**The `.ova` files themselves are not in this git repo** (each one is several GB,
far past GitHub's file-size limit) — get them from whoever has this folder (shared
drive / direct transfer). This README documents what exists and how to use it.

## Full file index

| File | Size | Contains |
|---|---|---|
| `SoulSecure-Lab-Module2-Lab1.ova` | ~4.41 GB | Module 2, Lab 1 only |
| `SoulSecure-Lab-Module2-Lab2.ova` | ~4.41 GB | Module 2, Labs 1–2 |
| `SoulSecure-Lab-Module2-Lab3.ova` | ~4.41 GB | Module 2, Labs 1–3 |
| `SoulSecure-Lab-Module2-Lab4.ova` | ~4.41 GB | Module 2, Labs 1–4 |
| `SoulSecure-Lab-Module2-Lab5.ova` | ~4.40 GB | Module 2, Labs 1–5 (full) |
| `SoulSecure-Lab-Module3-Lab1.ova` | ~7.35 GB | Module 2 (full) + Module 3, Lab 1 |
| `SoulSecure-Lab-Module3-Lab2.ova` | ~7.40 GB | Module 2 (full) + Module 3, Labs 1–2 |
| `SoulSecure-Lab-Module3-Lab3.ova` | ~7.40 GB | Module 2 (full) + Module 3, Labs 1–3 |
| `SoulSecure-Lab-Module3-Lab4.ova` | ~7.39 GB | Module 2 (full) + Module 3, Labs 1–4 |
| `SoulSecure-Lab-Module3-Lab5.ova` | ~7.38 GB | Module 2 (full) + Module 3, Labs 1–5 (full) |
| `SoulSecure-Lab-Module4-Lab1.ova` | ~7.39 GB | Modules 2–3 (full) + Module 4, Lab 1 |
| `SoulSecure-Lab-Module4-Lab2.ova` | ~7.38 GB | Modules 2–3 (full) + Module 4, Labs 1–2 |
| `SoulSecure-Lab-Module4-Lab3.ova` | ~7.37 GB | Modules 2–3 (full) + Module 4, Labs 1–3 |
| `SoulSecure-Lab-Module4-Lab4.ova` | ~7.36 GB | Modules 2–3 (full) + Module 4, Labs 1–4 |
| `SoulSecure-Lab-Module4-Lab5.ova` | ~7.36 GB | Modules 2–3 (full) + Module 4, Labs 1–5 (full) |
| `SoulSecure-Lab-Module5-Lab1.ova` | ~7.37 GB | Modules 2–4 (full) + Module 5, Lab 1 |
| `SoulSecure-Lab-Module5-Lab2.ova` | ~7.37 GB | Modules 2–4 (full) + Module 5, Labs 1–2 |
| `SoulSecure-Lab-Module5-Lab3.ova` | ~7.37 GB | Modules 2–4 (full) + Module 5, Labs 1–3 |
| `SoulSecure-Lab-Module5-Lab4.ova` | ~7.36 GB | Modules 2–4 (full) + Module 5, Labs 1–4 |
| `SoulSecure-Lab-Module5-Lab5.ova` | ~7.35 GB | Modules 2–4 (full) + Module 5, Labs 1–5 (full) |
| `SoulSecure-Lab-Module6-Lab1.ova` | ~7.39 GB | Modules 2–5 (full) + Module 6, Lab 1 (LocalStack posture assessment) |
| `SoulSecure-Lab-Module6-Lab2.ova` | ~7.38 GB | Modules 2–5 (full) + Module 6, Labs 1–2 (+ Pacu exploitation-framework target) |
| `SoulSecure-Lab-Module6-Lab3.ova` | ~7.38 GB | Modules 2–5 (full) + Module 6, Labs 1–3 (+ secret-scanning file dump) |
| `SoulSecure-Lab-Module6-Lab4.ova` | ~7.61 GB | Modules 2–5 (full) + Module 6, Labs 1–4 (+ Terraform IaC source tree) |
| `SoulSecure-Lab-Module6-Lab5.ova` | ~7.83 GB | Modules 2–5 (full) + Module 6, Labs 1–5 (full) — the capstone, freshly `labctl reset` before export |

## Why the sizes are all cumulative, not per-lab

Every module's labs build on shared infrastructure from earlier labs and earlier
modules (same DNS zone, same nginx gateway, same `iam-sim`/`api`/`storage`
services — see each module's `Docker-Ops.md`/`Build-Spec.md` for how the two-axis
`LAB_MODULE`+`LAB_LEVEL` gating works). So "Module 4, Lab 3" here means "everything
through Module 3 fully unlocked, plus Module 4 Labs 1–3 content, Labs 4–5 hidden" —
matching exactly what a student would see if they'd worked the course in order up
through that point. This was a deliberate tradeoff over building isolated
environments per lab (see [Module2-Docker-Ops.md](../Module2-Reconnaissance-Enumeration/Docker-Ops.md)
for the original reasoning; it carried forward unchanged for every later module).

**Module 6 Lab 5 (capstone) is the one exception to strict incrementality**: instead
of just adding Lab 5 content on top of Lab 4's state, the whole stack was run
through `labctl reset` immediately before export — clearing every backdoor/state a
prior lab run might have planted (IAM backdoors, Jenkins jobs, VPN certs, etc.) so
the capstone starts from a genuinely clean slate, per that lab's design (see
[Lab5-Capstone-Full-Chain/InstructorKey.md](../Module6-Cloud-Pentesting-Tools-Hands-on-Labs/Lab5-Capstone-Full-Chain/InstructorKey.md)).
It still includes the one completion flag (`POST /capstone/submit-report`,
`flag{436297b00829b4b4c7df7a325adede2e}` on genuine admin-equivalent access) — live
end-to-end verified before this export: SSRF/IMDS → `soulsecure-deploy-role` creds
→ PassRole escalation → admin creds → `403`/`400`/`200` all confirmed exactly as
documented in that lab's InstructorKey.

## Importing and using an OVA

1. Import into VMware Workstation/Player/Fusion, or ESXi (File → Open, or
   `ovftool <file>.ova <destination>`).
2. **Rename the VM** after import if you want — it currently shows up as
   `Ubuntu 22 - labs master claude` in your hypervisor's VM list regardless of which
   lab file you imported (a cosmetic leftover from the shared master source; the OVA
   *filename* is still correct, only the internal display name isn't lab-specific).
3. Power it on. No setup needed — a boot-time service (`soulsecure-boot.service`)
   automatically:
   - Detects the VM's current IP (works whether it lands on a NAT'd private IP, a
     different VMware host, or gets imported straight to a cloud instance)
   - Starts exactly the module+level baked into that OVA
     (`/opt/soulsecure-labs/lab.module` + `lab.level`), including re-seeding
     LocalStack for any Module 6 Lab 1–5 file (its state is in-memory only,
     `PERSISTENCE=0`, so this has to happen on every boot — the boot service
     handles it automatically via the same `labctl startm` path used for manual
     level switches)
   - No manual `labctl` invocation required — though it's still there if you want to
     switch levels later (`ssh tester@<ip>`, then see the relevant module's
     `Docker-Ops.md` — currently only written for
     [Module 2](../Module2-Reconnaissance-Enumeration/Docker-Ops.md); Modules 3–6
     don't have their own yet, `labctl startm <module> <level>` works the same way
     regardless)
4. Give students the VM's IP (shown by `cat /opt/soulsecure-labs/.env` over SSH, or
   just check your hypervisor's network info) — that's the `<TARGET_IP>` referenced
   throughout each lab's StudentGuide.

**Credentials:** `tester` / `password` (SSH). Same lab-only credential used
throughout — not internet-facing, isolated training network only.

## Regenerating these OVAs later

If lab content changes, the affected module's whole per-lab export cycle needs to
be repeated (there's no patch/diff mechanism for OVAs). Process used to build all
25 files above:

```
for level in 1 2 3 4 5:
    ssh tester@<vm-ip>
    echo <module> | sudo tee /opt/soulsecure-labs/lab.module
    echo <level>  | sudo tee /opt/soulsecure-labs/lab.level
    cd /opt/soulsecure-labs && sudo ./labctl startm <module> <level>   # verify it's correct
    # (Module 6 Lab 5 only: sudo ./labctl reset first, for a clean capstone state)
    sudo shutdown -h now
    (wait for the VM to fully power off -- vmrun.exe list)
    ovftool.exe --overwrite "<vmx path>" "SoulSecure-Lab-Module<module>-Lab<level>.ova"
    vmrun.exe start "<vmx path>" nogui               # power back on for next level
    # restore the shared VM's own default state afterward: module=5 level=5
```

Master VM: `C:\Users\agentmeoww\Documents\Virtual Machines\Ubuntu 22 - labs master
claude\Ubuntu 22 - labs master claude.vmx`. `ovftool.exe` and `vmrun.exe` both ship
with VMware Workstation (`...\VMware Workstation\OVFTool\` and `...\VMware
Workstation\` respectively).

**Known infrastructure quirk worth planning around**: after repeated compose
up/down cycles or long container uptime, the shared VM's Docker bridge/iptables
state has occasionally gotten stuck (containers show `Up` but all HTTP/HTTPS/
LocalStack traffic times out). If a fresh `labctl startm` doesn't come up healthy,
full reset fixes it every time:
```bash
docker compose -f /opt/soulsecure-labs/docker-compose.yml down
docker ps -a --filter name=soulsecure-lab- --format '{{.ID}}' | xargs -r docker rm -f
docker network prune -f
systemctl restart docker
sleep 5
/opt/soulsecure-labs/labctl startm <module> <level>
```

## History

- **2026-08-10**: all 5 Module 2 files (re-)exported to pick up a fix for a real
  bug — `docker-compose.yml` never passed the `LAB_IP` env var into the `osint`
  container, so the Recon Toolkit GUI's displayed `curl` commands showed a
  stale/hardcoded IP regardless of the appliance's actual current IP.
- **2026-08-13**: a critical DNS bug was fixed on the source (`iam`/`bastion`/
  `module6` vhosts never had DNS records — see commit `0d2fcf3`). All Module 3–6
  exports below were built *after* this fix landed, so none of them are affected;
  it only would have mattered for exports built before that date, and none were.
- **2026-08-19 to 2026-08-21**: full Module 3, 4, 5, and 6 per-lab export sets
  built (25 files total) — each live-verified against its target module/level
  state before export, VM restored to the team's default `module=5 level=5` after
  every single export.
