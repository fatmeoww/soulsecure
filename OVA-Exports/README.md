# Module 2 — OVA Exports

Five standalone VMware appliance files, one per lab, exported from the same master VM
(`Ubuntu 22 - labs master claude`) at a different `LAB_LEVEL` each time.

| File | Size | Contains |
|---|---|---|
| `SoulSecure-Lab-Module2-Lab1.ova` | ~4.46 GB | Lab 1 only |
| `SoulSecure-Lab-Module2-Lab2.ova` | ~4.46 GB | Labs 1–2 |
| `SoulSecure-Lab-Module2-Lab3.ova` | ~4.45 GB | Labs 1–3 |
| `SoulSecure-Lab-Module2-Lab4.ova` | ~4.45 GB | Labs 1–4 |
| `SoulSecure-Lab-Module2-Lab5.ova` | ~4.45 GB | Labs 1–5 (full) |

Each file is genuinely self-contained and independent — there is no cross-file
dependency, and importing one has no effect on the others.

## Why the sizes are all cumulative, not per-lab

Labs 2–5 build on shared infrastructure from earlier labs (same DNS zone, same nginx
service, same API service — see [Module2-Docker-Ops.md](../Module2-Reconnaissance-Enumeration/Docker-Ops.md) for
how `LAB_LEVEL` gating works). So "Lab 3" here means "Labs 1 through 3 content, Lab 4/5
content hidden" — matching exactly what a student would see if they'd worked the labs
in order up through that point. This was a deliberate tradeoff over building 5 fully
isolated environments (see that doc for the reasoning).

## Importing and using an OVA

1. Import into VMware Workstation/Player/Fusion, or ESXi (File → Open, or
   `ovftool <file>.ova <destination>`).
2. **Rename the VM** after import if you want — it currently shows up as
   `Ubuntu 22 - labs master claude` in your hypervisor's VM list regardless of which
   lab file you imported (a cosmetic leftover from the shared master source; the OVA
   *filename* is still correct, only the internal display name isn't lab-specific).
3. Power it on. No setup needed — a boot-time service
   (`soulsecure-boot.service`) automatically:
   - Detects the VM's current IP (works whether it lands on a NAT'd private IP, a
     different VMware host, or gets imported straight to an AWS EC2 instance)
   - Starts exactly the lab level baked into that OVA (`/opt/soulsecure-labs/lab.level`)
   - No manual `labctl` invocation required — though it's still there if you want to
     switch levels later (`ssh tester@<ip>`, then see
     [Module2-Docker-Ops.md](../Module2-Reconnaissance-Enumeration/Docker-Ops.md))
4. Give students the VM's IP (shown by `cat /opt/soulsecure-labs/.env` over SSH, or
   just check your hypervisor's network info) — that's the `<TARGET_IP>` referenced
   throughout each lab's StudentGuide.

**Credentials:** `tester` / `password` (SSH). Same lab-only credential used throughout
— not internet-facing, isolated training network only.

## Regenerating these OVAs later

If lab content changes, the whole 5-export cycle needs to be repeated (there's no
patch/diff mechanism for OVAs). Process used to build these:

```
for level in 1 2 3 4 5:
    ssh in, set /opt/soulsecure-labs/lab.level = level
    sudo /opt/soulsecure-labs/labctl start <level>   # verify it's correct
    sudo shutdown -h now
    (wait for the VM to fully power off)
    ovftool.exe --overwrite "<vmx path>" "SoulSecure-Lab-Module2-Lab<level>.ova"
    vmrun.exe start "<vmx path>" nogui               # power back on for next level
```

Master VM: `C:\Users\agentmeoww\Documents\Virtual Machines\Ubuntu 22 - labs master
claude\Ubuntu 22 - labs master claude.vmx`. `ovftool.exe` and `vmrun.exe` both ship
with VMware Workstation (`...\VMware Workstation\OVFTool\` and `...\VMware
Workstation\` respectively).
