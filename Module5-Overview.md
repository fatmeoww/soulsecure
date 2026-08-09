# Module 5: Post-Exploitation, Persistence & Lateral Movement — Overview

> **Status: PLANNED — design doc only, but Labs 1–5 now have full StudentGuide +
> InstructorKey drafts** (see [Module5-Build-Spec.md](Module5-Build-Spec.md) for the
> consolidated index). Depends on Module 4 shipping first (needs its admin-equivalent
> credential as input). Mirrors [Module2-Overview.md](Module2-Overview.md); update in
> place as labs get built on the VM.

**Course:** Cloud Pentest
**Fictional target:** SoulSecure Inc. (same tenant, continuing from Module 4)
**Architecture (proposed):** extends the `iam-sim` control plane from Module 4 with
state that *persists across a session* (backdoor users/keys/policies actually stick
around and are checkable later), plus a second compute-ish target (a small
container-orchestration stand-in, e.g. a mock "cluster" service) to give lateral
movement somewhere to move *to* beyond IAM alone.

## Why this module exists (continuity from Module 4)

Module 4 ends with students holding an admin-equivalent credential earned through a
provable escalation chain. Module 5 asks the next two questions every real engagement
asks: *can you keep this access if the original hole gets patched*, and *what else
can you reach from here*.

| Planted in Module 4 | Pays off in Module 5 |
|---|---|
| Admin-equivalent IAM credential (module-end goal) | Lab 1 — plant IAM backdoors before "cleanup" simulated |
| Instance-role creds via IMDS (M3→M4 Lab 3 chain) | Lab 2 — pivot compute-to-compute using role creds |
| Jenkins access from Module 3 Lab 3 | Lab 5 — reuse CI/CD as a persistence mechanism, not just an initial-access path |
| Secrets Manager exposure (M4 Lab 5) | Lab 4 — abuse the same over-broad read path for snapshot/backup exfiltration |

**Module-level goal:** students produce a **persistence/lateral-movement map** —
which backdoors they planted, where, and how each survives if any single one is
discovered and removed. That map becomes the raw material Module 6 wraps in tooling
and a formal report.

## Planned 5 labs

| # | Lab | Focus | Notes |
|---|---|---|---|
| 1 | Persistence via IAM Backdoors | New low-visibility admin user, backdoored trust policy on `soulsecure-finance-role`, second access key on an existing legitimate identity — each tested against a self-triggerable remediation simulation | See [Module5-Lab1-IAM-Backdoors](Module5-Lab1-IAM-Backdoors/StudentGuide.md) (drafted) |
| 2 | Lateral Movement via Compute/Instance-Profile Pivoting | SSH-key-fingerprint-gated bastion pivot (finally using Module 3 Lab 5's jump-host key), then an SSRF-shaped proxy reach to a second instance role | See [Module5-Lab2-Compute-Lateral-Movement](Module5-Lab2-Compute-Lateral-Movement/StudentGuide.md) (drafted) |
| 3 | Container/Cluster Escape & Lateral Movement | Exposed Docker Engine API subset (`docker-proxy`) — host-mounted container creation + `exec` for read and persistent write | See [Module5-Lab3-Container-Escape](Module5-Lab3-Container-Escape/StudentGuide.md) (drafted) |
| 4 | Data Exfiltration via Storage & Snapshot Abuse | Admin-only backup export, DB snapshot create/download, bucket-policy cross-account sharing as a stealthier alternative to direct download | See [Module5-Lab4-Data-Exfiltration](Module5-Lab4-Data-Exfiltration/StudentGuide.md) (drafted) |
| 5 | Persistence via CI/CD & Automation | Jenkins job-config backdoor, self-healing scheduled automation task, tested against both routine remediation and a deeper audit that (deliberately) still misses Lab 1's trust-policy backdoor | See [Module5-Lab5-CICD-Automation-Persistence](Module5-Lab5-CICD-Automation-Persistence/StudentGuide.md) (drafted) — capstone-of-module, ties Labs 1 and 3 (Module 3) together explicitly |

Target: ~4–5 flags/lab. Consider one flag per lab that only appears **after** a
simulated "detection and remediation" event (e.g. the original leaked key gets
rotated) — reinforces the "does your persistence survive cleanup" lesson concretely
rather than just narratively.

## Tooling to plan for

Whatever CLI/API surface Module 4 settles on for `iam-sim`, extended with
list/describe calls so students can *verify* their own backdoors persisted (a
realistic "prove persistence" step, not just "the instructor says it worked").
Container lab needs a deliberately vulnerable but self-contained runtime — avoid
anything requiring real Docker-in-Docker/privileged access on student machines if
possible.

## Design questions — resolved during Lab 1–5 drafting

- **Container/cluster lab scope:** resolved — kept as a genuinely simplified subset
  of the real Docker Engine API (`docker-proxy`, Lab 3), not a full cluster/k8s
  simulation. Deliberately isolated with no real access to the host's actual Docker
  socket (safety-critical build requirement, not optional).
- **Simulated remediation trigger:** resolved as a manual, student- or
  instructor-triggerable API call (`/admin/simulate-remediation`, extended in Lab 5
  by `/admin/simulate-deep-audit`) rather than a timer — students self-check their
  own persistence, matching real red-team practice of validating your own
  backdoors before relying on them.
- **Persistence map → Module 6 report format:** deferred to Module 6's own build
  phase — Lab 5's Section 5 deliverable already produces the full Module 5
  consolidated table; Module 6 Lab 5 (capstone) should reuse that structure directly
  rather than inventing a new one.

See [Module5-Build-Spec.md](Module5-Build-Spec.md) for the full route index,
cross-module dependency chain, and continuity checklist.

## Next up

Module 6 (Cloud Pentesting Tools & Hands-on Labs) shifts from "do it by hand, prove
you understand the primitive" to "now do it with the real tools professionals use,"
and closes with a full-chain capstone spanning Modules 3–5 in one continuous run.
