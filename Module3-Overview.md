# Module 3: Initial Access & Storage Exploitation — Overview

> **Status: PLANNED — design doc only.** No Docker services, labs, or flags built
> yet. This is the scaffold to build against once Module 2 ships. Mirrors the
> structure of [Module2-Overview.md](Module2-Overview.md); update in place as labs
> get built (StudentGuide/InstructorKey/Walkthrough-TH per lab, Docker-Ops doc,
> Flags summary, OVA exports).

**Course:** Cloud Pentest
**Fictional target:** SoulSecure Inc., domain `soulsecure.lab` (same tenant — continues
directly from Module 2, does not reset)
**Architecture (proposed):** extend the existing Module 2 Docker Compose stack rather
than start a new one — add new services/vhosts behind the same `www` nginx gateway,
reuse the CA/TLS setup and `labctl` pattern. Numbering scheme for `LAB_LEVEL` TBD at
build time: either continue 6–10 on the same stack, or introduce a second `MODULE`
env var (`MODULE=3 LEVEL=1..5`) so Module 2 and Module 3 can be run independently.
Decide this before scaffolding `docker-compose.yml` changes.

## Why this module exists (continuity from Module 2)

Module 2 was pure recon: students *found and fingerprinted* assets but were told not
to touch anything (passive/non-destructive scope). Module 3 is where that restraint
pays off — every lab here exploits something students only looked at before:

| Planted in Module 2 | Pays off in Module 3 |
|---|---|
| `soulsecure-dev-assets` bucket — confirmed to *exist* but `403 AccessDenied`, no creds available (Lab 4) | Lab 1 — a newly-found leaked credential pair turns that denial into access |
| Fake `AKIAFAKESOULSECURE0x`-pattern keys in API errors (Lab 3) and bucket objects (Lab 4) — **explicitly non-functional, narrative glue only** (see M2 Lab 3/4 InstructorKey design notes) | Stay red herrings — Module 3 mints its *own*, mechanically distinct, genuinely functional credentials per lab. Discussion hook: two different "leaked key" patterns in one engagement, one real, one not, indistinguishable until tried |
| `jenkins-old` found by port scan, flag-in-comment only, no real content (Lab 1) | Lab 3 — actual initial-access target |
| `backup-eu.soulsecure.lab`, flag-in-comment landing page only (Lab 1) | Lab 4 — credential/secret harvesting target |
| `vpn.soulsecure.lab`, flag-in-comment landing page only (Lab 1) | Lab 5 — initial access target |

**Module-level goal:** every student should leave Module 3 holding 2–3 distinct sets
of credentials (AWS-style keys, a GCP-style service-account JSON, an SSH key) of
*unknown* privilege level. That uncertainty is the exact hook Module 4 (IAM
Exploitation) starts from — don't resolve what these creds can do in this module.

## Planned 5 labs

| # | Lab | Focus | New/changed asset vs. Module 2 |
|---|---|---|---|
| 1 | Authenticated & Misconfigured Object Storage Exploitation | Turning M2 Lab 4's `AccessDenied` bucket into real access via a newly-leaked credential pair, public-write bucket abuse (distinct from public-read, which M2 Lab 4 already covered), unauthenticated presigned-URL minting abuse | New: a leaked-credentials bucket, a public-write bucket, a `/presign` route, and one bucket reachable only through it — see [Module3-Lab1-Object-Storage-Exploitation](Module3-Lab1-Object-Storage-Exploitation/StudentGuide.md) (drafted) |
| 2 | SSRF → Cloud Instance Metadata Service (IMDS) | Finding an SSRF-vulnerable feature (e.g. "import from URL" / webhook callback on `api`), pivoting to `169.254.169.254`-style mock IMDS, stealing temporary role credentials | New: an SSRF-vulnerable endpoint on `api`, new mock-IMDS container |
| 3 | Exposed CI/CD Server Exploitation | Unauthenticated/weak-creds Jenkins access, script console RCE, credentials store dump, hardcoded cloud keys in a Jenkinsfile/build env, planting a build step | `jenkins-old` gets real content (was banner-only shadow-IT find in M2 Lab 1) |
| 4 | Backup Portal & Secrets in Backups | Weak/leaked portal auth, downloading backup archives, extracting service-account JSON / `.git` dumps / plaintext config secrets | `backup-eu.soulsecure.lab` gets file listing + downloadable archives (was unexplored in M2) |
| 5 | VPN / Remote Access Gateway Exploitation | Leaked VPN client config or credentials (surfaced via earlier labs in this module), weak portal auth, foothold credential harvesting | `vpn.soulsecure.lab` gets a login portal + downloadable client config |

Target: ~4–5 flags/lab (3 core + 1–2 harder-mode), same `flag{md5-hash}` format as
Module 2, same "harder mode" pattern (one extra twist per lab — e.g. Lab 2's
harder-mode could require chaining through a redirect-based SSRF filter bypass).

## Tooling to plan for

`aws`-CLI-compatible client (or a lab-local shim if not hitting real AWS APIs),
`curl`/`gobuster` for bucket/portal brute forcing, a Jenkins CLI or raw HTTP for the
script console, `git` for dump extraction, basic archive tools (`tar`/`zip`/`unzip`).
Decide during build whether the mock cloud API surface (buckets, IMDS, IAM-adjacent
responses) is served by extending the existing Flask `apps/` base from Module 2 or a
new shared service.

## Open design questions to resolve before building

- Does the mock IMDS respond with a *fixed* set of temp creds, or creds scoped
  differently per which SSRF path the student used (to differentiate core vs.
  harder-mode)?
- Do the credentials harvested across labs 1/3/4/5 need to be *consistent* with each
  other (same account) so Module 4 can chain them, or deliberately inconsistent
  (student must figure out which cred set is useful for which target)?
- Reuse `LAB_LEVEL` gating pattern from Module 2 or introduce per-module levels?

## Next up

Module 4 (IAM Exploitation & Privilege Escalation) picks up with whatever credentials
students walked away with here — first task there is enumerating what those
credentials can actually do.
