# Module 4 — Build Spec (IAM Exploitation & Privilege Escalation)

> **⚠️ PLANNED CONTENT — nothing in this document is deployed.** Consolidated
> implementation checklist, mirroring [Module3-Build-Spec.md](Module3-Build-Spec.md).
> Ground truth lives in each lab's InstructorKey
> ([Lab1](Module4-Lab1-Credential-Enumeration/InstructorKey.md) through
> [Lab5](Module4-Lab5-Secrets-Manager-Exploitation/InstructorKey.md)); this is the
> at-a-glance index.

## New container: `iam-sim`

One new Flask container, new vhost `iam.soulsecure.lab` via the `www` gateway (add
to TLS SAN list). Implements a simplified but **genuinely enforced** AWS STS/IAM API
plus a small GCP-flavored surface. All auth via the `X-Access-Key-Id`/
`X-Secret-Access-Key` header pair convention from Module 3 Lab 1; GCP calls via
`X-GCP-Client-Email`.

**Single most important build task:** write the policy evaluator
(`is_allowed(principal, action, resource)`) once, correctly, in Lab 1's scope — every
other lab's routes depend on it and none should re-implement evaluation logic.

## Cross-module dependency (flag this during build sequencing)

Module 4 Lab 4 requires an edit to **Module 3's** `storage_app.py` (accepting
`ASIAFINANCE77` credentials for `soulsecure-finance-records`, adding
`finance-role-only-notes.txt`). This is the only Module 4 lab that reaches outside
`iam-sim`. Don't consider Module 4 Lab 4 buildable until Module 3 Lab 1's storage app
is in a stable, already-tested state.

## Full route index (all 5 labs)

| Method | Path | Introduced in | Auth |
|---|---|---|---|
| POST | `/sts/get-caller-identity` | Lab 1 | AWS headers |
| GET | `/iam/whoami-summary` | Lab 1 (extended Lab 4) | AWS headers |
| POST | `/gcp/testIamPermissions` | Lab 1 | `X-GCP-Client-Email` |
| GET | `/iam/policy?name=` | Lab 2 | AWS headers |
| GET | `/iam/trust-policy?role=` | Lab 2 | AWS headers |
| POST | `/automation/create-task` | Lab 3 | AWS headers |
| POST | `/iam/create-policy-version` | Lab 3 | AWS headers |
| POST | `/iam/set-default-policy-version` | Lab 3 | AWS headers |
| GET | `/iam/list-all-identities` | Lab 3 | AWS headers (admin-only) |
| POST | `/sts/assume-role` | Lab 4 | AWS headers |
| POST | `/gcp/impersonate` | Lab 4 | `X-GCP-Client-Email` |
| GET | `/secretsmanager/list-secrets` | Lab 5 | AWS headers |
| GET | `/secretsmanager/get-secret-value?name=&version=` | Lab 5 | AWS headers |

## Identity/policy/secret registry (consolidated — see Lab 1/2/5 InstructorKeys for full JSON)

| Principal | Standing credential? | Key policy/permission | First appears |
|---|---|---|---|
| `soulsecure-app-role` | Yes (from M3) | `AppRoleReadOnly` — dead end, negative control | Lab 1 |
| `soulsecure-deploy-role` | Yes (from M3) | `DeployRolePolicy` (PassRole+CreateTask) + `LegacyReadOnlyAuditPolicy` (Lab 2) + secretsmanager statement (Lab 5) | Lab 1, extended Labs 2 & 5 |
| `soulsecure-ci-deploy` | Yes (from M3) | `CIDeployPolicy` — self-managed policy version | Lab 1 |
| `storage-readonly` | Yes (from M3) | `StorageReadOnlyPolicy` — dead end within `iam-sim` | Lab 1 |
| `ci-backup@...gserviceaccount.com` | Yes (from M3) | GCP custom role — `actAs`/`getAccessToken` on `admin@...` | Lab 1 |
| `soulsecure-finance-role` | **No** — assume-only | `FinanceRolePolicy`, weak trust policy | Introduced Lab 2, exploited Lab 4 |
| `automation-admin-role` | **No** — reach-only | `Action:"*",Resource:"*"` — the crown jewel | Introduced Lab 1/2, reached Lab 3 |
| `admin@...gserviceaccount.com` (GCP) | **No** — impersonation-only | GCP admin-equivalent | Introduced Lab 1, reached Lab 4 |

## Master flag index (all 5 labs)

| Lab | Flag # | Value |
|---|---|---|
| 1 | 1 | `flag{b69b7f4f374540b29ae43404a9fcc89d}` |
| 1 | 2 | `flag{d02044d2a25acc0fd3703bed5c907cf8}` |
| 1 | 3 | `flag{52ad361a3ff8ffbfb019464ec97f54a8}` |
| 1 | 4 (harder) | `flag{d54dd5f6a25d0552109c0a67c86d8664}` |
| 2 | 1 | `flag{820d94547e3e663b7d45379d2062e3b3}` |
| 2 | 2 | `flag{5fd49af54f9c0cc0625120e68b81f681}` |
| 2 | 3 | `flag{7f7be903dbc162e3958d6272c83c7dbf}` |
| 2 | 4 (harder) | `flag{616c068d362294c6963dca42a17a4fba}` |
| 3 | 1 | `flag{092b9c2475d46295ca0f74ff12dee495}` |
| 3 | 2 | `flag{9fd20ef580ba858a4e5463f0d5100eb7}` |
| 3 | 3 | `flag{759f58aac7d06b135e6ee09e6e188a83}` |
| 3 | 4 (harder) | `flag{d1d73a3f8c5aa9246fd06eba0405d712}` |
| 4 | 1 | `flag{40228829de824ce9a37786eab838f977}` |
| 4 | 2 | `flag{e09a5ffcdc93f8f4956afa51abe36b6c}` |
| 4 | 3 | `flag{3148dda5ed81821c98f2a9f5e5691ad9}` |
| 4 | 4 (harder) | `flag{a3904b2cfa7a4e7bf20adf1ac6c4706b}` |
| 5 | 1 | `flag{e712f0a5409ca9fdd929e85d7d2d49c4}` |
| 5 | 2 | `flag{1ab5f666b3223a676701d255ac68940b}` |
| 5 | 3 | `flag{b233cc12d92ac3a3baa20ded1af225c0}` |
| 5 | 4 (harder) | `flag{8b9477d2b6dcb35b28ee5409011c1d1a}` |

**20 flags**, consistent with Module 2 and Module 3.

## Cross-module continuity checklist (verify during build)

- [ ] `soulsecure-app-role`, `soulsecure-deploy-role`, `soulsecure-ci-deploy`,
      `storage-readonly` access keys/secrets in `iam-sim` are **byte-identical** to
      the values Module 3 Labs 2/2-harder/3/1 hand students — this is what makes
      "bring your Module 3 haul" actually work
- [ ] `soulsecure/stripe/live-key` (Lab 5) matches Module 3 Lab 4's git-history value
      exactly
- [ ] `soulsecure/db/prod-password` current version (Lab 5) matches Module 3 Lab 4's
      `config/app.env` value exactly
- [ ] `soulsecure-finance-role`'s AWS credentials, once assumed, work against
      `storage.soulsecure.lab/soulsecure-finance-records/` (requires the Module 3
      `storage_app.py` edit noted above)
- [ ] Every escalation path genuinely changes what the policy evaluator returns for
      subsequent calls — not just a canned "success" response with no actual state
      change (this is the single most important correctness property of the whole
      module; test it explicitly)

## Level → content map (proposed, follows Module 3's `MODULE`/`LEVEL` scheme)

| `LEVEL` | Unlocks |
|---|---|
| 1 | Lab 1 (`iam-sim` stood up, identity registry, `whoami-summary`, GCP `testIamPermissions`) |
| 2 | + Lab 2 (`LegacyReadOnlyAuditPolicy`, `soulsecure-finance-role` introduced, policy/trust-policy read routes) |
| 3 | + Lab 3 (escalation routes, `list-all-identities`) |
| 4 | + Lab 4 (`assume-role`, `gcp/impersonate`, storage app cross-module edit) |
| 5 | + Lab 5 (Secrets Manager routes, secretsmanager statement on `DeployRolePolicy`) |

## Deferred/not-yet-decided items

- `Module4-Docker-Ops.md` and a Thai flags/walkthrough doc — write once implemented
  and verified, same policy as Module 3.
- OVA export composition for Module 4 — likely needs Module 3's full stack
  underneath it (real credential values must match), unlike some of Module 3's own
  labs which only needed partial carry-forward. Decide exact scope when OVAs are
  actually built.
