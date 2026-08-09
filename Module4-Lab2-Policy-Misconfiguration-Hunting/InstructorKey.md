# Module 4 — Lab 2: IAM Policy Misconfiguration Hunting — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Extends
> the canonical registry in [Lab 1's InstructorKey](../Module4-Lab1-Credential-Enumeration/InstructorKey.md)
> — read that first. Flag values below are placeholders generated at planning time.

## Registry additions (extends Lab 1's canonical table)

**`soulsecure-deploy-role` actually has TWO attached policies**, not one — Lab 1's
guide only walked students through noticing `DeployRolePolicy` closely;
`whoami-summary`'s `attached_policies` list has always included both, this lab is
where students are expected to read the second one properly:

**`LegacyReadOnlyAuditPolicy`** (second policy attached to `soulsecure-deploy-role`):
```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": ["iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
    "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies", "iam:GetTrustPolicy"],
   "Resource": "*"}
]}
```
Description field (returned alongside the policy document): `"Left over from an
account-wide security audit last year. Never revoked."` — the whole point: broad
IAM-read access is easy to forget about because it doesn't look dangerous the way
`iam:*` or `s3:*` does.

**New role: `soulsecure-finance-role`** (no standing credential — reachable only via
`sts:AssumeRole`, exploited in Lab 4):
```
ARN: arn:aws:iam::445566778899:role/soulsecure-finance-role
Permissions policy (FinanceRolePolicy): s3:GetObject, s3:ListBucket on
  arn:aws:s3:::soulsecure-finance-records and /*
Trust policy (AssumeRolePolicyDocument):
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::445566778899:root"},
   "Action": "sts:AssumeRole"}
]}
```
No `Condition` block at all — any principal in the account can assume it, no
`ExternalId`, no MFA requirement. **This is the Lab 4 core target.**

`automation-admin-role`'s full policy document (already referenced in Lab 1, now
actually readable):
```json
{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Action": "*", "Resource": "*"}
]}
```
Confirms it as the account's de facto `AdministratorAccess`-equivalent — reading this
here is what lets students correctly frame severity going into Lab 3, before they've
exploited anything.

## New `iam-sim` routes for this lab

| Method | Path | Auth/enforcement | Behavior |
|---|---|---|---|
| GET | `/iam/policy?name=<policy-name>` | Caller must have `iam:GetPolicy`+`iam:GetPolicyVersion` on that specific policy (either because it's their own attached policy, or via `LegacyReadOnlyAuditPolicy`'s wildcard) | Returns the full policy JSON + `description` + (see flag table) |
| GET | `/iam/trust-policy?role=<role-name>` | Same enforcement pattern, using `iam:GetTrustPolicy` | Returns the role's `AssumeRolePolicyDocument` |

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `whoami-summary` for `soulsecure-deploy-role`, noticing `LegacyReadOnlyAuditPolicy` — returned as a `flag` field on the `/iam/policy?name=LegacyReadOnlyAuditPolicy` fetch itself | `flag{820d94547e3e663b7d45379d2062e3b3}` |
| Flag 2 | `/iam/policy?name=AdministratorAccess` (or whatever the admin policy is named — align with Lab 1/3's naming) via `LegacyReadOnlyAuditPolicy` | `flag{5fd49af54f9c0cc0625120e68b81f681}` |
| Flag 3 | `/iam/policy?name=CIDeployPolicy` via `LegacyReadOnlyAuditPolicy` | `flag{7f7be903dbc162e3958d6272c83c7dbf}` |
| Flag 4 (harder mode) | `/iam/trust-policy?role=soulsecure-finance-role` | `flag{616c068d362294c6963dca42a17a4fba}` |

## Verification commands (once built)

```bash
curl -sk "https://iam.soulsecure.lab/iam/policy?name=LegacyReadOnlyAuditPolicy" \
  -H "X-Access-Key-Id: ASIASOULSECUREDEPLOY02" -H "X-Secret-Access-Key: <secret>"    # Flag 1

curl -sk "https://iam.soulsecure.lab/iam/policy?name=AdministratorAccess" \
  -H "X-Access-Key-Id: ASIASOULSECUREDEPLOY02" -H "X-Secret-Access-Key: <secret>"    # Flag 2

curl -sk "https://iam.soulsecure.lab/iam/policy?name=CIDeployPolicy" \
  -H "X-Access-Key-Id: ASIASOULSECUREDEPLOY02" -H "X-Secret-Access-Key: <secret>"    # Flag 3

curl -sk "https://iam.soulsecure.lab/iam/trust-policy?role=soulsecure-finance-role" \
  -H "X-Access-Key-Id: ASIASOULSECUREDEPLOY02" -H "X-Secret-Access-Key: <secret>"    # Flag 4
```

Note: reading `CIDeployPolicy` or `AdministratorAccess` also works with
`soulsecure-ci-deploy`'s own credentials for the former (it's attached to itself),
but only `soulsecure-deploy-role` (via `LegacyReadOnlyAuditPolicy`) can read
**everything**, which is the point students should articulate in Section 5.

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Noticed and correctly flagged `LegacyReadOnlyAuditPolicy` as the real finding (not just "deploy-role has 2 policies") | 25 |
| Used it to read `automation-admin-role`'s policy and correctly framed severity | 20 |
| Confirmed `CIDeployPolicy`'s self-modify statement directly from JSON | 20 |
| Found and correctly explained the `soulsecure-finance-role` trust-policy gap (missing Condition, broad Principal) | 25 |
| Clean findings table with accurate "why dangerous" reasoning per row | 10 |

## Design notes / narrative threads

- `LegacyReadOnlyAuditPolicy` is the lab's central lesson: **broad read access is
  still a real finding**, not a footnote — it's what makes every other policy in the
  account discoverable, including the trust policy that Lab 4 needs.
- `soulsecure-finance-role` deliberately breaks from the "every path leads to
  `automation-admin-role`" pattern established in Lab 1/3 — a real engagement
  produces findings of varying severity, not just one crown jewel. Its own
  permissions (finance bucket read) are moderate, not full admin.

## File locations (proposed)

- `/opt/soulsecure-labs/apps/iam_sim.py` — add `soulsecure-finance-role` to the role
  registry (no standing credential), add `LegacyReadOnlyAuditPolicy` to
  `soulsecure-deploy-role`'s attached-policies list, implement the two new GET routes
  against the same `is_allowed()` evaluator from Lab 1.

## Known limitations

Same as Lab 1 — see that InstructorKey.
