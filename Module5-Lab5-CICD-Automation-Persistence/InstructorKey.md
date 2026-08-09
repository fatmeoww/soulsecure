# Module 5 — Lab 5: Persistence via CI/CD & Automation — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Depends
> on Module 3 Lab 3's `/script` mechanism, Module 4 Lab 3's `automation:CreateTask`,
> and Module 5 Lab 1's backdoors + `/admin/simulate-remediation`. Flag values below
> are placeholders generated at planning time.

## Extension: `jenkins-old` `/script` pattern table (adds to Module 3 Lab 3's table)

| If POSTed `script` body contains... | Mock returns | Notes |
|---|---|---|
| `new File(...).text = "..."` targeting `/var/jenkins_home/jobs/<job>/config.xml` where the new content includes a recognizable build-step marker (e.g. `<hudson.tasks.Shell>`) | Marks that job `backdoored: true` in server-side state; returns `"status":"config updated","flag":"flag{17505a3ed3e5019ecd053a6430313ff2}"` | **Flag 1** |

`GET /job/<name>/config.xml` (existing route) should reflect the updated content
once backdoored, so students (and instructors) can verify via a plain read too.

## Extension: `iam-sim` `/automation/create-task` — scheduling

Module 4 Lab 3's route gains an optional `schedule` field:
```
POST /automation/create-task
Body: {"execution_role": "...", "command": "...", "schedule": "rate(1 hour)"}
```
When `schedule` is present **and** `command` contains `recreate-backdoor` (or similar
recognizable marker), store a persistent "scheduled task" record. Response:
`{"status":"scheduled","task_id":"<id>","flag":"flag{8e3d51e61b9915c926a8d403f3f0bdeb}"}`
— **Flag 2**.

## Self-healing mechanic

When `/admin/simulate-remediation` (Module 5 Lab 1) runs, **after** performing its
normal revocations, check for any active scheduled task matching the
`recreate-backdoor` marker. If one exists, immediately (no real wait — simulate
instantly) recreate the exact backdoor user/policy/key that Lab 1's `create-user`
flow produced, using the same student-chosen username if recorded, or a default
fallback name if not. Then, on the **next** authenticated call using that recreated
identity's credentials (e.g. `get-caller-identity`), include
`"flag":"flag{17205c5f7592f7e1eaece480045dcf44}"` — **Flag 3** — confirming the
self-heal fired.

## New route: `/admin/simulate-deep-audit`

A second, more thorough remediation simulation. On call:
1. Does everything `/admin/simulate-remediation` does.
2. **Additionally** scans all Jenkins job configs for backdoor markers (reverses any
   `backdoored: true` job from this lab's 3.1) and removes any scheduled automation
   task matching `recreate-backdoor` (defeating Flag 2/3's mechanism going forward).
3. **Does NOT** scan or touch trust policies — deliberately. Module 5 Lab 1's
   trust-policy addition to `soulsecure-finance-role` (Flag 2 of that lab) is
   untouched by this route.

After `/admin/simulate-deep-audit`, calling `/sts/assume-role` against
`soulsecure-finance-role` using the backdoor principal added in Lab 1 3.2 still
succeeds, and the response includes
`"flag":"flag{012f77a55bd7b3679c6798dcb8550562}"` — **Flag 4**, only present
post-deep-audit, confirming this specific backdoor category was never checked.

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | Jenkins `/script`, job-config backdoor write | `flag{17505a3ed3e5019ecd053a6430313ff2}` |
| Flag 2 | `iam-sim` `/automation/create-task` with `schedule` + `recreate-backdoor` | `flag{8e3d51e61b9915c926a8d403f3f0bdeb}` |
| Flag 3 | Backdoor identity's first authenticated call after self-heal fires post-remediation | `flag{17205c5f7592f7e1eaece480045dcf44}` |
| Flag 4 (harder mode) | `soulsecure-finance-role` assume-role via Lab 1's trust-policy backdoor, post-deep-audit | `flag{012f77a55bd7b3679c6798dcb8550562}` |

## Verification commands (once built)

```bash
curl -s http://<TARGET_IP>:9090/script -X POST \
  --data-urlencode 'script=new File("/var/jenkins_home/jobs/nightly-deploy/config.xml").text = "<config with <hudson.tasks.Shell> step>"'   # Flag 1

curl -sk -X POST https://iam.soulsecure.lab/automation/create-task \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' \
  -d '{"execution_role":"arn:aws:iam::445566778899:role/automation-admin-role","command":"recreate-backdoor-if-missing","schedule":"rate(1 hour)"}'   # Flag 2

curl -sk -X POST https://iam.soulsecure.lab/admin/simulate-remediation \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>"
curl -sk https://iam.soulsecure.lab/sts/get-caller-identity \
  -H "X-Access-Key-Id: <recreated-backdoor-key>" -H "X-Secret-Access-Key: <secret>"   # Flag 3

curl -sk -X POST https://iam.soulsecure.lab/admin/simulate-deep-audit \
  -H "X-Access-Key-Id: ASIAADMIN99" -H "X-Secret-Access-Key: <secret>"
curl -sk -X POST https://iam.soulsecure.lab/sts/assume-role \
  -H "X-Access-Key-Id: <lab1-trust-policy-backdoor-principal-key>" -H "X-Secret-Access-Key: <secret>" \
  -H 'Content-Type: application/json' \
  -d '{"role_arn":"arn:aws:iam::445566778899:role/soulsecure-finance-role"}'   # Flag 4
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Successfully backdoored a Jenkins job config via script console | 20 |
| Successfully created a scheduled self-healing automation task | 20 |
| Confirmed self-heal fired after routine remediation | 20 |
| Ran the deep audit and correctly identified which Lab 5 mechanisms it caught | 15 |
| Confirmed the Lab 1 trust-policy backdoor survived the deep audit and correctly explained why (category never checked, not luck) | 20 |
| Complete Module 5 wrap-up table with accurate survival predictions per mechanism | 5 |

## Design notes / narrative threads

- This lab's real teaching point isn't any single technique — it's that **different
  categories of persistence get caught by different categories of review**, and a
  security team's remediation is only as complete as their own checklist. The Lab 1
  trust-policy backdoor surviving `/admin/simulate-deep-audit` isn't because it's a
  cleverer technique than the others; it's because nobody thought to check trust
  policies specifically. Make sure class debrief lands this point explicitly.
- Deliberately makes the Lab 5-native mechanisms (job backdoor, scheduled task) the
  ones that get caught by the harder-mode audit, while an *earlier*, more
  structurally boring-looking Lab 1 mechanism survives — resist the temptation to
  make the newest/flashiest technique also the most durable one; that's not how real
  security reviews tend to work.

## File locations (proposed)

- `/opt/soulsecure-labs/apps/` (jenkins-old app) — extend the `/script` pattern table
  and job-state dict from Module 3 Lab 3
- `/opt/soulsecure-labs/apps/iam_sim.py` — extend `automation:CreateTask` with
  `schedule`, add the self-heal check inside `/admin/simulate-remediation`, add
  `/admin/simulate-deep-audit`

## Known limitations

Same as every other lab referencing `jenkins-old`'s simplified `/script` or
`iam-sim`'s simplified conventions. "Self-healing" and "deep audit" are both
deterministic, instantly-evaluated training mechanics, not models of real detection
timelines or real EventBridge/Lambda scheduling infrastructure.
