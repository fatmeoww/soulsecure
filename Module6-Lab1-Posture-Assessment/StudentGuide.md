# Module 6 — Lab 1: Automated Cloud Security Posture Assessment

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 6: Cloud Pentesting Tools & Hands-on Labs
**Target:** SoulSecure Inc. — a **second, parallel environment** for this module
(see Section 0)
**Estimated time:** 75–100 minutes

---

## 0. A different kind of target this module

Everything from Module 3 onward ran against hand-built, simplified stand-ins for
cloud APIs — good for learning the underlying mechanics without needing a real AWS
account, but not compatible with the actual tools professionals run day to day.
Module 6 switches to a **LocalStack**-backed environment: a real, local emulation of
the AWS API surface, seeded with resources that mirror the same misconfiguration
patterns you've been finding by hand all course — but this time, genuine open-source
tools (Prowler, Pacu, and friends) can point at it directly, using the real `aws`
CLI's request format, because it's speaking the real API shape.

Your instructor will give you the LocalStack endpoint (`http://<TARGET_IP>:4566`)
and a set of test credentials.

> **Scope reminder:** the LocalStack environment only. Same authorized-engagement
> framing as every other module.

## 1. Scenario

SoulSecure has asked for an automated posture assessment as a follow-up to the
manual engagement you've been running — the kind of pass a real assessment usually
starts with, not ends with. You're going to run one of the field's standard
open-source scanners and see how its findings compare to what you already know.

## 2. Learning objectives

- Configure and run a real AWS security-posture scanner (Prowler or ScoutSuite)
  against a target account
- Read a real automated tool's report format and extract actionable findings from it
- Cross-reference automated findings against your own manual work from Modules 3–5
- Triage a report that contains genuine noise — not every finding a scanner produces
  is equally severe, and recognizing which ones matter is a distinct skill from
  running the tool

## 3. Tasks

### 3.1 — Configure your AWS CLI for the target

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url=http://<TARGET_IP>:4566 sts get-caller-identity
```

### 3.2 — Run a posture scanner

Using Prowler (or ScoutSuite, if your instructor has it installed instead):

```bash
prowler aws --endpoint-url http://<TARGET_IP>:4566 -M html,json
```

This takes a few minutes. It will produce far more findings than you found by hand —
that's expected and part of the lesson.

### 3.3 — Read the report

Open the HTML report. Look specifically for:
- S3 bucket findings (public access)
- IAM policy findings (overly permissive actions/resources)
- IAM trust policy findings (overly permissive `AssumeRole` principals)

For each category, find the specific resource and read any tags or description
fields attached to it — some carry more than just a name.

### 3.4 — Harder mode: find the one that matters most

The report will contain a large number of low/informational findings alongside the
handful of critical ones. Correctly identify which single finding represents the
same "reach full administrative access" risk you spent all of Module 4 proving by
hand — and explain, in one sentence, why a scanner alone wouldn't have told you it
was *exploitable*, only that it was *suspicious*.

## 4. Tools you'll want

- `aws` CLI (pointed at the LocalStack endpoint via `--endpoint-url`)
- Prowler or ScoutSuite (whichever your instructor has installed — either works)

## 5. Deliverable: Automated vs. Manual Findings Comparison

| Scanner finding | Matches a manual finding from Module 3/4/5? | Severity as scored by the tool | Your assessment |
|---|---|---|---|
| | | | |

**Flags found:**

- [ ] Flag 1 (public bucket finding, tag value): `flag{________________________________}`
- [ ] Flag 2 (IAM wildcard policy finding): `flag{________________________________}`
- [ ] Flag 3 (overly permissive trust policy finding): `flag{________________________________}`
- [ ] Flag 4 (harder mode — correctly triaged the critical finding among the noise): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — where tags show up in the report</summary>

Prowler/ScoutSuite reports usually let you expand a finding to see the full resource
metadata, including tags — don't stop at the one-line summary.
</details>

<details>
<summary>Hint 2 — filtering a large report</summary>

Both tools support filtering/searching their output by service (`s3`, `iam`) — use
that instead of scrolling through everything.
</details>

<details>
<summary>Hint 3 — what "exploitable" adds beyond "suspicious"</summary>

A scanner can tell you a policy has `"Action":"*"` — it generally can't tell you
that combining that with `iam:PassRole` and a task-running service gets you to full
admin, because that requires understanding how multiple permissions interact. That
gap is exactly what Lab 2 (Pacu) closes.
</details>

## 7. Known limitations

The LocalStack environment models AWS's API responses closely enough for these
tools to function normally, but it isn't a live AWS account — some checks that rely
on real AWS-side behavior (CloudTrail history, real billing data, etc.) won't
produce meaningful results here. Stick to the S3/IAM-focused findings this lab asks
about.

## 8. Next up

Lab 2 (Cloud Exploitation Framework Practice) points a real exploitation framework
at the same environment — turning the "suspicious" findings from this lab into
confirmed, working privilege escalation, automatically.

