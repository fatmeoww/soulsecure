# Module 6 — Lab 4: Infrastructure-as-Code (IaC) Security Review

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 6: Cloud Pentesting Tools & Hands-on Labs
**Target:** A Terraform snapshot of SoulSecure's infrastructure definitions
**Estimated time:** 60–90 minutes

---

## 1. Recap & scenario

Everything you've found across this entire course already existed as *code* before
it existed as a live, exploitable system — someone wrote a Terraform file that
created a public bucket, or an IAM policy with a wildcard action, before you ever
ran `curl` against it. This lab is about catching those problems at the source,
before deployment, the way a mature security program actually tries to work: shift
left.

> **Scope reminder:** the provided Terraform files only — this lab involves no live
> infrastructure at all, static analysis exclusively.

## 2. Learning objectives

- Run a real IaC security scanner (checkov or tfsec) against Terraform source
- Map static-analysis findings back to specific, real vulnerabilities you exploited
  earlier in this course
- Recognize a misconfiguration class that hasn't come up yet in this engagement
  (network exposure) using the same static-analysis workflow
- Remediate a finding directly in source and confirm the fix with a re-scan — the
  complete real-world loop, not just detection

## 3. Tasks

### 3.1 — Run the scanner

```bash
checkov -d ./soulsecure-terraform --compact
```
or
```bash
tfsec ./soulsecure-terraform
```

### 3.2 — Map findings to what you already know

Go through the output and connect each finding to a specific lab from Module 3 or 4
where you exploited the *deployed* version of that same misconfiguration.

### 3.3 — Find something new

One finding is about network exposure — a resource type you haven't seen flagged
anywhere else in this course. Find it and explain, in cloud-pentest terms, what a
real attacker would do with it.

### 3.4 — Harder mode: fix it and prove it

Pick one finding, edit the `.tf` file to correct it, and re-run the scanner to
confirm that specific finding no longer appears. This is the step most students skip
in practice — a fix nobody verified is a fix nobody can be sure worked.

## 4. Tools you'll want

- `checkov` or `tfsec` (either; your instructor may have a preference)
- A text editor for 3.4

## 5. Deliverable: IaC Findings & Remediation

| Finding | Severity (per tool) | Matches a live finding from earlier in the course? | Remediated? |
|---|---|---|---|
| | | | |

**Flags found:**

- [ ] Flag 1 (S3 public-access finding): `flag{________________________________}`
- [ ] Flag 2 (IAM wildcard-action finding): `flag{________________________________}`
- [ ] Flag 3 (new — network/security-group exposure finding): `flag{________________________________}`
- [ ] Flag 4 (harder mode — remediated and re-scan confirms clean): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — where flag values live in the .tf files</summary>

Check resource-level `tags`/`Tags` blocks in the Terraform source — some carry more
than just a `Name`.
</details>

<details>
<summary>Hint 2 — the network-exposure resource type</summary>

Look for an `aws_security_group` resource with an ingress rule allowing port 22 from
`0.0.0.0/0` — a textbook finding in IaC scans, and directly relevant to everything
you did in Module 5 with bastion/jump-host access.
</details>

<details>
<summary>Hint 3 — how to prove remediation</summary>

Narrow the offending `cidr_blocks` value to something specific rather than
`0.0.0.0/0`, save, and re-run the exact same scan command — the finding should
disappear from the output entirely.
</details>

## 7. Known limitations

This lab is entirely static analysis — no Terraform `apply`, no live cloud resources
involved, no need for any credentials at all.

## 8. Next up

Lab 5 — the capstone — pulls everything from Modules 3 through 6 together into one
continuous engagement, ending in a client-ready report.
