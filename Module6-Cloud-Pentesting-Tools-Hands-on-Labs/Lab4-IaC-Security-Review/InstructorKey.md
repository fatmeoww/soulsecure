# Module 6 — Lab 4: Infrastructure-as-Code (IaC) Security Review — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Pure
> static-file lab — no live infrastructure dependency on any other module. Flag
> values below are placeholders generated at planning time.

## New asset: `soulsecure-terraform/` (static files, build once)

```
soulsecure-terraform/
├── s3.tf          <- public bucket, matches Module 3 Lab 1
├── iam.tf          <- wildcard policy, matches Module 4 Lab 1-3
├── network.tf      <- SSH-open-to-world security group (new, not seen live anywhere)
└── variables.tf, outputs.tf   <- boilerplate for realism
```

**`s3.tf`:**
```hcl
resource "aws_s3_bucket" "prod_assets" {
  bucket = "soulsecure-prod-assets"
  tags = {
    Environment = "production"
    flag        = "flag{12619665432a3c96437b87c7b96e896d}"   # Flag 1
  }
}

resource "aws_s3_bucket_acl" "prod_assets_acl" {
  bucket = aws_s3_bucket.prod_assets.id
  acl    = "public-read"   # <- the finding
}
```

**`iam.tf`:**
```hcl
resource "aws_iam_policy" "legacy_broad" {
  name        = "LegacyBroadPolicy"
  description = "flag{c3ae4b3c35750c5b136829cceed7b10d}"       # Flag 2
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]   # <- the finding
  })
}
```

**`network.tf`:**
```hcl
resource "aws_security_group" "bastion_sg" {
  name = "bastion-access"
  tags = {
    flag = "flag{97f409cf01cab031eb48dbc42c86ec95}"            # Flag 3
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # <- the finding: SSH open to the entire internet
  }
}
```

## Remediation/re-scan flag (harder mode)

Flag 4 is **not** a static value embedded in the repo — it's earned by the student's
own edit. Deliver it via an instructor-side verification script (or a companion
`check-remediation.sh` the student runs themselves) that:
1. Re-runs `checkov`/`tfsec` against the student's edited `network.tf`
2. Confirms the SSH-open-to-world finding no longer appears
3. Confirms `cidr_blocks` was narrowed to something other than `0.0.0.0/0` (not just
   deleted or commented out — must still define a working, scoped rule)
4. On success, prints `flag{8151a3e59ed6cc9709a8f5c910b51ec3}`

```bash
#!/bin/bash
# check-remediation.sh
if grep -q '0.0.0.0/0' network.tf; then
  echo "Still open to the world -- not remediated."
  exit 1
fi
if ! grep -q 'cidr_blocks' network.tf; then
  echo "Rule removed entirely rather than scoped -- not a real fix."
  exit 1
fi
echo "Remediated correctly. flag{8151a3e59ed6cc9709a8f5c910b51ec3}"
```

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `s3.tf`, `aws_s3_bucket.prod_assets` tags | `flag{12619665432a3c96437b87c7b96e896d}` |
| Flag 2 | `iam.tf`, `aws_iam_policy.legacy_broad` description | `flag{c3ae4b3c35750c5b136829cceed7b10d}` |
| Flag 3 | `network.tf`, `aws_security_group.bastion_sg` tags | `flag{97f409cf01cab031eb48dbc42c86ec95}` |
| Flag 4 (harder mode) | `check-remediation.sh` after correctly editing `network.tf` | `flag{8151a3e59ed6cc9709a8f5c910b51ec3}` |

## Verification commands (once built)

```bash
checkov -d ./soulsecure-terraform --compact
tfsec ./soulsecure-terraform

grep flag ./soulsecure-terraform/s3.tf        # Flag 1
grep flag ./soulsecure-terraform/iam.tf        # Flag 2
grep flag ./soulsecure-terraform/network.tf    # Flag 3

# after student edits network.tf:
./check-remediation.sh                          # Flag 4
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Ran the scanner and produced a findings list | 15 |
| Correctly mapped the S3 finding to Module 3 Lab 1 | 20 |
| Correctly mapped the IAM finding to Module 4 | 20 |
| Identified the security-group finding as new/network-specific and explained its risk | 20 |
| Correctly remediated `network.tf` and confirmed via re-scan | 20 |
| Clean findings table | 5 |

## Design notes / narrative threads

- `network.tf`'s SSH-open-to-world finding is **new** to the course on purpose —
  every other Module 6 lab reuses established story beats; this one demonstrates the
  IaC-review workflow catching something the live/manual portion of the engagement
  never happened to surface, reinforcing that static analysis and live testing find
  overlapping but not identical issues.
- The remediation step (3.4/Flag 4) is the only place in Module 6 where a student's
  own edit — not just their investigation — is directly what earns the flag,
  matching this lab's "complete the loop, don't just detect" objective.

## File locations (proposed)

- `/opt/soulsecure-labs/module6/soulsecure-terraform/` (new, static Terraform files)
- `/opt/soulsecure-labs/module6/check-remediation.sh` (new)

## Known limitations

checkov/tfsec finding IDs and exact severity labels vary by tool/version — verify
the specific check IDs relevant to these three resources are actually triggered by
whichever tool/version ships in the final build, and pin versions.
