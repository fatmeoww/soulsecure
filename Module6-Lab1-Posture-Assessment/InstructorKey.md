# Module 6 — Lab 1: Automated Cloud Security Posture Assessment — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. This
> file also establishes the **LocalStack architecture decision for all of Module 6
> Labs 1–2** — Lab 2's InstructorKey references back to this seeding rather than
> redefining it. Flag values below are placeholders generated at planning time.

## Architecture decision: LocalStack, not the story-based Flask mocks

Modules 3–5's hand-rolled Flask services (`iam-sim`, `storage`, etc.) are explicitly
**not** real-AWS-API-compatible (documented in every one of their InstructorKeys'
Known Limitations) — a deliberate simplification that worked fine for teaching
mechanics by hand, but is fundamentally incompatible with pointing real tools
(Prowler, ScoutSuite, Pacu, the real `aws` CLI) at them without those tools
completely failing on request signing/response parsing.

**Resolution:** stand up a **separate, parallel** `localstack` container for Module 6
Labs 1–2 only, seeded via a one-time boto3/`awslocal` script with resources that
mirror the *same misconfiguration story* as Modules 3–5, independently. This is not
the same backend — it's a deliberate re-creation, real-API-shaped, so genuine tools
work unmodified. Labs 3–4 (secret scanning, IaC review) don't need this — they
operate on static files, not a live API.

## LocalStack seed script (ground truth to implement)

Run once at container start (or via a `labctl module6-seed` helper):

```python
# Buckets
s3.create_bucket(Bucket="soulsecure-public-assets")
s3.put_bucket_acl(Bucket="soulsecure-public-assets", ACL="public-read")
s3.put_bucket_tagging(Bucket="soulsecure-public-assets", Tagging={"TagSet":[
  {"Key":"flag","Value":"flag{2361eeb8da89a1b0cfed7791affb0d00}"}]})   # Flag 1

s3.create_bucket(Bucket="soulsecure-internal-logs")   # private, no finding — noise/control

# IAM policy with wildcard action
iam.create_policy(PolicyName="LegacyBroadPolicy", PolicyDocument=json.dumps({
  "Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}),
  Description="flag{87710d4e5d946788aa34f19227db1293}")               # Flag 2
iam.create_user(UserName="svc-legacy-app")
iam.attach_user_policy(UserName="svc-legacy-app", PolicyArn="<LegacyBroadPolicy ARN>")

# Role with overly permissive trust policy
iam.create_role(RoleName="soulsecure-shared-role", AssumeRolePolicyDocument=json.dumps({
  "Version":"2012-10-17","Statement":[{"Effect":"Allow",
    "Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}),
  Tags=[{"Key":"flag","Value":"flag{86874cf9925295682b701ab1a6c34fc8}"}])   # Flag 3

# Noise: a batch of low-severity findings so the report isn't trivially short
for i in range(6):
    iam.create_user(UserName=f"svc-noise-{i}")
    # deliberately mundane: no MFA, unused for 90+ days simulated via CreateDate, etc.
```

`Flag 3` on `soulsecure-shared-role`'s **trust policy** (`Principal: {"AWS": "*"}` —
*any* AWS account, not just this one) is deliberately more severe than
`LegacyBroadPolicy`'s attachment — this is **Flag 4**'s answer: it's the finding a
student should identify as "the one that matters most," because an
externally-assumable role with no restriction is a far more direct path to
compromise than an overly broad policy that still requires a foothold inside the
account first.

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `soulsecure-public-assets` bucket tag, surfaced in scanner report detail view | `flag{2361eeb8da89a1b0cfed7791affb0d00}` |
| Flag 2 | `LegacyBroadPolicy` policy description | `flag{87710d4e5d946788aa34f19227db1293}` |
| Flag 3 | `soulsecure-shared-role` trust-policy tag | `flag{86874cf9925295682b701ab1a6c34fc8}` |
| Flag 4 (harder mode) | Correctly identifying `soulsecure-shared-role` (not `LegacyBroadPolicy`) as the critical finding — graded via deliverable reasoning, same value as Flag 3 accepted as confirmation | `flag{9f113bf4928fab55f48e37d956f55b80}` |

## Verification commands (once built)

```bash
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url=http://<TARGET_IP>:4566 sts get-caller-identity

aws --endpoint-url=http://<TARGET_IP>:4566 s3api get-bucket-tagging --bucket soulsecure-public-assets   # Flag 1
aws --endpoint-url=http://<TARGET_IP>:4566 iam get-policy --policy-arn <LegacyBroadPolicy-ARN>           # Flag 2
aws --endpoint-url=http://<TARGET_IP>:4566 iam list-role-tags --role-name soulsecure-shared-role         # Flag 3

prowler aws --endpoint-url http://<TARGET_IP>:4566 -M html,json
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Successfully configured CLI/tool against the LocalStack endpoint | 10 |
| Ran the scanner and produced a report | 15 |
| Correctly extracted all three tagged/described findings | 30 |
| Correctly triaged `soulsecure-shared-role` as the highest-severity finding, with sound reasoning | 30 |
| Clean comparison table connecting scanner output to earlier modules' manual findings | 15 |

## Design notes / narrative threads

- Noise users (`svc-noise-0..5`) exist purely so the report isn't a 4-line trivial
  list — real posture-assessment tools routinely surface dozens to hundreds of
  low-severity findings, and learning to filter is part of the point.
- `soulsecure-shared-role`'s `Principal: "*"` (any AWS account, not just this one)
  vs. Module 4 Lab 4's `soulsecure-finance-role` (any principal in the *same*
  account) is a deliberate escalation in severity between the two modules —
  Module 6 should feel like it's raising the stakes, not repeating Module 4.

## File locations (proposed)

- `docker-compose.yml` — add `localstack` service (official `localstack/localstack`
  image), Module 6-only network/profile so it doesn't interfere with Modules 3–5's
  stack.
- `/opt/soulsecure-labs/module6/seed_localstack.py` (new) — the script above,
  idempotent (safe to re-run), callable via a `labctl module6-seed` helper.

## Known limitations

LocalStack's free/community edition covers S3 and IAM well enough for this lab;
double-check at build time that the specific Prowler/ScoutSuite checks this lab
relies on don't require LocalStack Pro features. If they do, either seed a narrower
set of checks the community edition supports, or budget for LocalStack Pro in the
deployment.
