# Module 6 — Lab 3: Secret-Scanning & Credential Hunting at Scale — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Reuses
> Module 3 Lab 4's `site-src-backup` git repo as-is. Flag values below are
> placeholders generated at planning time.

## Reused asset: `site-src-backup` (Module 3 Lab 4, unchanged)

No changes needed — the existing 3-commit repo (add Stripe key → remove it) already
gives real tools a genuine, unmodified history-mining target. Running `trufflehog
git file://./site-src-backup` against it should surface the same
`sk_live_FAKE_soulsecure_...` value from Module 3 Lab 4 automatically. Response
should be treated as confirming **Flag 1** — `flag{99440dacd1c5df1c1cb37b53288f41da}`
(delivered as a companion text file `EXPECTED-FINDINGS.txt` alongside the archive, or
via instructor-verified submission — trufflehog itself won't print course flag
strings, see Lab 2's note on non-embedded flag mechanics for tool-output-driven labs).

## New asset: `soulsecure-webapp-dump.tar.gz`

A prepared (not git-history-based, plain file tree) source dump, to build once:

```
soulsecure-webapp-dump/
├── config/
│   └── deploy.conf        <- contains the base64-encoded secret (Flag 2)
├── tests/fixtures/
│   └── aws_example.env    <- contains the well-known AWS example key AND a real-looking DB password (Flag 3)
└── ... (assorted boring source files for volume/realism)
```

**`config/deploy.conf`:**
```
# deployment webhook config
WEBHOOK_TOKEN_B64=ZmxhZ3sxMmRmMGQxODgyMmQxZDY3MTdhYTQxYmQwNjQwNzIyMn0=
```
Base64-decodes to `flag{12df0d18822d1d6717aa41bd06407222}` directly — **Flag 2**.
(Real secret-scanning tools' entropy/pattern detectors flag base64-looking blobs
even without knowing they decode to something readable — the exercise is finding
and decoding it, not the tool doing the decoding for you.)

**`tests/fixtures/aws_example.env`:**
```
# Test fixture -- DO NOT use in production
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
DB_PASSWORD=Tr0ub4dor-Staging-2026
```
`AKIAIOSFODNN7EXAMPLE` / `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` are AWS's own
real, famous, publicly-documented placeholder values (used across AWS's official
docs/SDK examples) — genuinely non-functional, **correctly excludable** as a false
positive by anyone who recognizes the exact string. `DB_PASSWORD` on the line right
below, however, is a real-looking, distinct value with no such public-documentation
status — the correct triage is "AWS key = ignore, `DB_PASSWORD` = real finding."
Reporting `DB_PASSWORD` correctly (and the AWS key as excluded, with reasoning)
earns **Flag 3** — `flag{32dbc1d785d1d9a11d6a93f77e3f0eca}` (again, submission/
instructor-verified — see Lab 2's flag-mechanics note).

## Harder mode: deep/combined scan

Prepare one more, more obscure planted secret for the "scan everything combined"
exercise — e.g. embedded in a small binary file (a PNG's EXIF/metadata field, or
appended after valid image data) inside `soulsecure-webapp-dump/assets/`, findable
via `trufflehog filesystem --include-detectors=all` or gitleaks with binary scanning
enabled. Decoding/finding it yields **Flag 4** —
`flag{25ee7fa4ece475253ec07dd7d82e8c2d}`.

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `site-src-backup` git history (reused from M3 Lab 4) — automated confirmation | `flag{99440dacd1c5df1c1cb37b53288f41da}` |
| Flag 2 | `soulsecure-webapp-dump/config/deploy.conf`, base64-decoded | `flag{12df0d18822d1d6717aa41bd06407222}` |
| Flag 3 | Correct triage of `tests/fixtures/aws_example.env` (real `DB_PASSWORD` vs. fake AWS example key) | `flag{32dbc1d785d1d9a11d6a93f77e3f0eca}` |
| Flag 4 (harder mode) | Secret embedded in a binary asset, found via deep/combined scan | `flag{25ee7fa4ece475253ec07dd7d82e8c2d}` |

## Verification commands (once built)

```bash
trufflehog git file://./site-src-backup --only-verified=false | grep -i stripe

gitleaks detect --source ./soulsecure-webapp-dump --no-git -v | grep -A2 WEBHOOK_TOKEN_B64
echo 'ZmxhZ3sxMmRmMGQxODgyMmQxZDY3MTdhYTQxYmQwNjQwNzIyMn0=' | base64 -d

cat soulsecure-webapp-dump/tests/fixtures/aws_example.env

trufflehog filesystem ./combined-scan-dir --include-detectors=all
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Ran trufflehog/gitleaks against `site-src-backup` and confirmed automated detection | 20 |
| Found and correctly decoded the base64 secret in `deploy.conf` | 25 |
| Correctly excluded the AWS example key **and** correctly reported `DB_PASSWORD` as real | 25 |
| Completed the combined deep scan and found the binary-embedded secret | 20 |
| Clean, accurate findings table distinguishing real from false-positive results | 10 |

## Design notes / narrative threads

- Placing a real AWS-documented placeholder key directly beside a genuinely
  sensitive value is the lab's central lesson: **triage requires knowing what a
  known-safe value looks like**, not just running a scanner and reporting everything
  it flags. A student who reports the AWS example key as a critical finding hasn't
  actually done a security review, just run a tool.
- Reusing `site-src-backup` unmodified (rather than building a new repo) keeps this
  lab's setup cost low and reinforces the "same source material, better tooling"
  framing that defines Module 6.

## File locations (proposed)

- `/opt/soulsecure-labs/module6/soulsecure-webapp-dump/` (new, static file tree,
  built once, not dynamically generated)
- Existing `site-src-backup` archive from Module 3 Lab 4 — reused via a copy or
  shared reference, no changes.

## Known limitations

Tool output format/verbosity varies by trufflehog/gitleaks version — pin versions at
build time and verify the exact commands above still surface the intended findings
before shipping this lab.
