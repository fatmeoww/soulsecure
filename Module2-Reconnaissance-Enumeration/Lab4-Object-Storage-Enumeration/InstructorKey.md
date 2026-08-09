# Module 2 — Lab 4: Object Storage Enumeration — Instructor Key

Runs on the **same target host** as Labs 1–3. This lab only extends
`/opt/soulsecure-labs/apps/storage_app.py` (the `storage` container). **Access
changed** since the harder-mode rework: `storage` is no longer published on port 8081
— it's reverse-proxied through the `www` nginx container at
`https://storage.soulsecure.lab/` only (see Lab 1 InstructorKey's "Access
architecture" section). All `LAB_LEVEL` gating below is unchanged, still enforced
inside the Flask app itself. The bare `/` response (Lab 1's fingerprint) is unaffected.

## Bucket registry (ground truth)

### S3-style (`/<bucket>/<key>`)

| Bucket | Exists? | Public? | HTTP for `GET /<bucket>/` | Objects | Notes |
|---|---|---|---|---|---|
| `soulsecure-prod-assets` | Yes | Yes | 200 + listing | `README.txt`, `logo.png`, `config/backup-2026-07-01.json` | **Flag 1** in the config JSON |
| `soulsecure-dev-assets` | Yes | **No** | 403 AccessDenied | (none exposed) | Existence-oracle teaching point |
| `soulsecure-staging-assets` | **No** | n/a | 404 NoSuchBucket | n/a | Negative control |
| `soulsecure-backups-eu` | Yes | Yes | 200 + listing | `db-snapshot-notes.txt` | **Flag 2** |
| `soulsecure-terraform-state` | Yes | Yes | 200 + listing | `terraform.tfstate` | **Flag 3** |

### GCS-style (`/storage/v1/b/<bucket>/o[...]`, harder-mode addition)

| Bucket | Exists? | Public? | Objects | Notes |
|---|---|---|---|---|
| `soulsecure-gcs-assets` | Yes | Yes | `notes/migration-plan.txt` | **Flag 4** |

Any other bucket name a student tries returns `404 NoSuchBucket` /
`{"code":404,...}` — the Flask app's `BUCKETS` / `GCS_BUCKETS` dicts are the single
source of truth (`apps/storage_app.py`).

## Flags (ground truth)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `GET /soulsecure-prod-assets/config/backup-2026-07-01.json` | `flag{c3909083d936385564ffe54a86c340b9}` |
| Flag 2 | `GET /soulsecure-backups-eu/db-snapshot-notes.txt` | `flag{bb244e7d9025c5600bdc019ad5c726dc}` |
| Flag 3 | `GET /soulsecure-terraform-state/terraform.tfstate` | `flag{e21e4a4043ae07729741ef42be7dc9af}` |
| Flag 4 (harder-mode) | `GET /storage/v1/b/soulsecure-gcs-assets/o/notes%2Fmigration-plan.txt?alt=media` | `flag{b091f26222ff3e2e245ee90a35927202}` |

## Verification commands

```bash
curl -sk -o /dev/null -w '%{http_code}\n' https://storage.soulsecure.lab/                                    # 403 (Lab 1 fingerprint, unchanged)
curl -sk https://storage.soulsecure.lab/soulsecure-prod-assets/                                                # 200, lists 3 keys
curl -sk https://storage.soulsecure.lab/soulsecure-prod-assets/config/backup-2026-07-01.json                  # Flag 1
curl -sk -o /dev/null -w '%{http_code}\n' https://storage.soulsecure.lab/soulsecure-dev-assets/                # 403 AccessDenied (exists!)
curl -sk -o /dev/null -w '%{http_code}\n' https://storage.soulsecure.lab/soulsecure-staging-assets/            # 404 NoSuchBucket
curl -sk https://storage.soulsecure.lab/soulsecure-backups-eu/db-snapshot-notes.txt                           # Flag 2
curl -sk https://storage.soulsecure.lab/soulsecure-terraform-state/terraform.tfstate                          # Flag 3
curl -sk https://storage.soulsecure.lab/storage/v1/b/soulsecure-gcs-assets/o
curl -sk 'https://storage.soulsecure.lab/storage/v1/b/soulsecure-gcs-assets/o/notes%2Fmigration-plan.txt?alt=media'  # Flag 4
```

## Grading rubric (out of 100)

| Criterion | Points |
|---|---|
| Systematically permuted bucket names from the Lab 1 seed (didn't just get lucky) | 15 |
| Correctly distinguished `NoSuchBucket` vs `AccessDenied` vs `200` and explained why it matters | 15 |
| Retrieved and correctly read the `config/` object from `soulsecure-prod-assets` | 15 |
| Retrieved `soulsecure-backups-eu` content | 10 |
| Found `soulsecure-terraform-state` via permutation (not hinted) and flagged its severity correctly | 15 |
| Recognized the GCS URL pattern and found `soulsecure-gcs-assets` | 20 |
| Clean storage inventory table deliverable | 10 |

## Design notes / narrative threads

- The `config/backup-2026-07-01.json`, `terraform.tfstate`, and the Lab 3
  `/api/internal/debug` disclosure all contain the same placeholder-styled fake AWS
  access key pattern (`AKIAFAKESOULSECURE0x`) — deliberately consistent across labs so
  a student (or you, in class discussion) can point out the org appears to
  reuse/rotate credentials poorly. None of these are functional against anything;
  they're narrative glue for Module 4.
- `soulsecure-dev-assets` (exists, denied) and `soulsecure-staging-assets` (doesn't
  exist) are a matched pair specifically so grading can check whether students
  actually understood the AccessDenied-vs-NoSuchBucket distinction.

## File locations

- `/opt/soulsecure-labs/apps/storage_app.py` — `BUCKETS` dict (S3-style) and
  `GCS_BUCKETS` dict (harder-mode addition) both live at the top of this file; add/edit
  buckets there directly.

## Known limitations

- This is a hand-rolled S3/GCS-*shaped* API (XML/JSON error and list formats mimic the
  real ones closely enough for `curl`/browser-based enumeration), not enough to point
  the real `aws s3` CLI, `gsutil`, or `boto3` at with real signed-request auth.
