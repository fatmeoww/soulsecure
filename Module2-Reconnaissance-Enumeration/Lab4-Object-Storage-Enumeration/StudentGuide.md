# Module 2 — Lab 4: Object Storage Enumeration

**Course:** Cloud Pentest — Module 2: Reconnaissance & Enumeration
**Target:** SoulSecure Inc. (simulated engagement, continued)
**Target:** `https://storage.soulsecure.lab/` (same target host as Labs 1–3 — make
sure your DNS/CA setup from Lab 1 Section 0 is still in place)
**Estimated time:** 60–90 minutes

---

## 1. Recap & scenario

Back in Lab 1, an HTML comment on the SoulSecure marketing site leaked a bucket name:
`soulsecure-prod-assets`, with a TODO to "make it private before GA launch." Nobody did.
This lab is about taking a single leaked bucket name and turning it into a full picture
of an organization's object storage footprint — which is exactly how a huge share of
real cloud breaches start.

> **Scope reminder:** `storage.soulsecure.lab` only. This is recon — reading what's
> publicly exposed. Don't attempt to write, delete, or modify any object.

## 2. Learning objectives

- Enumerate object storage buckets by name permutation from a single leaked seed name
- Distinguish three distinct server responses and know what each one *means*:
  a bucket that **doesn't exist**, a bucket that **exists but you can't access**, and
  a bucket that's **fully open**
- List a public bucket's contents and retrieve individual objects
- Recognize common sensitive file patterns in object storage (config backups,
  Terraform state files, database snapshots) and why each is dangerous if exposed
- Recognize that not everything is AWS — identify a different provider's storage API
  by its URL shape alone
- Document findings the way a real cloud storage exposure finding gets reported

## 3. Tasks

### 3.1 — Confirm the seed

Start from what Lab 1 already gave you:

```bash
curl -sk https://storage.soulsecure.lab/soulsecure-prod-assets/
```

### 3.2 — Permutation / name-guessing

Real organizations are extremely predictable about bucket naming. From one real name,
generate variants and test each one. Common patterns: environment suffixes
(`-dev`, `-staging`, `-prod`), region suffixes (`-eu`, `-us`), purpose suffixes
(`-backups`, `-logs`, `-state`, `-tfstate`), and prefix/company-name variants.

For each guess, note the **HTTP status code and response body** — don't just check
"did it 404." You need all three outcomes:

```bash
for b in soulsecure-prod-assets soulsecure-dev-assets soulsecure-staging-assets \
         soulsecure-backups-eu soulsecure-backups soulsecure-logs \
         soulsecure-terraform-state soulsecure-tfstate; do
  echo "== $b =="
  curl -sk -o /dev/null -w '%{http_code}\n' "https://storage.soulsecure.lab/$b/"
done
```

### 3.3 — Read the error, not just the status code

Pull the raw XML body for a couple of your `403`/`404` results. The `<Code>` element
tells you *why*:

- `NoSuchBucket` → the bucket name doesn't exist at all
- `AccessDenied` → the bucket **exists** but you don't have permission — this is a huge
  finding on its own, because it confirms the org owns that exact name, even with zero
  file access
- `200` + `ListBucketResult` → fully public, list away

### 3.4 — Loot the public buckets

For every bucket that lists successfully, fetch every object key it shows you:

```bash
curl -sk https://storage.soulsecure.lab/<bucket>/<key>
```

Read what you get back like an assessor, not a script kiddie — what's actually
sensitive here, and why?

### 3.5 — Update your inventory

Add a **storage inventory** table (Section 4) covering every bucket name you tested,
whether it exists, whether it's public, and what (if anything) you retrieved.

## 4. Deliverable

| Bucket name | Exists? | Public? | Notable objects | Sensitivity |
|---|---|---|---|---|
| | | | | |

**Flags found** (all live inside object contents — you have to actually read the
files, not just list them):

- [ ] Flag 1 (`soulsecure-prod-assets` object content): `flag{________________________________}`
- [ ] Flag 2 (`soulsecure-backups-eu` object content): `flag{________________________________}`
- [ ] Flag 3 (a bucket you had to guess — not hinted anywhere else in this engagement): `flag{________________________________}`
- [ ] Flag 4 (harder mode — a different cloud provider's storage): `flag{________________________________}`

## 5. Harder mode: not everything is AWS

SoulSecure isn't a pure-AWS shop. Google Cloud Storage's JSON API has a distinctive
URL shape you should learn to recognize on sight:
```
GET https://storage.soulsecure.lab/storage/v1/b/<bucket>/o                       (list)
GET https://storage.soulsecure.lab/storage/v1/b/<bucket>/o/<object>?alt=media    (fetch)
```
Same permutation-guessing discipline as the S3 exercise, same hostname, different URL
pattern, nothing hinting at the bucket name anywhere else in this engagement. If the
object key contains a `/`, URL-encode it as `%2F`.

## 6. Hints

<details>
<summary>Hint 1 — the config file is the point</summary>

`soulsecure-prod-assets` lists three objects. One of them is under a `config/`
"folder" (S3 doesn't really have folders — key prefixes just look like them). That's
the one worth reading closely.
</details>

<details>
<summary>Hint 2 — a whole bucket wordlist worth trying</summary>

`-dev-assets, -staging-assets, -backups, -backups-eu, -logs, -state, -tfstate,
-terraform-state, -assets-eu, -public, -static, -gcs-assets`. Not every suffix will
hit; that's realistic.
</details>

<details>
<summary>Hint 3 — why Terraform state files matter</summary>

If you find a bucket ending in `-state` or `-tfstate`, that's not a random guess
paying off by luck — it's a genuinely common real-world naming convention for
Terraform's remote state backend, and state files routinely contain full
infrastructure secrets in plaintext. Treat finding one as a critical finding in your
report, not a curiosity.
</details>

<details>
<summary>Hint 4 — GCS object keys</summary>

`GET .../o/notes%2Fmigration-plan.txt?alt=media` — the `%2F` matters (it's an encoded
`/`), and so does `?alt=media` (without it you get metadata, not the file content).
</details>

## 7. Next up

Lab 5 (CDN, Origin & Technology Fingerprinting) wraps up Module 2 by identifying what's
sitting in front of these services (CDN/WAF) and confirming the real origin behind it —
tying together everything you've enumerated across Labs 1–4 into one final asset map.
