# Module 3 — Lab 4: Backup Portal & Secrets in Backups — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Flag
> values below are placeholders generated at planning time.

Extends the existing `backup-eu` vhost (M2 Lab 1's flag-in-comment landing page,
served via the `www` gateway per M2's access architecture) with an HTTP-Basic-gated
`/files/` listing and four downloadable archives, three generated at build time and
one hand-prepared (the git-history one).

## Portal auth (ground truth)

- HTTP Basic Auth on `/files/` and everything under it. Realm string:
  `SoulSecure Backup Portal (EU)`.
- Valid credentials: `ops-eu` / `Backup2025!`
- No lockout/rate-limiting (matches the course's established "everything
  overexposed" misconfiguration theme) — a short guided wordlist is enough, no need
  for real brute-force tooling.

## File listing (`GET /files/`, once authenticated)

```
web-prod-2026-06-01.tar.gz
gcp-sa-key-backup.tar.gz
site-src-backup.tar.gz
board-backup-encrypted.zip
notes.txt
```

## Archive contents (ground truth, to prepare at build time)

### `web-prod-2026-06-01.tar.gz`
```
config/app.env
```
```
DB_HOST=orders-db.internal.soulsecure.lab
DB_USER=webapp
DB_PASSWORD=Pr0d-DB-2026!
SESSION_SECRET=<random>
# rotate after Q2 audit -- flag{6796919a876d9d47a3d93400609d00bd}
```
**Flag 1.** `DB_HOST` deliberately reuses the same fake internal hostname from M2 Lab
3's verbose error (`orders-db.internal.soulsecure.lab`, doesn't resolve — same
red-herring hostname, now with plaintext creds attached to it; still no live service
behind it, this is about the credential leak, not standing up that host).

### `gcp-sa-key-backup.tar.gz`
```
service-account.json
```
```json
{
  "type": "service_account",
  "project_id": "soulsecure-prod",
  "private_key_id": "a1b2c3d4e5f6",
  "private_key": "-----BEGIN PRIVATE KEY-----\n<placeholder, syntactically valid PEM shape>\n-----END PRIVATE KEY-----\n",
  "client_email": "ci-backup@soulsecure-prod.iam.gserviceaccount.com",
  "client_id": "109876543210",
  "flag": "flag{05cfcd81a9d9e2e1eda009b24cc726ea}"
}
```
**Flag 2.** First GCP-flavored credential in the course (Module 2 only fingerprinted
a GCS bucket by URL shape; this is the first actual GCP-shaped identity) — good
diversity input for Module 4, which shouldn't be AWS-only.

### `site-src-backup.tar.gz`
A real, small git repository (prepare once, tar it with `.git/` included). All
commits authored by `James Ops <j.ops@soulsecure.lab>` — matches `notes.txt`'s "-- J"
signature, and **feeds forward into Lab 5** (VPN portal username):

- Commit 1: initial site scaffold, no secrets
- Commit 2 (`add stripe integration`): adds `payments/config.py` containing
  `STRIPE_API_KEY = "sk_live_FAKE_soulsecure_..."` in plaintext
- Commit 3 (`security: remove hardcoded key, use env var`): removes the hardcoded
  line from `payments/config.py`, replaces with `os.environ["STRIPE_API_KEY"]` — the
  file at `HEAD` is clean
- Commit 3's message body (or a code comment in the diff context) includes
  `flag{0e9d24f17137d08f3cd6523f2121e961}` — **Flag 3**, only visible via
  `git show <commit-2-or-3-hash>` / `git log -p`, never in a checkout of `HEAD`

### `board-backup-encrypted.zip` (harder mode)
Password-protected (standard zip encryption is fine — this isn't a crypto lesson).
Password: `Backup2024!` (same pattern as the portal login `Backup2025!`, prior year).
Contents once decrypted: `board-notes-summary.txt` with
`flag{e7418d9f10280b0033b0ea4f2e8798c6}` — **Flag 4**.

### `notes.txt` (unauthenticated-adjacent hint file, still behind Basic Auth)
```
Reminder from ops: encrypted archives use last year's portal password convention.
Don't ask me why we haven't standardized this. -- J
```

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `web-prod-2026-06-01.tar.gz` → `config/app.env` | `flag{6796919a876d9d47a3d93400609d00bd}` |
| Flag 2 | `gcp-sa-key-backup.tar.gz` → `service-account.json` | `flag{05cfcd81a9d9e2e1eda009b24cc726ea}` |
| Flag 3 | `site-src-backup.tar.gz` git history, commit adding/removing `STRIPE_API_KEY` | `flag{0e9d24f17137d08f3cd6523f2121e961}` |
| Flag 4 (harder mode) | `board-backup-encrypted.zip` (password `Backup2024!`) → `board-notes-summary.txt` | `flag{e7418d9f10280b0033b0ea4f2e8798c6}` |

## Verification commands (once built)

```bash
curl -sk -u 'ops-eu:Backup2025!' https://backup-eu.soulsecure.lab/files/
curl -sk -u 'ops-eu:Backup2025!' https://backup-eu.soulsecure.lab/files/web-prod-2026-06-01.tar.gz -o a.tar.gz
tar -xzf a.tar.gz && cat config/app.env                                                    # Flag 1

curl -sk -u 'ops-eu:Backup2025!' https://backup-eu.soulsecure.lab/files/gcp-sa-key-backup.tar.gz -o b.tar.gz
tar -xzf b.tar.gz && cat service-account.json                                              # Flag 2

curl -sk -u 'ops-eu:Backup2025!' https://backup-eu.soulsecure.lab/files/site-src-backup.tar.gz -o c.tar.gz
tar -xzf c.tar.gz && cd site-src-backup && git log --all --oneline && git log -p --all | grep -i stripe   # Flag 3

curl -sk -u 'ops-eu:Backup2025!' https://backup-eu.soulsecure.lab/files/board-backup-encrypted.zip -o d.zip
unzip -P 'Backup2024!' d.zip && cat board-notes-summary.txt                                # Flag 4
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Correctly guessed portal credentials via pattern reasoning (not brute-force-tool-only) | 15 |
| Extracted and read the plaintext config backup | 15 |
| Extracted and correctly identified the GCP service-account key and its scope/purpose | 15 |
| Mined git history successfully and found the removed secret (not just checked `HEAD`) | 25 |
| Decrypted and read the encrypted archive via password-pattern reasoning | 20 |
| Clean deliverable table, correctly distinguishing "protected" vs. "actually protected" secrets | 10 |

## Design notes / narrative threads

- `ops-eu` / `Backup2025!` and the zip's `Backup2024!` are deliberately guessable
  *without* a leaked-file shortcut — Module 3's other labs mostly hand students a
  leaked secret to find; this lab specifically wants students to practice reasoning
  about weak human-chosen patterns instead.
- The git-history secret (Flag 3) directly foreshadows Module 6 Lab 3
  (secret-scanning at scale / git-history mining with tooling like trufflehog) — this
  is the "do it by hand once" version of that later automated lab.
- `DB_HOST=orders-db.internal.soulsecure.lab` reusing M2 Lab 3's non-resolving
  red-herring hostname is intentional continuity, not a new asset to stand up.

## File locations (proposed)

- Wherever the M2 `backup-eu` static content currently lives — add `/files/` route +
  Basic Auth check + the four archive files as static assets.
- The git-history archive needs to be **hand-prepared once** (create the repo, make
  the three commits, `tar` it including `.git/`) and committed as a build asset —
  not generated dynamically at container start.

## Known limitations

- Standard zip-encryption strength is intentionally weak/irrelevant here — this
  isn't a cryptography exercise, the password is meant to be reasoned out, not
  cracked.
- The GCP service-account private key is a syntactically-valid-looking placeholder,
  not a real key — don't expect it to work with real `gcloud`/`google-auth` tooling.
