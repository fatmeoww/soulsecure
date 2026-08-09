# Module 3 — Lab 4: Backup Portal & Secrets in Backups

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 3: Initial Access & Storage Exploitation
**Target:** SoulSecure Inc. (simulated engagement, continued)
**Target host:** `https://backup-eu.soulsecure.lab/`
**Estimated time:** 75–100 minutes

---

## 1. Recap & scenario

Module 2 Lab 1 found `backup-eu.soulsecure.lab` and grabbed one flag from its landing
page comment. You never went further — it was clearly some kind of backup portal, and
recon scope didn't cover logging into anything.

Backup systems are an underrated initial-access target in real engagements: they
exist specifically to hold copies of everything sensitive, they're often run by a
smaller/less-monitored team than production, and — as you're about to find —
password policy discipline tends to be the first thing that slips.

> **Scope reminder:** `backup-eu.soulsecure.lab` only.

## 2. Learning objectives

- Recognize and exploit weak/guessable password patterns behind an authenticated
  portal (not a leaked-credentials-file shortcut this time — you have to guess)
- Extract and correctly read multiple backup archive formats: plaintext config,
  cloud-provider service-account JSON, and a raw `.git` history dump
- Understand why secrets removed from a repo's current files can still be fully
  recoverable from its commit history
- Recognize password-reuse/pattern-reuse across systems as a distinct, very common
  real-world weakness

## 3. Tasks

### 3.1 — Get past the login

`/files/` requires HTTP Basic authentication. This organization's password habits
have been consistently weak throughout this engagement — try combining a plausible
operations-team username with a plausible weak password (year + punctuation is a very
common real-world pattern; you've seen SoulSecure lean on "-eu" as a naming
convention before, that's a hint about the username too).

```bash
curl -sk -u '<username>:<password>' https://backup-eu.soulsecure.lab/files/
```

### 3.2 — See what's there

Once authenticated, list the available backup archives and pull each one down.

```bash
curl -sk -u '<username>:<password>' https://backup-eu.soulsecure.lab/files/<archive> -o <archive>
```

### 3.3 — Extract and read: the plaintext config backup

Start with the one that sounds like a standard web app backup. Extract it and look
for anything that shouldn't be in plaintext.

```bash
tar -xzf web-prod-<date>.tar.gz
```

### 3.4 — Extract and read: the service-account key

SoulSecure isn't pure-AWS (you already knew this from Module 2's GCS bucket). Pull
the archive that sounds like it holds a cloud service-account key and see what
provider it's for and what it's scoped to.

### 3.5 — Mine the git history

One of the archives is a raw source-code backup — including its full `.git`
directory, not just a snapshot of the files. Extract it, and instead of just reading
what's there *now*, look at what used to be there:

```bash
tar -xzf <git-archive>.tar.gz
cd <extracted-dir>
git log --all --oneline
git log -p --all   # or target a specific old commit once you spot it
```

A secret that was "removed" in a later commit is still sitting in the history unless
someone rewrote it — most orgs never do.

### 3.6 — Harder mode: the encrypted one

One archive is a password-protected zip. There's no leaked-file shortcut for this
one, but there's a pattern hint sitting in the file listing itself — read `notes.txt`
if it's there, and think about what you already know about how this organization
constructs passwords.

## 4. Tools you'll want

- `curl` with HTTP Basic auth (`-u user:pass`)
- `tar` to extract `.tar.gz` archives
- `git log` / `git show` / `git log -p` for history mining
- `unzip` (with `-P <password>` once you have one) for the encrypted archive

## 5. Deliverable: Backup Exposure Findings

| Archive | Format | Secret(s) found | How it was hidden/protected |
|---|---|---|---|
| | | | |

**Flags found:**

- [ ] Flag 1 (plaintext config backup): `flag{________________________________}`
- [ ] Flag 2 (GCP-style service-account JSON): `flag{________________________________}`
- [ ] Flag 3 (removed-from-HEAD secret, found via git history): `flag{________________________________}`
- [ ] Flag 4 (harder mode — encrypted archive, password-pattern reuse): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — portal credentials</summary>

Username follows the same regional-team convention as the `-eu` bucket/hostname
naming you've seen all engagement (think "operations, EU region"). Password: a common
year-plus-punctuation pattern for this year's rotation.
</details>

<details>
<summary>Hint 2 — which archive has the git history</summary>

Look for a filename that sounds like a full site/source backup rather than a database
or config dump — that's the one with `.git/` inside it.
</details>

<details>
<summary>Hint 3 — finding the right commit</summary>

`git log --all --oneline` will show a commit message that sounds like it's removing
or rotating something. Check that commit's diff (`git show <hash>`) and, importantly,
the commit *before* it, where the secret was still present.
</details>

<details>
<summary>Hint 4 — the encrypted zip's password</summary>

If the portal login password follows a "word + this-year + punctuation" pattern,
what would *last* year's version of that same pattern have been? Try that against the
zip.
</details>

## 7. Known limitations

The `.git` history in the archive is a real, small git repository prepared once at
build time (not dynamically generated) — `git log`/`git show` work exactly as they
would against a real repo. The rest of the portal (auth, file listing) is a
hand-rolled Flask app, not a real file-server product.

## 8. Next up

Lab 5 (VPN Gateway Exploitation) closes out Module 3 with `vpn.soulsecure.lab` — by
this point you'll be bringing a growing pile of leaked usernames/password patterns
with you, and this lab is where you find out whether SoulSecure reused any of them
somewhere even more consequential.
