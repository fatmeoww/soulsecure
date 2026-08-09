# Module 2 — Lab 3: API Reconnaissance

**Course:** Cloud Pentest — Module 2: Reconnaissance & Enumeration
**Target:** SoulSecure Inc. (simulated engagement, continued)
**Target:** `https://api.soulsecure.lab/` (same target host as Labs 1–2 — make sure
your DNS/CA setup from Lab 1 Section 0 is still in place)
**Estimated time:** 60–90 minutes

---

## 1. Recap & scenario

Lab 2's `internal-tools` vhost dropped a hint: *"internal API base: `/api/internal/`"*.
Time to take `api.soulsecure.lab` seriously. Cloud-native apps are usually a thin
frontend in front of a REST (and sometimes GraphQL) API — and APIs leak far more than
websites do, because developers assume "nobody's looking, it's just for our frontend."

> **Scope reminder:** `api.soulsecure.lab` (and the rest of the previously-scoped
> hosts) only. This lab is recon — you're **finding and documenting** endpoints, not
> exploiting them. Don't attempt auth bypass, injection, or data modification here;
> that's later modules.

## 2. Learning objectives

- Discover REST API endpoints via wordlists, spec files, and response analysis
- Find and read machine-readable API specs (OpenAPI/Swagger) and recognize when they
  leak more than intended
- Detect undocumented API versions through systematic version-number probing
- Recognize verbose/debug error output as an information-disclosure finding
- Use GraphQL introspection to enumerate a schema and query fields that shouldn't be
  publicly reachable
- Document API attack surface the way a real assessment report would

## 3. Tasks

### 3.1 — Find the API spec

Many APIs expose a machine-readable spec at a predictable path. Try the common ones:

```bash
curl -sk https://api.soulsecure.lab/openapi.json
curl -sk https://api.soulsecure.lab/swagger.json
curl -sk https://api.soulsecure.lab/api-docs
```

Read whatever comes back carefully — specs list *every* path the developer told the
spec generator about, including ones they probably shouldn't have.

### 3.2 — Enumerate documented endpoints

Walk every path the spec lists. Note the HTTP methods, parameters, and what each one
returns.

### 3.3 — Chase the one path that looks wrong

One entry in the spec has a summary that reads like an internal note, not API
documentation. That's not an accident. Go visit it.

### 3.4 — Look for versions the spec doesn't mention

APIs evolve. If you see `/api/v1/...` anywhere, ask yourself: is there a `v2`? A `v0`?
Try incrementing/decrementing the version segment and see what happens. (The spec you
pulled in 3.1 only documents one version.)

Don't skip `/api/v1/status` while you're enumerating documented endpoints in 3.2 —
read its response carefully. It's telling you something about where this API is
headed, which is exactly the kind of detail that turns "randomly guess a version
number" into "there's a specific reason to look for v2."

### 3.5 — Break something (gently) and read the error

Real input validation gaps are everywhere. Try sending an endpoint a parameter value
of the *wrong type* (e.g. text where a numeric ID is expected) and look closely at
what comes back on a `500`. Verbose error handlers routinely leak file paths, stack
traces, internal hostnames, and connection strings — all useful recon even without
triggering the actual bug the error represents.

### 3.6 — Update your asset inventory

Add an **API endpoint inventory** as its own section: method, path, auth required
(yes/no/unknown), and what it discloses.

## 4. Deliverable

**API endpoint inventory** (new table):

| Method | Path | Documented? | Auth required? | Notable disclosure |
|---|---|---|---|---|
| | | | | |

**Flags found:**
- [ ] Flag 1 (spec leaked an internal-only path): `flag{________________________________}`
- [ ] Flag 2 (undocumented API version): `flag{________________________________}`
- [ ] Flag 3 (verbose error disclosure): `flag{________________________________}`
- [ ] Flag 4 (harder mode — GraphQL): `flag{________________________________}`

## 5. Harder mode: GraphQL

Not every API is REST, and `/openapi.json` won't tell you about a GraphQL endpoint
even if one exists — the two are separate standards, and plenty of real orgs document
one and not the other. Guess common paths: `/graphql`, `/api/graphql`, `/gql`.

Once found, use a standard introspection query to list what's queryable:
```bash
curl -sk https://api.soulsecure.lab/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name}}}}"}'
```
(Don't forget the `Content-Type` header — a lot of servers, this one included, will
silently ignore the body without it.) One field in the response has a description
that reads like an internal warning, not documentation. Query it directly the same
way:
```bash
curl -sk https://api.soulsecure.lab/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{<field-name-you-found>}"}'
```

## 6. Hints

<details>
<summary>Hint 1 — where's the spec</summary>

You don't need a wordlist for this one — `/openapi.json` is live and gives you
everything you need for section 3.1 in one request.
</details>

<details>
<summary>Hint 2 — which path looks like a note-to-self</summary>

Look for a `summary` field that reads like an internal comment ("remove before...",
"do not document..." ) rather than user-facing API documentation. That's the tell.
</details>

<details>
<summary>Hint 3 — versions</summary>

Every documented path starts with `/api/v1/`. Try `/api/v2/status` — same shape as an
endpoint you've already seen, one version number higher.
</details>

<details>
<summary>Hint 4 — breaking the type</summary>

`/api/v1/orders` takes an optional `id` query parameter that the spec says is an
integer. Send it something that isn't one.
</details>

## 7. Next up

The internal-only path disclosure in this lab included what looks like AWS
credentials. Hold onto those — Module 4 (IAM Exploitation & Privilege Escalation) is
where credentials like that actually get used. For now, just note that you found them;
this module stops at recon.
