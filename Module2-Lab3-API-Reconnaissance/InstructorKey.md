# Module 2 — Lab 3: API Reconnaissance — Instructor Key

Runs on the **same target host** as Labs 1–2. This lab only extends
`/opt/soulsecure-labs/apps/api_app.py` (the `api` container). **Access changed** since
the harder-mode rework: `api` is no longer published on port 8080 — it's reverse-proxied
through the `www` nginx container at `https://api.soulsecure.lab/` only (see Lab 1
InstructorKey's "Access architecture" section). All `LAB_LEVEL` gating described below
is unchanged, still enforced inside the Flask app itself.

## Endpoint map (ground truth)

| Method | Path | Documented in `/openapi.json`? | Discovery method | Notes |
|---|---|---|---|---|
| GET | `/` , `/health`, `/version`, `/status` | n/a | Given (Lab 1) | Unchanged from Lab 1 |
| GET | `/openapi.json` | — | Common-path guess | Entry point for this whole lab |
| GET | `/api/v1/health` | Yes | Spec | |
| GET | `/api/v1/status` | Yes | Spec | Deprecation notice mentioning v2 -- motivates the version brute-force in the next row, so it isn't unmotivated guessing |
| GET | `/api/v1/users` | Yes | Spec | Fake usernames only, no PII |
| GET | `/api/v1/orders` | Yes | Spec | `?id=<int>` optional |
| GET | `/api/v1/orders?id=<non-int>` | N/A (same path, bad input) | Manual testing / fuzzing | Triggers verbose 500 → **Flag 3** |
| GET | `/api/v2/status` | **No** | Version-number brute force | **Flag 2** |
| GET | `/api/internal/debug` | Yes, but flagged `x-internal` with a "do not document externally" summary | Spec leak | **Flag 1**; also leaks fake AWS keys (foreshadows Module 4) |
| POST | `/graphql` | **No** (separate standard, not in the REST spec) | Common-path guess | Introspection on, **Flag 4** (harder mode) |

## Flags (ground truth)

| Flag | Trigger | Value |
|---|---|---|
| Flag 1 | `GET /api/internal/debug` | `flag{3555384be5128ee4c26ffc4992d2c1e1}` |
| Flag 2 | `GET /api/v2/status` | `flag{76616423d4eeb78183ccfbf84092b179}` |
| Flag 3 | `GET /api/v1/orders?id=abc` (or any non-integer) | `flag{7c8934797877b254b9db3695a84cbf8b}` |
| Flag 4 (harder-mode) | `POST /graphql` with query `{internalSecret}` | `flag{b1579ebf26c0e4de304a77b01879d801}` |

## Verification commands

```bash
curl -sk https://api.soulsecure.lab/openapi.json | python3 -m json.tool
curl -sk https://api.soulsecure.lab/api/internal/debug          # Flag 1
curl -sk https://api.soulsecure.lab/api/v2/status                # Flag 2
curl -sk 'https://api.soulsecure.lab/api/v1/orders?id=abc'        # Flag 3

curl -sk https://api.soulsecure.lab/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{fields{name}}}}"}'
curl -sk https://api.soulsecure.lab/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{internalSecret}"}'                                # Flag 4
```

### Harder-mode addition: GraphQL

`POST /graphql` is a pattern-matched stand-in for a real GraphQL engine (not a full
implementation) but the workflow is realistic: **not** listed in `/openapi.json`
(GraphQL and REST specs are separate standards — a real org's OpenAPI doc frequently
just doesn't mention it), so students must guess the path. Introspection is left "on".

**Common student mistake:** forgetting `Content-Type: application/json` on the POST —
Flask's `request.get_json(silent=True)` returns `None` without it, and the endpoint
silently falls through to the default `{"health": "ok"}` response. Worth flagging in
class as a "read your own tooling's defaults" lesson if several students hit it.

File: `apps/api_app.py`, gated `LAB_LEVEL >= 3` alongside the rest of the Lab 3 routes
(including `/graphql`).

## Grading rubric (out of 100)

| Criterion | Points |
|---|---|
| Found and parsed `/openapi.json` | 10 |
| Enumerated all documented v1 endpoints correctly | 15 |
| Identified `/api/internal/debug` as suspicious from the spec and retrieved it | 20 |
| Found the undocumented `/api/v2/status` via version brute forcing | 20 |
| Triggered and correctly analyzed the verbose error on `/orders` | 15 |
| Found `/graphql`, ran introspection, and queried the flagged field | 15 |
| Clean API endpoint inventory table deliverable | 5 |

## Design notes / narrative threads

- The fake `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in `/api/internal/debug` are
  placeholder strings, not functional credentials against anything — they exist purely
  to set up Module 4 (IAM Exploitation & Privilege Escalation).
- The verbose `/orders` error also leaks a fake internal hostname
  (`orders-db.internal.soulsecure.lab`) and file paths (`/opt/app/api/...`) — useful if
  you want to build a "map the internal service architecture from error messages"
  discussion into class, but there's no functioning service behind that hostname (it
  doesn't resolve — that's expected, it's a red herring/realism detail, not a 4th
  asset to find).

## Known limitations

- This is a hand-built spec/API, not a real framework's auto-generated OpenAPI output
  — good enough to teach the recon workflow.
- The GraphQL endpoint is pattern-matched (checks the request body text for
  `__schema` or `internalSecret`), not a real GraphQL engine — don't expect a real
  GraphQL client library to do anything interesting beyond the two documented queries.
- No rate limiting or auth is implemented anywhere in this API (matches Lab 1's
  "everything overexposed" cloud-misconfiguration theme).
