#!/usr/bin/env python3
"""api.soulsecure.lab -- fake internal REST API (port 8080).

Route availability is gated by LAB_LEVEL (1-5) so that running "up to lab N"
via docker-compose only exposes what that lab is meant to teach:
  LAB_LEVEL 1  -> /, /health, /version, /status                  (Lab 1)
  LAB_LEVEL 3+ -> + /openapi.json, /api/v1/*, /api/v2/*, /api/internal/*  (Lab 3)
  LAB_LEVEL 5+ -> + custom 404 tech-fingerprint handler            (Lab 5)
"""
import json
import os
import datetime
from urllib.parse import urlparse, urlunparse
from flask import Flask, jsonify, request
try:
    import requests as pyrequests
except ImportError:
    pyrequests = None

app = Flask(__name__)
LAB_MODULE = int(os.environ.get("LAB_MODULE", "2"))
LAB_LEVEL = int(os.environ.get("LAB_LEVEL", "5"))

# Module 3+ continues the same tenant -- Module 2 content never disappears
# once you move past it. M2 is "effective Module 2 level": 5 (fully unlocked)
# once LAB_MODULE > 2, otherwise whatever LAB_LEVEL currently is.
def _module_level(module_num):
    if LAB_MODULE > module_num:
        return 5
    if LAB_MODULE == module_num:
        return LAB_LEVEL
    return 0

M2 = _module_level(2)
M3 = _module_level(3)

# SSRF target rewrite -- 169.254.169.254 has no real network presence in this
# lab (see M3 Lab2 InstructorKey "File locations": static-IP-in-169.254.0.0/16
# assignment isn't reliable across Docker versions/bridge drivers, so the
# fetch layer rewrites the *hostname* to the imds-sim service name instead --
# identical observable behavior for students, who only ever go through this
# fetch/relay endpoint and never resolve the IP themselves).
SSRF_HOST_REWRITE = {"169.254.169.254": "imds-sim"}

def ssrf_fetch(url, method="GET", headers=None, timeout=5):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    target_host = SSRF_HOST_REWRITE.get(hostname, hostname)
    netloc = target_host
    if parsed.port:
        netloc += f":{parsed.port}"
    if parsed.username:
        auth = parsed.username + (f":{parsed.password}" if parsed.password else "")
        netloc = auth + "@" + netloc
    rewritten = urlunparse(parsed._replace(netloc=netloc))
    return pyrequests.request(method, rewritten, headers=headers or {}, timeout=timeout)

@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "SoulSecure-Gateway"
    resp.headers["X-Amzn-Trace-Id"] = "Root=1-6620a1b2-0f3a9c2e1a4b7d6c5e8f9a0b"
    resp.headers["Via"] = "1.1 awsproxy.us-east-1.soulsecure.lab (CloudFront)"
    return resp

# ---------------------------------------------------------------------------
# Lab 1 routes -- always available
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return jsonify(service="soulsecure-api", status="ok")

@app.route("/health")
def health():
    return jsonify(status="healthy", ts=datetime.datetime.utcnow().isoformat())

@app.route("/version")
def version():
    return jsonify(
        version="2.4.1",
        build_host="ip-10-0-1-15.ec2.internal",
        region="us-east-1",
        env="production",
    )

@app.route("/status")
def status():
    return jsonify(
        upstream_services=["auth-svc", "billing-svc", "storage-proxy"],
        note="deprecated internal build pipeline: jenkins-old (decommission pending)"
    )

# ---------------------------------------------------------------------------
# Lab 3 routes: API Reconnaissance
# ---------------------------------------------------------------------------

if M2 >= 3:
    OPENAPI_SPEC = {
        "openapi": "3.0.0",
        "info": {"title": "SoulSecure Internal API", "version": "1.0.0"},
        "paths": {
            "/api/v1/health": {"get": {"summary": "Health check"}},
            "/api/v1/status": {"get": {"summary": "Service status"}},
            "/api/v1/users": {"get": {"summary": "List users"}},
            "/api/v1/orders": {"get": {"summary": "List orders", "parameters": [
                {"name": "id", "in": "query", "required": False, "schema": {"type": "integer"}}
            ]}},
            "/api/internal/debug": {
                "get": {"summary": "DEPRECATED - remove before v1.0 GA. Do not document externally.",
                         "x-internal": True}
            },
        },
    }

    @app.route("/openapi.json")
    def openapi_spec():
        return jsonify(OPENAPI_SPEC)

    @app.route("/api/v1/health")
    def api_v1_health():
        return jsonify(status="healthy")

    # Motivates the version-brute-force step in 3.4 -- rather than v2 just
    # existing for no reason, v1 itself says it's being sunset. Documented in
    # the spec (so it turns up during normal endpoint enumeration in 3.2),
    # deliberately doesn't say what v2's path actually is.
    @app.route("/api/v1/status")
    def api_v1_status():
        return jsonify(
            status="ok",
            version="v1",
            uptime_days=412,
            deprecation_notice="API v1 will be sunset once v2 reaches GA. "
                                "New integrations should target v2 going forward.",
        )

    @app.route("/api/v1/users")
    def api_v1_users():
        return jsonify(users=[
            {"id": 1, "username": "jdoe"},
            {"id": 2, "username": "asmith"},
            {"id": 3, "username": "devops-bot"},
        ])

    @app.route("/api/v1/orders")
    def api_v1_orders():
        order_id = request.args.get("id")
        if order_id is not None:
            try:
                int(order_id)
            except ValueError:
                return jsonify(
                    error="Internal Server Error",
                    exception="ValueError: invalid literal for int() with base 10",
                    traceback=[
                        "File \"/opt/app/api/routes/orders.py\", line 42, in get_orders",
                        "    order_id = int(request.args['id'])",
                        "File \"/opt/app/api/db.py\", line 17, in query_orders",
                        "    conn = psycopg2.connect(DATABASE_URL)",
                    ],
                    database_url_hint="postgres://orders_svc:***@orders-db.internal.soulsecure.lab:5432/orders",
                    debug_flag="flag{7c8934797877b254b9db3695a84cbf8b}",
                ), 500
        return jsonify(orders=[{"id": 101, "total": 249.99}, {"id": 102, "total": 89.00}])

    @app.route("/api/v2/status")
    def api_v2_status():
        resp = dict(
            status="beta",
            note="v2 not yet public, do not share this URL",
            flag="flag{76616423d4eeb78183ccfbf84092b179}",
        )
        if M3 >= 2:
            resp["changelog"] = (
                "v2.1 (beta): integrations webhook preview -- "
                "POST /api/v2/integrations/fetch-preview"
            )
        return jsonify(**resp)

    # GraphQL: no auth, introspection left on. Simplified (pattern-matched
    # rather than a real GraphQL engine) but the workflow is realistic --
    # introspect the schema first, then query whatever looks interesting.
    @app.route("/graphql", methods=["POST"])
    def graphql():
        body = (request.get_json(silent=True) or {})
        query = str(body.get("query", ""))
        if "__schema" in query:
            return jsonify(data={"__schema": {"queryType": {"fields": [
                {"name": "health"},
                {"name": "orders"},
                {"name": "internalSecret", "description": "DEPRECATED - internal use only, do not expose in client apps"},
            ]}}})
        if "internalSecret" in query:
            return jsonify(data={"internalSecret": "flag{b1579ebf26c0e4de304a77b01879d801}"})
        return jsonify(data={"health": "ok"})

    @app.route("/api/internal/debug")
    def api_internal_debug():
        return jsonify(
            warning="internal debug endpoint -- should have been removed before GA",
            env={
                "AWS_ACCESS_KEY_ID": "AKIAFAKESOULSECURE01",
                "AWS_SECRET_ACCESS_KEY": "fakeSecretKeyForLabPurposesOnly1234567890AB",
                "AWS_DEFAULT_REGION": "us-east-1",
            },
            note="these are lab-only placeholder credentials, not real AWS keys",
            flag="flag{3555384be5128ee4c26ffc4992d2c1e1}",
        )

# ---------------------------------------------------------------------------
# Module 3 Lab 2: SSRF -> Cloud Instance Metadata Service (IMDS)
# ---------------------------------------------------------------------------

if M3 >= 2:
    @app.route("/api/v2/integrations/fetch-preview", methods=["POST"])
    def fetch_preview():
        body = request.get_json(silent=True) or {}
        url = body.get("url", "")
        if not url:
            return jsonify(error="url is required"), 400
        try:
            resp = ssrf_fetch(url, method="GET")
        except Exception as e:
            result = {
                "error": f"fetch failed: {e}",
            }
            # Discovery hook for the harder-mode route -- only surfaced when
            # the target itself would reject a plain fetch (IMDSv2 gate).
            if "deploy-role" in url:
                result["hint"] = ("for full method/header control see "
                                   "/api/v2/integrations/webhook-relay (internal use only)")
            return jsonify(result), 502
        preview = {
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "body_preview": resp.text[:2000],
        }
        if resp.status_code == 401 and "deploy-role" in url:
            preview["hint"] = ("for full method/header control see "
                                "/api/v2/integrations/webhook-relay (internal use only)")
        return jsonify(preview)

    # Harder-mode only -- not linked from /api/v2/status. Forwards method +
    # arbitrary headers, which is what's needed to mint and use an IMDSv2
    # session token via the two-step PUT-then-GET dance.
    @app.route("/api/v2/integrations/webhook-relay", methods=["POST"])
    def webhook_relay():
        body = request.get_json(silent=True) or {}
        url = body.get("url", "")
        method = body.get("method", "GET")
        headers = body.get("headers") or {}
        if not url:
            return jsonify(error="url is required"), 400
        try:
            resp = ssrf_fetch(url, method=method, headers=headers)
        except Exception as e:
            return jsonify(error=f"fetch failed: {e}"), 502
        return jsonify(
            status_code=resp.status_code,
            content_type=resp.headers.get("Content-Type", ""),
            body_preview=resp.text[:2000],
        )

# ---------------------------------------------------------------------------
# Lab 5 addition: tech-fingerprinting error handler
# ---------------------------------------------------------------------------

if M2 >= 5:
    @app.errorhandler(404)
    def not_found(e):
        return jsonify(
            error="Not Found",
            powered_by="SoulSecure API Gateway (Flask 3.x / Python 3.12, Gunicorn behind ALB)",
            flag="flag{ea97648f7c958c3e5c750862b4ab4519}",
        ), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
