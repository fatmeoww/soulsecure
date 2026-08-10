#!/usr/bin/env python3
"""imds-sim -- mock AWS-style Instance Metadata Service (IMDS) for Module 3
Lab 2. Internal-only: no published port, no vhost/DNS. Reachable only via
the `api` container's SSRF routes (which rewrite requests to
169.254.169.254 -> this service's Docker Compose service name -- see
api_app.py's SSRF_HOST_REWRITE). Not reachable from outside the Docker host
under any circumstances.

Simplified IMDSv2 gating: only the second role (soulsecure-deploy-role) is
token-gated. Don't present this as a literal IMDSv2 reference.
"""
import json
import secrets
import time
from flask import Flask, Response, request, jsonify

app = Flask(__name__)

VALID_TOKENS = {}  # token -> expiry epoch

APP_ROLE_CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-01-01T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIASOULSECUREAPP01",
    "SecretAccessKey": "app9f2c7a1e4b6d8801f3a5c9d2e6b1084",
    "Token": "app-session-token-c4d8e1f2a9b6c3d0",
    "Expiration": "2026-01-01T06:00:00Z",
    "flag": "flag{6734732f699ecc94c94afcefd08d3fb5}",
}

DEPLOY_ROLE_CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-01-01T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIASOULSECUREDEPLOY02",
    "SecretAccessKey": "deploy3d7f1a9c4e6b8021d5a3f7c9e1b048",
    "Token": "deploy-session-token-e6b1c4d8f2a9c3d0",
    "Expiration": "2026-01-01T06:00:00Z",
    "flag": "flag{9c0a12db183b624beaae1a8e4f2bc608}",
}

USER_DATA = """#!/bin/bash
# soulsecure-app cloud-init bootstrap
export WEBHOOK_SIGNING_SECRET=whsec_9f2c7a1e4b6d8801f3a5c9d2e6b1084c
echo "bootstrap complete" >> /var/log/cloud-init-output.log
# TODO: migrate this instance to soulsecure-deploy-role once IAM cleanup lands -- ticket flag{b718ed8571792e378f2fa92f9cad0307}
"""


@app.route("/latest/meta-data/")
def meta_data_root():
    return Response("instance-id\nlocal-ipv4\niam/\nplacement/\n", mimetype="text/plain")


@app.route("/latest/meta-data/instance-id")
def instance_id():
    return Response("i-0a1b2c3d4e5f6g7h8", mimetype="text/plain")


@app.route("/latest/user-data")
def user_data():
    return Response(USER_DATA, mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/")
def iam_role_list():
    # soulsecure-deploy-role is deliberately NOT listed here -- only
    # discoverable via the user-data TODO comment above.
    return Response("soulsecure-app-role\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/soulsecure-app-role")
def app_role_creds():
    return jsonify(**APP_ROLE_CREDS)


@app.route("/latest/api/token", methods=["PUT"])
def mint_token():
    ttl = request.headers.get("X-aws-ec2-metadata-token-ttl-seconds")
    if not ttl:
        return Response("missing X-aws-ec2-metadata-token-ttl-seconds header", status=400)
    try:
        ttl = int(ttl)
    except ValueError:
        return Response("invalid ttl", status=400)
    token = secrets.token_urlsafe(20)
    VALID_TOKENS[token] = time.time() + ttl
    return Response(token, mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/soulsecure-deploy-role")
def deploy_role_creds():
    token = request.headers.get("X-aws-ec2-metadata-token")
    expiry = VALID_TOKENS.get(token) if token else None
    if not expiry or expiry < time.time():
        return jsonify(error="IMDSv2 token required"), 401
    return jsonify(**DEPLOY_ROLE_CREDS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
