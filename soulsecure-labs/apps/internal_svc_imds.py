#!/usr/bin/env python3
"""internal-svc -- Module 5 Lab 2's second IMDS mock. Internal-only, no
published port, no vhost/DNS -- reachable only via bastion's /proxy (same
network). Deliberately minimal (one role only) compared to Module 3 Lab 2's
imds-sim -- the point of this lab is the pivot itself, not IMDS depth.
"""
from flask import Flask, Response, jsonify

app = Flask(__name__)

ROLE_CREDS = {
    "Code": "Success",
    "LastUpdated": "2026-01-01T00:00:00Z",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIAINTERNALSVC04",
    "SecretAccessKey": "isvc9c2d7f1a4e6b8021d5a3f7c9e1b048",
    "Token": "internal-svc-session-token-a1b2c3d4",
    "Expiration": "2026-01-01T06:00:00Z",
    "flag": "flag{54508c0acdd49305a73f7e5e48c87271}",
}


@app.route("/latest/meta-data/")
def meta_data_root():
    return Response("iam/\ninstance-id\n", mimetype="text/plain")


@app.route("/latest/meta-data/instance-id")
def instance_id():
    return Response("i-0svc9c2d7f1a4e6b80", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/")
def role_list():
    return Response("soulsecure-internal-svc-role\n", mimetype="text/plain")


@app.route("/latest/meta-data/iam/security-credentials/soulsecure-internal-svc-role")
def role_creds():
    return jsonify(**ROLE_CREDS)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
