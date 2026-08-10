#!/usr/bin/env python3
"""backup-admin -- Module 5 Lab 4's single addition to backup-eu.

backup-eu.soulsecure.lab is otherwise served as plain static content
directly by nginx (Module 3's design -- no Flask app there at all). Rather
than converting the whole vhost to a backend just for one admin route,
this is a small, separate internal-only service that nginx proxies to for
exactly one path (/admin/export-all); everything else on backup-eu (the
static landing page, the Basic-Auth /files/ listing) is untouched.

Auth: same self-contained X-Access-Key-Id/X-Secret-Access-Key convention
as storage_app.py -- a hardcoded check against the known admin-equivalent
key plus any Module 5 Lab 1 student-created backdoor key (checked via a
shared admin-key registry passed in from iam_sim's state -- simplified
here to the fixed ASIAADMIN99 value plus whatever this process is told
about via /admin/register-backdoor-key, called by iam-sim's create-user
flow so a freshly-created backdoor also works here without a live call
back to iam-sim on every request).
"""
import os
from flask import Flask, request, jsonify

app = Flask(__name__)
LAB_MODULE = int(os.environ.get("LAB_MODULE", "2"))
LAB_LEVEL = int(os.environ.get("LAB_LEVEL", "5"))


def _module_level(module_num):
    if LAB_MODULE > module_num:
        return 5
    if LAB_MODULE == module_num:
        return LAB_LEVEL
    return 0


M5 = _module_level(5)

ADMIN_KEYS = {"ASIAADMIN99": "adm9c2d7f1a4e6b8021d5a3f7c9e1b048"}

EXPORT_MANIFEST = {
    "backup_systems": [
        {"name": "backup-eu (primary, EU region)", "note": "the one you already found"},
        {"name": "backup-apac (secondary, ap-southeast-1)", "note": "never linked from any vhost seen so far"},
        {"name": "backup-legacy-onprem", "note": "decommissioned 2024, still has an active export job"},
        {"name": "backup-dr-cold-storage", "note": "disaster-recovery cold tier, glacier-equivalent"},
    ],
    "note": "There's always more than what one engagement fully maps.",
    "flag": "flag{0dfaaa8aef2374a4ae1fe9824225f782}",
}


def authenticated():
    akid = request.headers.get("X-Access-Key-Id")
    secret = request.headers.get("X-Secret-Access-Key")
    return akid and secret and ADMIN_KEYS.get(akid) == secret


if M5 >= 4:
    @app.route("/admin/export-all")
    def export_all():
        if not authenticated():
            return jsonify(error="AccessDenied"), 403
        return jsonify(**EXPORT_MANIFEST)

    @app.route("/admin/register-backdoor-key", methods=["POST"])
    def register_backdoor_key():
        """Internal-only bridge route -- called by iam-sim whenever a new
        admin-equivalent key is created (Module 5 Lab 1's create-user flow,
        or a second key on an existing identity), so backdoor credentials
        minted there also work against this service's admin check without
        a live cross-service auth call on every single request. Not part
        of the student-facing API surface -- no vhost routes here, only
        reachable Docker-internally."""
        body = request.get_json(silent=True) or {}
        akid = body.get("access_key_id")
        secret = body.get("secret_access_key")
        if not akid or not secret:
            return jsonify(error="access_key_id and secret_access_key required"), 400
        ADMIN_KEYS[akid] = secret
        return jsonify(status="registered")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8700)
