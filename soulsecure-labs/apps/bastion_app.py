#!/usr/bin/env python3
"""bastion.soulsecure.lab -- Module 5 Lab 2 pivot point.

Auth is a simplified stand-in for "you have the jump-host SSH key": the
caller must present the key's real MD5 fingerprint in a header. This is
NOT a working SSH/VPN tunnel -- see InstructorKey "Known limitations".
The fingerprint below is the genuine, computable MD5 fingerprint of the
private key Module 3 Lab 5 hands students (`ssh-keygen -lf <file> -E md5`),
not a placeholder string.
"""
import os
from urllib.parse import urlparse, urlunparse
from flask import Flask, Response, request, jsonify
try:
    import requests as pyrequests
except ImportError:
    pyrequests = None

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

EXPECTED_FINGERPRINT = "MD5:a6:c4:f1:a7:b4:8d:33:12:c5:5d:db:c9:1b:b7:e3:98"

PAGE = """<!DOCTYPE html>
<html><head><title>Bastion Host</title></head>
<body>
<h1>SoulSecure Bastion</h1>
<p>Internal jump host. Reserved for ops SSH access only.</p>
<!-- flag: flag{a047843f2cfae9a88e0bf81a4ce8f1dc} -->
</body></html>
"""


def check_fingerprint():
    return request.headers.get("X-SSH-Key-Fingerprint") == EXPECTED_FINGERPRINT


@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "OpenSSH-Bastion-Gateway"
    return resp


if M5 >= 2:
    @app.route("/")
    def index():
        if not check_fingerprint():
            return jsonify(error="AccessDenied"), 403
        return Response(PAGE, mimetype="text/html")

    @app.route("/proxy", methods=["GET", "POST"])
    @app.route("/proxy/<path:extra>", methods=["GET", "POST"])
    def proxy(extra=""):
        """Deliberately mirrors Module 3 Lab 2's fetch-preview shape for
        simple GET pivots (Lab 2), but also relays method + JSON body
        (Lab 3 needs POST to reach docker-proxy's containers/create, exec,
        etc.) -- the `url` query param can itself already contain a
        trailing path (see verification commands: $BASE/v1.41/containers/json
        works because the whole remainder becomes the `url` value), and
        `/proxy/<extra>?url=...` is also accepted as an equivalent form.
        This proxy wrapper appends its own flag when the target response is
        internal-svc's role-listing call (Flag 2), distinct from whatever
        internal-svc itself returns."""
        if not check_fingerprint():
            return jsonify(error="AccessDenied"), 403
        url = request.args.get("url", "")
        if not url:
            return jsonify(error="url is required"), 400
        if extra:
            url = url.rstrip("/") + "/" + extra
        headers = {}
        if request.headers.get("Content-Type"):
            headers["Content-Type"] = request.headers["Content-Type"]
        for h in ("X-Access-Key-Id", "X-Secret-Access-Key"):
            if request.headers.get(h):
                headers[h] = request.headers[h]
        try:
            resp = pyrequests.request(request.method, url, headers=headers,
                                       data=request.get_data(), timeout=5)
        except Exception as e:
            return jsonify(error=f"fetch failed: {e}"), 502
        body = resp.text
        if url.rstrip("/").endswith("/security-credentials") and resp.status_code == 200:
            body = body.rstrip("\n") + "\nflag{36a809a129fb2d022edc547d7105ab06}\n"
        return Response(body, status=resp.status_code,
                         mimetype=resp.headers.get("Content-Type", "text/plain"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
