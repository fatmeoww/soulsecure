#!/usr/bin/env python3
"""vpn.soulsecure.lab -- forgotten VPN gateway (port 943, reverse-proxied via
www on 443). M2 Lab 1: banner + flag-in-comment only. M3 Lab 5 extends it in
place with session-cookie login, an authenticated dashboard, a .ovpn config
download, an SSH key download, and a deliberately unvalidated `profile`
query parameter (the IDOR).
"""
import os
import secrets
from flask import Flask, Response, request, jsonify, make_response

app = Flask(__name__)
LAB_MODULE = int(os.environ.get("LAB_MODULE", "2"))
LAB_LEVEL = int(os.environ.get("LAB_LEVEL", "5"))


def _module_level(module_num):
    if LAB_MODULE > module_num:
        return 5
    if LAB_MODULE == module_num:
        return LAB_LEVEL
    return 0


M3 = _module_level(3)

PAGE = """<!DOCTYPE html>
<html><head><title>OpenVPN Access Server</title></head>
<body>
<h1>SoulSecure VPN Gateway</h1>
<p>Please sign in with your corporate SSO credentials to continue.</p>
<!-- flag: flag{553edeb5b994421a80636e7556fab1b4} -->
</body></html>
"""

@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "OpenVPN-AS/2.9.5"
    return resp

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

# ---------------------------------------------------------------------------
# Module 3 Lab 5: VPN / Remote Access Gateway Exploitation
# ---------------------------------------------------------------------------

if M3 >= 5:
    VALID_USERNAME = "j.ops"
    VALID_PASSWORD = "Backup2025!"  # deliberate reuse of M3 Lab 4's portal password
    SESSIONS = {}  # token -> username

    LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>VPN Login</title></head>
<body>
<h1>SoulSecure VPN Gateway -- Sign in</h1>
<form method="POST" action="/login">
  <input name="username" placeholder="username"><br>
  <input name="password" type="password" placeholder="password"><br>
  <input type="submit" value="Sign in">
</form>
</body></html>
"""

    def _current_username():
        token = request.cookies.get("vpn_session")
        return SESSIONS.get(token)

    @app.route("/login", methods=["GET"])
    def login_page():
        return Response(LOGIN_PAGE, mimetype="text/html")

    @app.route("/login", methods=["POST"])
    def login_submit():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            token = secrets.token_urlsafe(24)
            SESSIONS[token] = username
            resp = make_response(jsonify(status="ok"))
            resp.set_cookie("vpn_session", token)
            return resp
        return jsonify(error="invalid credentials"), 401

    @app.route("/dashboard")
    def dashboard():
        username = _current_username()
        if not username:
            return jsonify(error="login required"), 401
        return Response(
            f"""<!DOCTYPE html>
<html><head><title>VPN Dashboard</title></head>
<body>
<h1>Welcome, {username}</h1>
<ul>
  <li><a href="/download-config?profile={username}">Download OpenVPN config</a></li>
  <li><a href="/jump-host-key?profile={username}">Download jump-host SSH key</a></li>
</ul>
<!-- flag{{c83c94451748f88e0cc8eb21e446e089}} -->
</body></html>
""",
            mimetype="text/html",
        )

    OVPN_PROFILES = {
        "j.ops": """client
dev tun
proto udp
remote vpn.soulsecure.lab 1194
# internal network: 10.42.0.0/16
# flag{669d10c840bb4275678eedf5ca121dda}
<ca>...placeholder cert block...</ca>
<cert>...placeholder cert block...</cert>
<key>...placeholder cert block...</key>
""",
        # Harder mode / IDOR target -- reachable with ANY valid session,
        # not just j.ops's own. No extra credential required, only a
        # different query-string value. Broader routed range signals
        # "more privileged" without extra mechanics.
        "admin": """client
dev tun
proto udp
remote vpn.soulsecure.lab 1194
# internal network: 10.42.0.0/16 (full routing, incl. management VLAN 10.42.255.0/24)
# flag{9877e95d68a38b4d15a3f7a373562789}
<ca>...placeholder cert block...</ca>
<cert>...placeholder cert block...</cert>
<key>...placeholder cert block...</key>
""",
    }

    @app.route("/download-config")
    def download_config():
        if not _current_username():
            return jsonify(error="login required"), 401
        profile = request.args.get("profile", "")
        content = OVPN_PROFILES.get(profile)
        if content is None:
            return jsonify(error="unknown profile"), 404
        return Response(content, mimetype="text/plain")

    JUMP_HOST_KEYS = {
        "j.ops": (
            "Jump host: bastion.internal.soulsecure.lab "
            "(only reachable once VPN-connected)\n"
            "flag{b6d5e3a55e1bc426be3522b8b236e253}\n\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
            "QyNTUxOQAAACBOTFVBUEVBQ0VIT0xERVJOT1RBUkVBTEtFWU5PVFJFQUxBQUFBQUFB\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
    }

    @app.route("/jump-host-key")
    def jump_host_key():
        if not _current_username():
            return jsonify(error="login required"), 401
        profile = request.args.get("profile", "")
        content = JUMP_HOST_KEYS.get(profile)
        if content is None:
            return jsonify(error="unknown profile"), 404
        return Response(content, mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=943)
