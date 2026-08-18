#!/usr/bin/env python3
"""monitor.soulsecure.lab-style Grafana-lookalike dashboard (port 3000).

Lab 1 addition: NOT findable via DNS or a plain port scan banner alone in the
"intended" path -- it's meant to be found via the OSINT Sandbox's
/shodan-search endpoint (simulating an internet-wide scan result), which is
how a lot of real internal dashboards get discovered in practice: someone
exposed it, nobody advertised it, and it just shows up in Shodan/Censys.
A plain nmap -p- will still find the open port -- Shodan-search is the
*faster*, more realistic path, not the only one.
"""
from flask import Flask, Response

app = Flask(__name__)

PAGE = """<!DOCTYPE html>
<html><head><title>Grafana</title></head>
<body style="font-family:Arial;background:#111217;color:#d8d9da;padding:40px">
<h2>Welcome to Grafana</h2>
<p>Monitoring dashboard for SoulSecure production infrastructure.</p>
<p>Sign in to continue.</p>
<!-- flag: flag{24d7fbca483d726d1ae7ba4c745acd2b} -->
<!-- ops note: exposed for a debugging session in March, never locked back down -->
</body></html>
"""

@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "Grafana/10.2.3"
    return resp

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
