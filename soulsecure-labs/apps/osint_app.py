#!/usr/bin/env python3
"""OSINT Sandbox / Recon Toolkit (port 9091) -- Module 2 lab utility service.

Two things live here:
  1. The original OSINT stand-ins (Lab 1): RDAP/WHOIS, ASN, CT-log, Shodan-style
     search, and (Lab 5) passive DNS history -- data the isolated lab network
     can't reach for real.
  2. A generic "Recon Toolkit" (Lab 2 onward): DNS Lookup, an HTTP(S) Request
     tool (a small Postman/Burp-Repeater-style panel), and a TLS Certificate
     Viewer. These aren't simulations -- they run real `dig`/`openssl`/HTTP
     requests against the actual lab environment, just from a browser button
     instead of a terminal, so every result still shows the equivalent CLI
     command for when a GUI isn't available (which is true for everything
     *except* this one utility service).

Serves both a browser GUI at "/" and the underlying JSON API endpoints
(unchanged paths, still usable directly with curl/scripts).
"""
import os
import subprocess
from flask import Flask, jsonify, request, Response

try:
    import requests as pyrequests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    pyrequests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pyrequests = None

app = Flask(__name__)
LAB_MODULE = int(os.environ.get("LAB_MODULE", "2"))
LAB_LEVEL = int(os.environ.get("LAB_LEVEL", "5"))

# Module 3+ continues the same tenant -- Module 2 content (including the
# Passive DNS History card, gated at M2>=5) never disappears once you move
# past Module 2.
M2 = 5 if LAB_MODULE > 2 else LAB_LEVEL

LAB_CIDR = os.environ.get("LAB_CIDR", "192.168.174.0/24")
LAB_IP = os.environ.get("LAB_IP", "192.168.174.136")
_net_prefix = LAB_CIDR.rsplit(".", 1)[0]
_start_ip = f"{_net_prefix}.0"
_end_ip = f"{_net_prefix}.255"

RDAP_DB = {
    LAB_CIDR: {
        "handle": "SOULSECURE-NET-1",
        "startAddress": _start_ip,
        "endAddress": _end_ip,
        "name": "SOULSECURE-INC",
        "type": "DIRECT ALLOCATION",
        "country": "SG",
        "entities": [
            {"role": "registrant", "org": "SoulSecure Inc.", "email": "hostmaster@soulsecure.lab"},
            {"role": "abuse", "org": "SoulSecure Inc. SOC", "email": "abuse@soulsecure.lab"},
        ],
        "remarks": "Allocation flagged in lab data as an AWS-style direct-allocation "
                    "range for training purposes (cloud provider fingerprinting exercise).",
    }
}

ASN_DB = {
    "soulsecure": {
        "asn": "AS64512",
        "org": "SoulSecure Inc.",
        "prefixes": [LAB_CIDR],
        "upstream": "AS16509 (simulated AMAZON-02 style upstream for lab realism)",
    }
}

CT_LOG = [
    {
        "issuer": "R3 (Let's Encrypt, simulated)",
        "not_before": "2026-05-01",
        "not_after": "2026-08-01",
        "common_name": "www.soulsecure.lab",
        "san": ["www.soulsecure.lab", "soulsecure.lab"],
    },
    {
        "issuer": "R3 (Let's Encrypt, simulated)",
        "not_before": "2026-04-11",
        "not_after": "2026-07-11",
        "common_name": "storage.soulsecure.lab",
        "san": ["storage.soulsecure.lab", "vpn.soulsecure.lab"],
    },
    {
        "issuer": "R3 (Let's Encrypt, simulated)",
        "not_before": "2025-12-02",
        "not_after": "2026-03-02",
        "common_name": "backup-eu.soulsecure.lab",
        "san": ["backup-eu.soulsecure.lab"],
    },
]

SHODAN_RESULTS = {
    "soulsecure": [
        {
            "port": 3000,
            "product": "Grafana",
            "version": "10.2.3",
            "banner": "HTTP/1.1 200 OK\\r\\nServer: Grafana/10.2.3",
            "note": "no auth prompt visible in banner -- worth a manual look",
        },
        {
            "port": 22,
            "product": "OpenSSH",
            "version": "8.9p1",
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
            "note": "standard management SSH, out of scope for this engagement",
        },
    ]
}

DNS_HISTORY = {
    "www.soulsecure.lab": [
        {"date": "2025-01-10", "type": "A", "value": "(behind CDN as of this date)"},
        {"date": "2024-06-02", "type": "CNAME", "value": "origin-direct.soulsecure.lab"},
        {"date": "2023-11-20", "type": "A", "value": "origin-direct.soulsecure.lab (pre-CDN, direct origin)"},
    ]
}

# ---------------------------------------------------------------------------
# JSON API -- Lab 1 OSINT stand-ins (unchanged paths)
# ---------------------------------------------------------------------------

@app.route("/api")
def api_index():
    endpoints = ["/rdap?ip=<cidr>", "/asn?query=<org>", "/ct-log?domain=<domain>",
                 "/shodan-search?query=<term>",
                 "/tools/dns-lookup?domain=<domain>&type=<A|TXT|MX|CAA|SRV|CNAME>",
                 "/tools/http-request (POST)", "/tools/tls-cert?hostname=<host>"]
    if M2 >= 5:
        endpoints.append("/dns-history?domain=<domain>")
    return jsonify(
        service="OSINT Sandbox / Recon Toolkit",
        note="Local stand-in for RDAP / ASN / crt.sh / Shodan / passive-DNS, plus a "
             "real DNS/HTTP/TLS toolkit -- for lab use only.",
        endpoints=endpoints,
    )

@app.route("/rdap")
def rdap():
    ip = request.args.get("ip", "")
    data = RDAP_DB.get(ip)
    if not data:
        return jsonify(error="not found", hint=f"try ?ip={LAB_CIDR}"), 404
    return jsonify(data)

@app.route("/asn")
def asn():
    q = request.args.get("query", "").lower()
    data = ASN_DB.get(q)
    if not data:
        return jsonify(error="not found", hint="try ?query=soulsecure"), 404
    return jsonify(data)

@app.route("/shodan-search")
def shodan_search():
    q = request.args.get("query", "").lower()
    results = SHODAN_RESULTS.get(q)
    if not results:
        return jsonify(error="not found", hint="try ?query=soulsecure"), 404
    return jsonify(query=q, results=results)

@app.route("/ct-log")
def ct_log():
    domain = request.args.get("domain", "")
    if "soulsecure.lab" not in domain:
        return jsonify(error="not found", hint="try ?domain=soulsecure.lab"), 404
    return jsonify(certificates=CT_LOG)

if M2 >= 5:
    @app.route("/dns-history")
    def dns_history():
        domain = request.args.get("domain", "")
        records = DNS_HISTORY.get(domain)
        if not records:
            return jsonify(error="not found", hint="try ?domain=www.soulsecure.lab"), 404
        return jsonify(domain=domain, history=records)

# ---------------------------------------------------------------------------
# Recon Toolkit -- real tools (Lab 2 onward), not simulated data
# ---------------------------------------------------------------------------

ALLOWED_RTYPES = {"A", "AAAA", "TXT", "MX", "CAA", "SRV", "CNAME", "NS", "SOA", "ANY"}

@app.route("/tools/dns-lookup")
def tool_dns_lookup():
    domain = request.args.get("domain", "").strip()
    rtype = request.args.get("type", "A").strip().upper()
    if not domain:
        return jsonify(error="domain required"), 400
    if rtype not in ALLOWED_RTYPES:
        return jsonify(error=f"unsupported type, use one of {sorted(ALLOWED_RTYPES)}"), 400
    try:
        proc = subprocess.run(
            ["dig", "@dns", "+noall", "+answer", domain, rtype],
            capture_output=True, text=True, timeout=8,
        )
        out = proc.stdout.strip()
        return jsonify(domain=domain, type=rtype, output=out or "(no records -- NXDOMAIN or empty answer)")
    except subprocess.TimeoutExpired:
        return jsonify(error="dig timed out"), 504
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route("/tools/http-request", methods=["POST"])
def tool_http_request():
    if pyrequests is None:
        return jsonify(error="requests library not available"), 500
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "").strip()
    path = (data.get("path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = "/" + path
    method = (data.get("method") or "GET").strip().upper()
    headers_raw = data.get("headers", "") or ""
    body = data.get("body", "") or ""
    if not hostname:
        return jsonify(error="hostname required"), 400
    if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}:
        return jsonify(error="unsupported method"), 400

    headers = {"Host": hostname}
    for line in headers_raw.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()

    try:
        resp = pyrequests.request(
            method,
            f"https://www:443{path}",
            headers=headers,
            data=body if method in ("POST", "PUT") else None,
            verify=False,
            timeout=8,
            allow_redirects=False,
        )
        return jsonify(
            status=resp.status_code,
            headers=dict(resp.headers),
            body=resp.text[:8000],
            truncated=len(resp.text) > 8000,
        )
    except pyrequests.exceptions.RequestException as e:
        return jsonify(error=str(e)), 502

@app.route("/tools/tls-cert")
def tool_tls_cert():
    hostname = request.args.get("hostname", "").strip()
    if not hostname:
        return jsonify(error="hostname required"), 400
    try:
        p1 = subprocess.run(
            ["openssl", "s_client", "-connect", "www:443", "-servername", hostname],
            input="", capture_output=True, text=True, timeout=8,
        )
        if "BEGIN CERTIFICATE" not in p1.stdout:
            return jsonify(error="no certificate returned", raw=p1.stderr[:1000]), 502
        p2 = subprocess.run(
            ["openssl", "x509", "-noout", "-text"],
            input=p1.stdout, capture_output=True, text=True, timeout=8,
        )
        text = p2.stdout
        lines = text.splitlines()
        san = ""
        issuer = ""
        validity = ""
        for i, line in enumerate(lines):
            if "Subject Alternative Name" in line and i + 1 < len(lines):
                san = lines[i + 1].strip()
            if line.strip().startswith("Issuer:"):
                issuer = line.strip()
            if line.strip().startswith("Not Before") or line.strip().startswith("Not After"):
                validity += line.strip() + "  "
        return jsonify(hostname=hostname, san=san, issuer=issuer, validity=validity.strip(),
                        raw=text[:4000])
    except subprocess.TimeoutExpired:
        return jsonify(error="openssl timed out"), 504
    except Exception as e:
        return jsonify(error=str(e)), 500

# ---------------------------------------------------------------------------
# Browser GUI
# ---------------------------------------------------------------------------

DNS_HISTORY_CARD = """
    <section class="card" id="card-dnshist">
      <h2>8. Passive DNS History <span class="tag">Lab 5</span></h2>
      <p>Services like SecurityTrails/ViewDNS keep <strong>old</strong> DNS records even
      after an org changes them -- including from before a CDN was put in front of a
      site. Useful for finding an origin server a CDN is supposed to be hiding.</p>
      <div class="row">
        <label>Domain</label>
        <input id="in-dnshist" value="www.soulsecure.lab">
        <button onclick="runDnsHistory()">Look up history</button>
      </div>
      <div class="curl" id="curl-dnshist"></div>
      <div class="result" id="result-dnshist"></div>
    </section>
""" if M2 >= 5 else ""

PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SoulSecure OSINT Sandbox &amp; Recon Toolkit</title>
<style>
  :root {{
    --bg: #0b1220; --panel: #111a2b; --border: #22314f; --text: #e6edf3;
    --muted: #8a97ab; --accent: #4fd1c5; --accent2: #f0b429; --mono: 'Consolas','Monaco',monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: Arial, Helvetica, sans-serif; background: var(--bg); color: var(--text);
          margin: 0; padding: 0 0 60px 0; }}
  header {{ background: var(--panel); padding: 28px 24px; border-bottom: 2px solid var(--border); }}
  header h1 {{ margin: 0 0 6px 0; color: var(--accent); font-size: 22px; }}
  header p {{ margin: 0; color: var(--muted); max-width: 860px; line-height: 1.5; font-size: 14px; }}
  main {{ max-width: 860px; margin: 24px auto; padding: 0 20px; }}
  h3.section {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
                margin: 30px 0 10px 4px; border-top: 1px solid var(--border); padding-top: 20px; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
           padding: 20px 22px; margin-bottom: 20px; }}
  .card h2 {{ margin: 0 0 8px 0; font-size: 16px; color: var(--accent2); }}
  .card p {{ color: var(--muted); font-size: 13px; line-height: 1.5; margin: 0 0 14px 0; }}
  .tag {{ display: inline-block; background: #1c2b45; color: var(--accent); border-radius: 4px;
          padding: 1px 8px; font-size: 11px; font-family: var(--mono); margin-left: 8px; vertical-align: middle; }}
  .row {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px; }}
  .row label {{ font-size: 13px; color: var(--muted); min-width: 70px; }}
  .row input, .row select {{ flex: 1; min-width: 160px; background: #0d1626; border: 1px solid var(--border);
                color: var(--text); padding: 8px 10px; border-radius: 5px; font-family: var(--mono);
                font-size: 13px; }}
  .row textarea {{ flex: 1; min-width: 240px; background: #0d1626; border: 1px solid var(--border);
                    color: var(--text); padding: 8px 10px; border-radius: 5px; font-family: var(--mono);
                    font-size: 12px; resize: vertical; }}
  .row button {{ background: var(--accent); color: #08131a; border: none; padding: 9px 16px;
                 border-radius: 5px; cursor: pointer; font-weight: bold; font-size: 13px; }}
  .row button:hover {{ opacity: 0.85; }}
  .curl {{ margin-top: 4px; font-family: var(--mono); font-size: 12px; color: #7dd3c0;
           background: #08131a; border: 1px solid var(--border); border-radius: 5px;
           padding: 8px 12px; display: none; white-space: pre-wrap; word-break: break-all; }}
  .curl.show {{ display: block; }}
  .result {{ margin-top: 12px; }}
  .result table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .result th, .result td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }}
  .result th {{ color: var(--muted); font-weight: normal; width: 160px; vertical-align: top; }}
  .result td {{ font-family: var(--mono); word-break: break-word; }}
  .result pre {{ background: #08131a; border: 1px solid var(--border); border-radius: 5px;
                 padding: 10px 12px; font-size: 12px; overflow-x: auto; white-space: pre-wrap;
                 word-break: break-all; margin: 6px 0; }}
  .result .err {{ color: #f07178; font-family: var(--mono); font-size: 13px; }}
  .result .subtable {{ margin: 6px 0 6px 0; width: 100%; border: 1px solid var(--border); border-radius: 4px; }}
  .result .status-ok {{ color: #7dd3c0; }}
  .result .status-bad {{ color: #f07178; }}
  footer {{ max-width: 860px; margin: 0 auto; padding: 0 20px; color: var(--muted); font-size: 12px; }}
  a {{ color: var(--accent); }}
  code {{ background: #0d1626; padding: 1px 5px; border-radius: 3px; }}
</style>
</head>
<body>
<header>
  <h1>SoulSecure OSINT Sandbox &amp; Recon Toolkit</h1>
  <p>This lab network has no internet access, so cards 1-4 mimic real-world OSINT
  sources (WHOIS/RDAP, a BGP looking-glass, crt.sh, Shodan/Censys) with realistic
  data. Cards 5-7 (and 8, once you reach Lab 5) are <strong>real tools</strong> --
  they run actual DNS queries / HTTP requests / TLS handshakes against this
  environment, just from a button instead of a terminal. Every result shows the
  <strong>equivalent CLI command</strong> too, because Labs 2-5's target services
  themselves have no GUI of their own -- you'll need curl/dig/openssl directly once
  you're working against them for real.</p>
</header>
<main>

  <h3 class="section">OSINT stand-ins (simulated data) &mdash; Lab 1</h3>

  <section class="card" id="card-rdap">
    <h2>1. RDAP / WHOIS-style Lookup</h2>
    <p>Who owns this IP range? Real recon starts by identifying the organization
    behind a target's address block.</p>
    <div class="row">
      <label>IP / CIDR</label>
      <input id="in-rdap" value="{LAB_CIDR}">
      <button onclick="runRdap()">Look up</button>
    </div>
    <div class="curl" id="curl-rdap"></div>
    <div class="result" id="result-rdap"></div>
  </section>

  <section class="card" id="card-asn">
    <h2>2. ASN Lookup</h2>
    <p>Which Autonomous System (network block) does this organization announce?</p>
    <div class="row">
      <label>Org name</label>
      <input id="in-asn" value="soulsecure">
      <button onclick="runAsn()">Look up</button>
    </div>
    <div class="curl" id="curl-asn"></div>
    <div class="result" id="result-asn"></div>
  </section>

  <section class="card" id="card-ctlog">
    <h2>3. Certificate Transparency Log</h2>
    <p>Every publicly-trusted TLS certificate gets logged permanently. Past
    certificates often reveal subdomains that were never announced anywhere else.</p>
    <div class="row">
      <label>Domain</label>
      <input id="in-ctlog" value="soulsecure.lab">
      <button onclick="runCtLog()">Search logs</button>
    </div>
    <div class="curl" id="curl-ctlog"></div>
    <div class="result" id="result-ctlog"></div>
  </section>

  <section class="card" id="card-shodan">
    <h2>4. Shodan-style Internet Scan</h2>
    <p>Simulates an internet-wide port/banner scan engine (like real Shodan/Censys) --
    often the fastest way to find something exposed that nobody meant to expose,
    faster than scanning every port yourself.</p>
    <div class="row">
      <label>Search term</label>
      <input id="in-shodan" value="soulsecure">
      <button onclick="runShodan()">Search</button>
    </div>
    <div class="curl" id="curl-shodan"></div>
    <div class="result" id="result-shodan"></div>
  </section>

  <h3 class="section">Recon toolkit (real tools, real results) &mdash; Labs 2-5</h3>

  <section class="card" id="card-dns">
    <h2>5. DNS Lookup <span class="tag">Lab 2</span></h2>
    <p>Runs a real <code>dig</code> query against this lab's DNS server. Use it for
    every record type you need -- A, TXT, MX, CAA, SRV, CNAME.</p>
    <div class="row">
      <label>Domain</label>
      <input id="in-dns-domain" value="soulsecure.lab">
      <label style="min-width:40px">Type</label>
      <select id="in-dns-type">
        <option>A</option><option>TXT</option><option>MX</option><option>CAA</option>
        <option>SRV</option><option>CNAME</option><option>NS</option><option>ANY</option>
      </select>
      <button onclick="runDnsTool()">Query</button>
    </div>
    <div class="curl" id="curl-dns"></div>
    <div class="result" id="result-dns"></div>
  </section>

  <section class="card" id="card-http">
    <h2>6. HTTP(S) Request Tool <span class="tag">Labs 2-5</span></h2>
    <p>A small Postman/Burp-Repeater-style panel. Sends a real HTTPS request into
    this lab's gateway with whatever hostname/path/headers/body you set --
    use it for virtual-host testing, API/GraphQL calls, object storage
    listing, header inspection, and WAF testing (canary payloads in the path).</p>
    <div class="row">
      <label>Hostname</label>
      <input id="in-http-host" value="www.soulsecure.lab">
      <label style="min-width:50px">Method</label>
      <select id="in-http-method" onchange="toggleBody()">
        <option>GET</option><option>POST</option><option>PUT</option>
        <option>HEAD</option><option>OPTIONS</option>
      </select>
    </div>
    <div class="row">
      <label>Path</label>
      <input id="in-http-path" value="/">
    </div>
    <div class="row">
      <label>Headers</label>
      <textarea id="in-http-headers" rows="2" placeholder="One per line, e.g.&#10;X-Beta-Access: enabled&#10;Content-Type: application/json"></textarea>
    </div>
    <div class="row" id="row-http-body" style="display:none">
      <label>Body</label>
      <textarea id="in-http-body" rows="3" placeholder='{{"query":"{{__schema{{queryType{{fields{{name}}}}}}}}"}}'></textarea>
    </div>
    <div class="row">
      <button onclick="runHttpTool()">Send Request</button>
    </div>
    <div class="curl" id="curl-http"></div>
    <div class="result" id="result-http"></div>
  </section>

  <section class="card" id="card-tls">
    <h2>7. TLS Certificate Viewer <span class="tag">Lab 2 / Lab 5</span></h2>
    <p>Connects over TLS and pulls the certificate's Subject Alternative Name (SAN)
    list -- a source of hostnames that has nothing to do with DNS. All hostnames in
    this lab share one certificate, so any SNI value works; try one you already know
    first to see the full list.</p>
    <div class="row">
      <label>Hostname</label>
      <input id="in-tls-host" value="www.soulsecure.lab">
      <button onclick="runTlsTool()">Get Certificate</button>
    </div>
    <div class="curl" id="curl-tls"></div>
    <div class="result" id="result-tls"></div>
  </section>

  {DNS_HISTORY_CARD}

</main>
<footer>
  <p>Note: this service itself (port 9091) is a <strong>lab utility</strong>, not an
  in-scope target asset -- don't include it in your asset inventory. Raw JSON API is
  still available at the same paths for scripts/curl.</p>
</footer>

<script>
const TARGET_IP = "{LAB_IP}";
function showCurl(id, cmd) {{
  const el = document.getElementById(id);
  el.textContent = '$ ' + cmd;
  el.classList.add('show');
}}
function errBox(id, msg) {{
  document.getElementById(id).innerHTML = '<div class="err">' + msg + '</div>';
}}
function esc(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}
function kvTable(obj, skip) {{
  skip = skip || [];
  let html = '<table>';
  for (const k in obj) {{
    if (skip.includes(k)) continue;
    let v = obj[k];
    if (Array.isArray(v)) {{
      if (v.length && typeof v[0] === 'object') {{ html += '<tr><th>' + k + '</th><td>' + subTable(v) + '</td></tr>'; continue; }}
      v = v.join(', ');
    }} else if (typeof v === 'object' && v !== null) {{ v = JSON.stringify(v); }}
    html += '<tr><th>' + k + '</th><td>' + esc(v) + '</td></tr>';
  }}
  html += '</table>';
  return html;
}}
function subTable(arr) {{
  if (!arr.length) return '(none)';
  const cols = Object.keys(arr[0]);
  let html = '<table class="subtable"><tr>' + cols.map(c => '<th>' + c + '</th>').join('') + '</tr>';
  for (const row of arr) {{
    html += '<tr>' + cols.map(c => '<td>' + esc(Array.isArray(row[c]) ? row[c].join(', ') : (row[c] ?? '')) + '</td>').join('') + '</tr>';
  }}
  html += '</table>';
  return html;
}}

async function runRdap() {{
  const ip = document.getElementById('in-rdap').value.trim();
  const url = '/rdap?ip=' + encodeURIComponent(ip);
  showCurl('curl-rdap', 'curl -s "http://' + TARGET_IP + ':9091' + url + '"');
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-rdap', data.error + ' -- ' + data.hint);
  document.getElementById('result-rdap').innerHTML = kvTable(data);
}}

async function runAsn() {{
  const q = document.getElementById('in-asn').value.trim();
  const url = '/asn?query=' + encodeURIComponent(q);
  showCurl('curl-asn', 'curl -s "http://' + TARGET_IP + ':9091' + url + '"');
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-asn', data.error + ' -- ' + data.hint);
  document.getElementById('result-asn').innerHTML = kvTable(data);
}}

async function runCtLog() {{
  const d = document.getElementById('in-ctlog').value.trim();
  const url = '/ct-log?domain=' + encodeURIComponent(d);
  showCurl('curl-ctlog', 'curl -s "http://' + TARGET_IP + ':9091' + url + '"');
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-ctlog', data.error + ' -- ' + data.hint);
  document.getElementById('result-ctlog').innerHTML =
    '<p style="color:#8a97ab;font-size:12px;margin:0 0 8px 0">' + data.certificates.length +
    ' certificate(s) found -- read every SAN entry, not just the common name:</p>' + subTable(data.certificates);
}}

async function runShodan() {{
  const q = document.getElementById('in-shodan').value.trim();
  const url = '/shodan-search?query=' + encodeURIComponent(q);
  showCurl('curl-shodan', 'curl -s "http://' + TARGET_IP + ':9091' + url + '"');
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-shodan', data.error + ' -- ' + data.hint);
  let html = subTable(data.results);
  html += '<p style="color:#8a97ab;font-size:12px;margin-top:8px">Connect directly to a port, e.g. ' +
    '<code>curl http://' + TARGET_IP + ':' + data.results[0].port + '/</code></p>';
  document.getElementById('result-shodan').innerHTML = html;
}}

async function runDnsHistory() {{
  const d = document.getElementById('in-dnshist').value.trim();
  const url = '/dns-history?domain=' + encodeURIComponent(d);
  showCurl('curl-dnshist', 'curl -s "http://' + TARGET_IP + ':9091' + url + '"');
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-dnshist', data.error + ' -- ' + data.hint);
  document.getElementById('result-dnshist').innerHTML = subTable(data.history);
}}

async function runDnsTool() {{
  const domain = document.getElementById('in-dns-domain').value.trim();
  const type = document.getElementById('in-dns-type').value;
  const url = '/tools/dns-lookup?domain=' + encodeURIComponent(domain) + '&type=' + type;
  showCurl('curl-dns', 'dig @' + TARGET_IP + ' ' + domain + ' ' + type);
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-dns', data.error);
  document.getElementById('result-dns').innerHTML = '<pre>' + esc(data.output) + '</pre>';
}}

function toggleBody() {{
  const m = document.getElementById('in-http-method').value;
  document.getElementById('row-http-body').style.display = (m === 'POST' || m === 'PUT') ? 'flex' : 'none';
}}

async function runHttpTool() {{
  const hostname = document.getElementById('in-http-host').value.trim();
  const path = document.getElementById('in-http-path').value.trim() || '/';
  const method = document.getElementById('in-http-method').value;
  const headersRaw = document.getElementById('in-http-headers').value;
  const body = document.getElementById('in-http-body').value;

  let curlCmd = 'curl -sk --resolve ' + hostname + ':443:' + TARGET_IP + ' -X ' + method +
    ' "https://' + hostname + path + '"';
  headersRaw.split('\\n').forEach(l => {{ l = l.trim(); if (l) curlCmd += ' -H "' + l + '"'; }});
  if ((method === 'POST' || method === 'PUT') && body) curlCmd += " -d '" + body + "'";
  showCurl('curl-http', curlCmd);

  const res = await fetch('/tools/http-request', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{ hostname, path, method, headers: headersRaw, body }}),
  }});
  const data = await res.json();
  if (!res.ok) return errBox('result-http', data.error || 'request failed');
  const statusClass = data.status < 400 ? 'status-ok' : 'status-bad';
  let html = '<p><span class="' + statusClass + '">HTTP ' + data.status + '</span></p>';
  html += '<table><tr><th>Response headers</th><td>' + subTable(Object.entries(data.headers).map(([k,v]) => ({{header: k, value: v}}))) + '</td></tr></table>';
  html += '<pre>' + esc(data.body) + (data.truncated ? '\\n... (truncated)' : '') + '</pre>';
  document.getElementById('result-http').innerHTML = html;
}}

async function runTlsTool() {{
  const hostname = document.getElementById('in-tls-host').value.trim();
  const url = '/tools/tls-cert?hostname=' + encodeURIComponent(hostname);
  showCurl('curl-tls', 'echo | openssl s_client -connect ' + TARGET_IP + ':443 -servername ' + hostname +
    ' 2>/dev/null | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"');
  const res = await fetch(url); const data = await res.json();
  if (!res.ok) return errBox('result-tls', data.error);
  let html = '<table>';
  html += '<tr><th>Issuer</th><td>' + esc(data.issuer) + '</td></tr>';
  html += '<tr><th>Validity</th><td>' + esc(data.validity) + '</td></tr>';
  html += '<tr><th>SAN list</th><td>' + esc(data.san) + '</td></tr>';
  html += '</table>';
  document.getElementById('result-tls').innerHTML = html;
}}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9091)
