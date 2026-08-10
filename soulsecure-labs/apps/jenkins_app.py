#!/usr/bin/env python3
"""jenkins-old -- UNDOCUMENTED shadow-IT asset (port 9090). M2 Lab 1: banner
+ flag-in-comment only, no DNS record. M3 Lab 3 extends it in place with a
fake unauthenticated script console, job registry, and stateful userContent
write/read -- still port 9090, still no DNS, still not behind the `www`
gateway (found by port scan only, that's the point).
"""
import os
from flask import Flask, Response, request, jsonify

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
M5 = _module_level(5)

PAGE = """<!DOCTYPE html>
<html><head><title>Dashboard [Jenkins]</title></head>
<body>
<h1>Jenkins</h1>
<p>Welcome to the old CI server. Scheduled for decommission -- please migrate
jobs to the new pipeline before EOL.</p>
<!-- flag: flag{cdad904c3f229c8a33f6b9a37b2ec64b} -->
<!-- last deploy: soulsecure-prod-assets bucket sync job, owner: devops@soulsecure.lab -->
</body></html>
"""

@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "Jetty(9.4.z-SNAPSHOT)"
    resp.headers["X-Jenkins"] = "2.204.1"
    resp.headers["X-Jenkins-Session"] = "e13f9c2a"
    return resp

@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")

# ---------------------------------------------------------------------------
# Module 3 Lab 3: Exposed CI/CD Server Exploitation
# ---------------------------------------------------------------------------

if M3 >= 3:
    JOBS = ["nightly-deploy", "legacy-deploy-script", "site-healthcheck"]

    CONFIG_XML = {
        "nightly-deploy": """<?xml version='1.1' encoding='UTF-8'?>
<project>
  <description>Nightly sync to soulsecure-prod-assets</description>
  <builders>
    <hudson.tasks.Shell>
      <command>aws s3 sync ./dist s3://soulsecure-prod-assets --delete</command>
    </hudson.tasks.Shell>
  </builders>
  <credentialsId>soulsecure-ci-deploy</credentialsId>
</project>
""",
        "legacy-deploy-script": """<?xml version='1.1' encoding='UTF-8'?>
<project>
  <description>Legacy deploy job -- predates the credentials store migration</description>
  <builders>
    <hudson.tasks.Shell>
      <command>export AWS_ACCESS_KEY_ID=AKIAFAKESOULSECURE0x
export AWS_SECRET_ACCESS_KEY=fakeSecretKeyForLabPurposesOnly1234567890AB
./deploy.sh
</command>
    </hudson.tasks.Shell>
  </builders>
  <!-- flag{0f04c87f9bd39778b962621ed4e624be} -->
</project>
""",
        "site-healthcheck": """<?xml version='1.1' encoding='UTF-8'?>
<project>
  <description>Pings the site every 5 minutes, pages on-call on failure</description>
  <builders>
    <hudson.tasks.Shell>
      <command>curl -sf https://www.soulsecure.lab/ || exit 1</command>
    </hudson.tasks.Shell>
  </builders>
</project>
""",
    }

    CREDENTIALS_XML = """<?xml version='1.1' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider>
  <domainCredentialsMap>
    <entry>
      <com.amazonaws.auth.profile.internal.BasicProfileAWSCredentials>
        <id>soulsecure-ci-deploy</id>
        <description>Used by nightly-deploy for S3 sync to soulsecure-prod-assets -- do not use for anything else</description>
        <accessKey>ASIASOULSECURECIDEPLOY03</accessKey>
        <secretKey>ci7d3f1a9c4e6b8021d5a3f7c9e1b048d</secretKey>
      </com.amazonaws.auth.profile.internal.BasicProfileAWSCredentials>
    </entry>
  </domainCredentialsMap>
  <!-- flag{693ed3542feda5a18e6e859787894745} -->
</com.cloudbees.plugins.credentials.SystemCredentialsProvider>
"""

    USER_CONTENT = {}  # filename -> content, in-memory, reset on restart
    BACKDOORED_JOBS = set()  # Module 5 Lab 5: jobs whose config.xml was backdoored
    ORIGINAL_CONFIG_XML = dict(CONFIG_XML)  # snapshot for /admin/reverse-backdoors

    @app.route("/api/json")
    def api_json():
        return jsonify(jobs=[{"name": j} for j in JOBS])

    SCRIPT_CONSOLE_PAGE = """<!DOCTYPE html>
<html><head><title>Script Console [Jenkins]</title></head>
<body>
<h1>Script Console</h1>
<form method="POST" action="/script">
  <textarea name="script" rows="10" cols="80"></textarea><br>
  <input type="submit" value="Run">
</form>
</body></html>
"""

    @app.route("/script", methods=["GET"])
    def script_console():
        return Response(SCRIPT_CONSOLE_PAGE, mimetype="text/html")

    @app.route("/script", methods=["POST"])
    def script_run():
        script = request.form.get("script", "")

        if '"id".execute()' in script or '"whoami".execute()' in script:
            return Response(
                "uid=999(jenkins) gid=999(jenkins) groups=999(jenkins)\n"
                "<!-- flag{d960fb25c0bad0f0d100c6e18a12472d} -->\n",
                mimetype="text/plain",
            )

        if "credentials.xml" in script:
            return Response(CREDENTIALS_XML, mimetype="text/plain")

        # Module 5 Lab 5: job-config backdoor. Checked BEFORE the generic
        # userContent-write pattern below, since a job-config write also
        # contains "new File(" + ".text" + "=" and would otherwise get
        # misrouted into that branch.
        if M5 >= 5 and "new File(" in script and "jobs/" in script and "config.xml" in script:
            import re
            m = re.search(r'jobs/([\w\-]+)/config\.xml', script)
            job_name = m.group(1) if m else None
            m2 = re.search(r'=\s*"(.*)"', script, re.DOTALL)
            new_content = m2.group(1) if m2 else ""
            if job_name and job_name in CONFIG_XML and "<hudson.tasks.Shell>" in new_content:
                CONFIG_XML[job_name] = new_content
                BACKDOORED_JOBS.add(job_name)
                return Response(
                    "config updated\n<!-- flag{17505a3ed3e5019ecd053a6430313ff2} -->\n",
                    mimetype="text/plain",
                )
            return Response("error: job not found or content missing a recognizable build step\n",
                             mimetype="text/plain")

        if "new File(" in script and ".text" in script and "=" in script:
            # Extract a target filename under userContent/ -- best-effort
            # parse, good enough for the lab's guided technique.
            import re
            m = re.search(r'userContent/([\w.\-]+)"?\)', script)
            filename = m.group(1) if m else "poc.txt"
            m2 = re.search(r'=\s*"([^"]*)"', script)
            content = m2.group(1) if m2 else "written by script console"
            USER_CONTENT[filename] = content
            if "flag.txt" not in USER_CONTENT:
                USER_CONTENT["flag.txt"] = (
                    "Nice work proving code execution end-to-end.\n"
                    "flag{feb917557da0726b5bd11d97fd376dff}\n"
                )
            return Response(f"wrote {len(content)} bytes to /var/jenkins_home/userContent/{filename}\n",
                             mimetype="text/plain")

        return Response(
            "error: unrecognized script (this console only responds to a "
            "limited set of demonstrated techniques in this lab)\n",
            mimetype="text/plain",
        )

    @app.route("/job/<name>/config.xml")
    def job_config(name):
        xml = CONFIG_XML.get(name)
        if xml is None:
            return Response("job not found", status=404)
        return Response(xml, mimetype="application/xml")

    @app.route("/userContent/<path:filename>")
    def user_content(filename):
        content = USER_CONTENT.get(filename)
        if content is None:
            return Response("Not Found", status=404)
        return Response(content, mimetype="text/plain")

    if M5 >= 5:
        @app.route("/admin/reverse-backdoors", methods=["POST"])
        def admin_reverse_backdoors():
            """Internal-only bridge route -- called by iam-sim's
            /admin/simulate-deep-audit, not part of the student-facing
            surface (no auth of its own; only reachable Docker-internally,
            same pattern as backup_admin_app.py's register-backdoor-key)."""
            for job_name in list(BACKDOORED_JOBS):
                if job_name in ORIGINAL_CONFIG_XML:
                    CONFIG_XML[job_name] = ORIGINAL_CONFIG_XML[job_name]
                BACKDOORED_JOBS.discard(job_name)
            return jsonify(status="reversed")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090)
