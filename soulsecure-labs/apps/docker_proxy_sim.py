#!/usr/bin/env python3
"""docker-proxy -- Module 5 Lab 3. Simplified SIMULATION of a subset of the
real Docker Engine HTTP API (port-2375 convention). Internal-only, no
published port, no vhost/DNS -- reachable only via bastion's /proxy.

*** SAFETY-CRITICAL: this file must NEVER touch a real Docker socket. ***
Everything below is in-memory state and pattern-matched string content.
There is no `docker` SDK import, no subprocess call, no filesystem access
outside this process, and this container is never granted the host's
/var/run/docker.sock, privileged mode, or any host bind mount in
docker-compose.yml. A bug here can make the *simulation* behave oddly; it
cannot reach the real Docker daemon running the lab stack, because this
process has no code path that ever attempts to.

Auth: same self-contained X-Access-Key-Id/X-Secret-Access-Key convention
as storage_app.py, checked independently here (not a call-out to iam-sim),
matching soulsecure-internal-svc-role's credentials from Lab 2.
"""
import os
import secrets
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

VALID_CREDS = {"ASIAINTERNALSVC04": "isvc9c2d7f1a4e6b8021d5a3f7c9e1b048"}

# Canned inventory -- a fake "here's everything running" list. Not read from
# the real Docker daemon; hand-authored to match this stack's actual service
# names for narrative realism only.
CONTAINER_INVENTORY = [
    {"Id": "c1a2b3c4d5e6", "Names": ["/www"], "Image": "soulsecure-lab-www", "Labels": {}},
    {"Id": "c2a2b3c4d5e6", "Names": ["/api"], "Image": "soulsecure-lab-api", "Labels": {}},
    {"Id": "c3a2b3c4d5e6", "Names": ["/storage"], "Image": "soulsecure-lab-storage", "Labels": {}},
    {"Id": "c4a2b3c4d5e6", "Names": ["/jenkins-old"], "Image": "soulsecure-lab-jenkins", "Labels": {}},
    {"Id": "c5a2b3c4d5e6", "Names": ["/iam-sim"], "Image": "soulsecure-lab-iam-sim", "Labels": {}},
    {"Id": "c6a2b3c4d5e6", "Names": ["/bastion"], "Image": "soulsecure-lab-bastion", "Labels": {}},
    {"Id": "c7a2b3c4d5e6", "Names": ["/internal-svc"], "Image": "soulsecure-lab-internal-svc", "Labels": {}},
    {"Id": "c8a2b3c4d5e6", "Names": ["/backup-eu"], "Image": "soulsecure-lab-backup-eu", "Labels": {}},
    {"Id": "c9a2b3c4d5e6", "Names": ["/docker-proxy"], "Image": "soulsecure-lab-docker-proxy",
     "Labels": {"flag": "flag{328eabb244a10c29a66df568dd066ab9}"}},
]

HOST_SECRET_TXT = (
    "This file only exists on the host filesystem, outside any container.\n"
    "If you can read this, your container escape actually reached the host.\n"
    "flag{d4e90ea050335b467c43e1c69546d9c9}\n"
)

# In-memory simulated state -- reset on container restart, no persistence,
# no relationship to any real container/exec on this or any other host.
CONTAINERS = {}   # id -> {"privileged_host_mount": bool}
EXECS = {}        # id -> {"container_id": str, "cmd": list}
CRON_PERSISTED = {"value": False}


def authenticated():
    akid = request.headers.get("X-Access-Key-Id")
    secret = request.headers.get("X-Secret-Access-Key")
    return akid and secret and VALID_CREDS.get(akid) == secret


if M5 >= 3:
    @app.route("/v1.41/containers/json")
    def containers_json():
        if not authenticated():
            return jsonify(error="unauthorized"), 403
        return jsonify(CONTAINER_INVENTORY)

    @app.route("/v1.41/containers/create", methods=["POST"])
    def containers_create():
        if not authenticated():
            return jsonify(error="unauthorized"), 403
        body = request.get_json(silent=True) or {}
        binds = (body.get("HostConfig") or {}).get("Binds") or []
        # Simulated check only -- no real bind mount is ever created; this
        # just decides what the SIMULATED container record remembers.
        full_root_mount = any(b.split(":")[0] == "/" and b.split(":", 2)[1] == "/host" for b in binds if ":" in b)
        cid = secrets.token_hex(12)
        CONTAINERS[cid] = {"privileged_host_mount": full_root_mount}
        return jsonify(Id=cid)

    @app.route("/v1.41/containers/<cid>/start", methods=["POST"])
    def containers_start(cid):
        if not authenticated():
            return jsonify(error="unauthorized"), 403
        c = CONTAINERS.get(cid)
        if c is None:
            return jsonify(error="no such container"), 404
        if c["privileged_host_mount"]:
            return jsonify(status="started", flag="flag{cab288312382b1a7d0294645aa360e97}")
        return jsonify(status="started")

    @app.route("/v1.41/containers/<cid>/exec", methods=["POST"])
    def containers_exec(cid):
        if not authenticated():
            return jsonify(error="unauthorized"), 403
        if cid not in CONTAINERS:
            return jsonify(error="no such container"), 404
        body = request.get_json(silent=True) or {}
        cmd = body.get("Cmd", [])
        eid = secrets.token_hex(12)
        EXECS[eid] = {"container_id": cid, "cmd": cmd}
        return jsonify(Id=eid)

    @app.route("/v1.41/exec/<eid>/start", methods=["POST"])
    def exec_start(eid):
        if not authenticated():
            return jsonify(error="unauthorized"), 403
        e = EXECS.get(eid)
        if e is None:
            return jsonify(error="no such exec"), 404
        c = CONTAINERS.get(e["container_id"])
        if not c or not c["privileged_host_mount"]:
            return jsonify(output="", note="exec target was never a host-mounted container -- no host access")
        cmd_str = " ".join(str(x) for x in e["cmd"])
        if "cat" in e["cmd"] and "/host/opt/soulsecure-labs/HOST-SECRET.txt" in e["cmd"]:
            return jsonify(output=HOST_SECRET_TXT)
        if "/host/etc/cron.d/soulsecure-persist" in cmd_str:
            CRON_PERSISTED["value"] = True
            return jsonify(output="", status="written")
        return jsonify(output="", note="command not recognized by this simulation")

    @app.route("/host-check/cron")
    def host_check_cron():
        if not authenticated():
            return jsonify(error="unauthorized"), 403
        resp = {"cron_persisted": CRON_PERSISTED["value"]}
        if CRON_PERSISTED["value"]:
            resp["flag"] = "flag{97d00066d487c67fcc100bb04e50ef29}"
        return jsonify(**resp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=2375)
