#!/usr/bin/env python3
"""storage.soulsecure.lab -- fake S3-compatible object storage endpoint (port 8081).

Gating uses two axes now: LAB_MODULE (which module is currently active) and
LAB_LEVEL (level within that module). Module 2's bucket registry (Lab 4) is
gated on M2 = effective Module 2 level (5/fully-unlocked once LAB_MODULE > 2,
otherwise LAB_LEVEL). Module 3's additions (Lab 1: leaked-credential auth,
public-write bucket, presign abuse) are gated on M3 = effective Module 3
level, same pattern -- see docstring math below.

  M2 1-3 -> only "/" is meaningful (fingerprint-only, AccessDenied), no
            bucket ever resolves (all bucket paths -> NoSuchBucket)
  M2 4+  -> full Module 2 bucket registry (Lab 4)
  M3 1+  -> Module 3 Lab 1: soulsecure-secrets-eu (leaked creds), auth-gated
            soulsecure-dev-assets, public-write soulsecure-uploads-public,
            presign-only soulsecure-finance-records, /presign route
"""
import json
import os
import secrets
import time
from flask import Flask, Response, request, jsonify

app = Flask(__name__)
LAB_MODULE = int(os.environ.get("LAB_MODULE", "2"))
LAB_LEVEL = int(os.environ.get("LAB_LEVEL", "5"))

# Same tenant, doesn't reset: Module 2 content stays fully unlocked once
# LAB_MODULE moves past 2. M3 is 0 (nothing) until LAB_MODULE actually
# reaches 3, then tracks LAB_LEVEL while on Module 3, then stays fully
# unlocked (5) once LAB_MODULE moves past 3 too.
def _module_level(module_num):
    if LAB_MODULE > module_num:
        return 5
    if LAB_MODULE == module_num:
        return LAB_LEVEL
    return 0

M2 = _module_level(2)
M3 = _module_level(3)
M4 = _module_level(4)
M5 = _module_level(5)

ACCESS_DENIED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>7B2F1A9C4E6D8801</RequestId>
  <HostId>soulsecure-prod-assets.s3.soulsecure.lab</HostId>
</Error>
"""

NO_SUCH_BUCKET_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
  <BucketName>{bucket}</BucketName>
  <RequestId>7B2F1A9C4E6D8802</RequestId>
</Error>
"""

NO_SUCH_KEY_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Key>{key}</Key>
  <RequestId>7B2F1A9C4E6D8803</RequestId>
</Error>
"""

LIST_BUCKET_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.soulsecure.lab/doc/2006-03-01/">
  <Name>{bucket}</Name>
  <Prefix></Prefix>
  <KeyCount>{count}</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
{contents}</ListBucketResult>
"""

CONTENT_ENTRY = """  <Contents>
    <Key>{key}</Key>
    <Size>{size}</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
"""

BUCKETS = {}
if M2 >= 4:
    BUCKETS = {
        "soulsecure-prod-assets": {
            "public": True,
            "objects": {
                "README.txt": "SoulSecure prod asset bucket. See config/ for environment configs.\n",
                "logo.png": "<not a real image -- lab placeholder content>\n",
                "config/backup-2026-07-01.json": json.dumps({
                    "db_host": "prod-db.internal.soulsecure.lab",
                    "db_user": "soulsecure_app",
                    "db_password": "Sup3rS3cretProdPW!",
                    "stripe_api_key": "sk_live_51HFAKESOULSECUREDONOTUSE0000",
                    "note": "lab-only placeholder secrets, not real credentials",
                    "flag": "flag{c3909083d936385564ffe54a86c340b9}",
                }, indent=2) + "\n",
            },
        },
        "soulsecure-dev-assets": {"public": False, "objects": {}},
        "soulsecure-backups-eu": {
            "public": True,
            "objects": {
                "db-snapshot-notes.txt": (
                    "Nightly snapshot notes -- backup-eu region\n"
                    "Retention: 30 days\n"
                    "Last verified restore: 2026-06-15\n"
                    "flag{bb244e7d9025c5600bdc019ad5c726dc}\n"
                ),
            },
        },
        "soulsecure-terraform-state": {
            "public": True,
            "objects": {
                "terraform.tfstate": json.dumps({
                    "version": 4,
                    "terraform_version": "1.7.5",
                    "outputs": {
                        "vpc_id": {"value": "vpc-0fake1234567890ab"},
                        "rds_endpoint": {"value": "prod-db.internal.soulsecure.lab:5432"},
                        "deploy_role_access_key": {"value": "AKIAFAKESOULSECURE02"},
                    },
                    "note": "lab-only placeholder values, not a real state file",
                    "flag": "flag{e21e4a4043ae07729741ef42be7dc9af}",
                }, indent=2) + "\n",
            },
        },
    }

# ---------------------------------------------------------------------------
# Module 3 Lab 1: Authenticated & Misconfigured Object Storage Exploitation
#
# Mints its OWN, mechanically distinct, genuinely functional credential
# (SVCKEY-STORAGE-RO-8841) -- deliberately NOT the AKIAFAKESOULSECURE0x
# pattern used elsewhere as non-functional narrative glue (M2 Lab3/Lab4).
# ---------------------------------------------------------------------------
CREDENTIALS = {}
PRESIGN_TOKENS = {}  # token -> {"bucket": str, "key": str, "expires": epoch}

if M3 >= 1:
    SVC_ACCESS_KEY_ID = "SVCKEY-STORAGE-RO-8841"
    SVC_SECRET_ACCESS_KEY = "f6a2c9d1b4e7091834fcab52d6e9871a3c5d0e8"
    CREDENTIALS[SVC_ACCESS_KEY_ID] = SVC_SECRET_ACCESS_KEY

    BUCKETS["soulsecure-secrets-eu"] = {
        "public": True,
        "objects": {
            "access-keys.json": json.dumps({
                "access_key_id": SVC_ACCESS_KEY_ID,
                "secret_access_key": SVC_SECRET_ACCESS_KEY,
                "note": "read-only service key for internal tooling -- rotate quarterly",
                "flag": "flag{66ad82418609288526a5ad4afa075fb4}",
            }, indent=2) + "\n",
        },
    }

    # Same bucket name Module 2 Lab 4 found as a confirmed-but-denied 403 --
    # now it actually has content, reachable with the creds leaked above.
    BUCKETS["soulsecure-dev-assets"] = {
        "public": False,
        "auth_required": True,
        "objects": {
            "internal-notes.txt": (
                "dev-assets internal notes\n"
                "-- creds for this bucket were never rotated after the July "
                "incident (see the prod-assets TODO from way back). still "
                "using the same service key today.\n"
                "flag{5c8b4809ead97e71ce62cb3d420a42c5}\n"
            ),
        },
    }

    BUCKETS["soulsecure-uploads-public"] = {
        "public": True,
        "public_write": True,
        "objects": {
            "pending-releases/Q3-roadmap-draft.txt": (
                "Q3 roadmap draft -- DO NOT SHARE EXTERNALLY\n"
                "- migrate remaining S3 buckets to least-privilege policies\n"
                "- rotate the storage service key (still on the 2025 one...)\n"
                "flag{3486829bf77c89a06243cef73e03c12e}\n"
            ),
        },
    }

    # Different service identity on purpose -- the M3 Lab 1 creds must NOT
    # work here. Direct access is 403 for those. The M3-only path in is a
    # presigned URL minted by the unauthenticated /presign endpoint below
    # (the actual vulnerability: missing authorization check, not missing
    # authentication). Module 4 Lab 4 adds a SECOND, legitimate path in --
    # see FINANCE_SPECIAL_CREDS below (cross-module edit, see that lab's
    # InstructorKey "Cross-module extension" section).
    FINANCE_OBJECTS = {
        "board-notes-confidential.txt": (
            "Board notes (confidential) -- Q3 review\n"
            "Do not distribute. Storage team: please confirm this bucket "
            "is not reachable from the presign service before next audit.\n"
            "flag{5333191eb62f388705bfd1b76598b8cb}\n"
        ),
    }
    FINANCE_SPECIAL_CREDS = {}
    if M4 >= 4:
        # Module 4 Lab 4: credentials issued by iam-sim's /sts/assume-role
        # for soulsecure-finance-role. Byte-identical to iam_sim.py's value.
        FINANCE_SPECIAL_CREDS["ASIAFINANCE77"] = "fin4a1c7d3f9e6b8021d5a3f7c9e1b048c"
        FINANCE_OBJECTS["finance-role-only-notes.txt"] = (
            "Q3 numbers hold in the usual place. -- Finance team\n"
            "flag{e09a5ffcdc93f8f4956afa51abe36b6c}\n"
        )

    BUCKETS["soulsecure-finance-records"] = {
        "public": False,
        "objects": FINANCE_OBJECTS,
        "special_creds": FINANCE_SPECIAL_CREDS,
    }

# ---------------------------------------------------------------------------
# Module 5 Lab 4: bucket-policy read/write on soulsecure-finance-records.
# Admin-equivalent only -- same hardcoded-check pattern as the rest of this
# self-contained app (matches backup_admin_app.py's simplification for the
# same lab).
# ---------------------------------------------------------------------------
BUCKET_POLICY_ADMIN_KEYS = {"ASIAADMIN99": "adm9c2d7f1a4e6b8021d5a3f7c9e1b048"}
BUCKET_POLICIES = {}
if M5 >= 4:
    BUCKET_POLICIES["soulsecure-finance-records"] = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::445566778899:root"},
             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::soulsecure-finance-records/*"},
        ],
    }


def bucket_policy_admin_authenticated():
    akid = request.headers.get("X-Access-Key-Id")
    secret = request.headers.get("X-Secret-Access-Key")
    return akid and secret and BUCKET_POLICY_ADMIN_KEYS.get(akid) == secret


def check_auth(bucket_dict):
    """True if the bucket is public, valid special-credential headers were
    sent (a second, distinct credential path some buckets accept -- e.g.
    Module 4 Lab 4's assumed-role creds on soulsecure-finance-records), or
    valid X-Access-Key-Id/X-Secret-Access-Key headers matching the standard
    Module 3 Lab 1 credential."""
    if bucket_dict.get("public"):
        return True
    akid = request.headers.get("X-Access-Key-Id")
    secret = request.headers.get("X-Secret-Access-Key")
    special_creds = bucket_dict.get("special_creds")
    if special_creds and akid and secret and special_creds.get(akid) == secret:
        return True
    if bucket_dict.get("auth_required"):
        if akid and secret and CREDENTIALS.get(akid) == secret:
            return True
    return False


@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "SoulSecureObjectStore"
    resp.headers["x-amz-request-id"] = "7B2F1A9C4E6D8801"
    resp.headers["x-amz-bucket-region"] = "us-east-1"
    return resp

if M5 >= 4:
    @app.route("/soulsecure-finance-records/_policy", methods=["GET"])
    def finance_bucket_policy_get():
        return jsonify(**BUCKET_POLICIES["soulsecure-finance-records"])

    @app.route("/soulsecure-finance-records/_policy", methods=["POST"])
    def finance_bucket_policy_post():
        if not bucket_policy_admin_authenticated():
            return jsonify(error="AccessDenied"), 403
        body = request.get_json(silent=True) or {}
        account = body.get("add_principal_account", "")
        if not account:
            return jsonify(error="add_principal_account is required"), 400
        BUCKET_POLICIES["soulsecure-finance-records"]["Statement"].append({
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::soulsecure-finance-records/*",
        })
        return jsonify(status="policy updated", flag="flag{24c7e5fff5028119ff5ea792639037c6}")

# GCS-style bucket (Lab 4 addition) -- SoulSecure isn't all-AWS. Same
# permutation-guessing technique, different provider, different URL shape
# (Google Cloud Storage's JSON API: /storage/v1/b/<bucket>/o[...]). Not
# hinted anywhere -- found only by recognizing the pattern and guessing.
GCS_BUCKETS = {}
if M2 >= 4:
    GCS_BUCKETS = {
        "soulsecure-gcs-assets": {
            "public": True,
            "objects": {
                "notes/migration-plan.txt": (
                    "Migration notes: moving remaining prod assets from S3 to GCS "
                    "by end of quarter. Bucket ACL review still pending.\n"
                    "flag{b091f26222ff3e2e245ee90a35927202}\n"
                ),
            },
        },
    }

@app.route("/")
def root():
    return Response(ACCESS_DENIED_XML, mimetype="application/xml", status=403)

@app.route("/storage/v1/b/<bucket>/o")
def gcs_list_objects(bucket):
    b = GCS_BUCKETS.get(bucket)
    if b is None:
        return jsonify(error={"code": 404, "message": f"Bucket {bucket} not found"}), 404
    if not b["public"]:
        return jsonify(error={"code": 403, "message": "Permission denied"}), 403
    items = [{"name": k, "size": str(len(v)), "bucket": bucket} for k, v in b["objects"].items()]
    return jsonify(kind="storage#objects", items=items)

@app.route("/storage/v1/b/<bucket>/o/<path:obj>")
def gcs_get_object(bucket, obj):
    b = GCS_BUCKETS.get(bucket)
    if b is None:
        return jsonify(error={"code": 404, "message": f"Bucket {bucket} not found"}), 404
    if not b["public"]:
        return jsonify(error={"code": 403, "message": "Permission denied"}), 403
    content = b["objects"].get(obj)
    if content is None:
        return jsonify(error={"code": 404, "message": f"Object {obj} not found"}), 404
    if request.args.get("alt") == "media":
        return Response(content, mimetype="text/plain")
    return jsonify(kind="storage#object", name=obj, bucket=bucket, size=str(len(content)))

if M3 >= 1:
    @app.route("/presign")
    def presign():
        """No authentication or ownership check -- that's the entire
        vulnerability. Any caller can mint a working URL for any bucket/key
        that exists, including buckets that are otherwise unreachable."""
        bucket = request.args.get("bucket", "")
        key = request.args.get("key", "")
        b = BUCKETS.get(bucket)
        if b is None or key not in b.get("objects", {}):
            return jsonify(error="NoSuchBucket or NoSuchKey"), 404
        token = secrets.token_urlsafe(24)
        expires = int(time.time()) + 24 * 3600  # 24h -- generous on purpose,
        # expiry isn't the point of this exercise, the missing authz check is
        PRESIGN_TOKENS[token] = {"bucket": bucket, "key": key, "expires": expires}
        url = (f"https://storage.soulsecure.lab/{bucket}/{key}"
               f"?X-Sig={token}&X-Expires={expires}")
        return jsonify(url=url)

@app.route("/<bucket>")
@app.route("/<bucket>/")
def list_bucket(bucket):
    b = BUCKETS.get(bucket)
    if b is None:
        return Response(NO_SUCH_BUCKET_XML.format(bucket=bucket), mimetype="application/xml", status=404)
    if not check_auth(b):
        return Response(ACCESS_DENIED_XML, mimetype="application/xml", status=403)
    contents = "".join(
        CONTENT_ENTRY.format(key=k, size=len(v)) for k, v in b["objects"].items()
    )
    xml = LIST_BUCKET_XML.format(bucket=bucket, count=len(b["objects"]), contents=contents)
    return Response(xml, mimetype="application/xml", status=200)

@app.route("/<bucket>/<path:key>", methods=["GET", "PUT"])
def object_route(bucket, key):
    b = BUCKETS.get(bucket)
    if b is None:
        return Response(NO_SUCH_BUCKET_XML.format(bucket=bucket), mimetype="application/xml", status=404)

    if request.method == "PUT":
        if not b.get("public_write"):
            return Response(ACCESS_DENIED_XML, mimetype="application/xml", status=403)
        data = request.get_data(cache=False)[:10 * 1024]  # 10KB cap -- lab hygiene, not realism
        if not data:
            return jsonify(error="empty body"), 400
        b["objects"][key] = data.decode("utf-8", errors="replace")
        return Response("", status=200, headers={"ETag": '"' + secrets.token_hex(16) + '"'})

    # GET below. Presigned access is checked first -- it bypasses every
    # other rule when the signature matches, by design: that's the whole
    # point of the Module 3 Lab 1 vulnerability.
    sig = request.args.get("X-Sig")
    if sig:
        tok = PRESIGN_TOKENS.get(sig)
        if not tok or tok["bucket"] != bucket or tok["key"] != key or tok["expires"] < time.time():
            return Response(ACCESS_DENIED_XML, mimetype="application/xml", status=403)
        obj = b["objects"].get(key)
        if obj is None:
            return Response(NO_SUCH_KEY_XML.format(key=key), mimetype="application/xml", status=404)
        mimetype = "application/json" if key.endswith(".json") else "text/plain"
        return Response(obj, mimetype=mimetype, status=200)

    if not check_auth(b):
        return Response(ACCESS_DENIED_XML, mimetype="application/xml", status=403)
    obj = b["objects"].get(key)
    if obj is None:
        return Response(NO_SUCH_KEY_XML.format(key=key), mimetype="application/xml", status=404)
    mimetype = "application/json" if key.endswith(".json") else "text/plain"
    return Response(obj, mimetype=mimetype, status=200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
