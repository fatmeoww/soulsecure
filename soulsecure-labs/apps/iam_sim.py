#!/usr/bin/env python3
"""iam.soulsecure.lab -- mock AWS-style IAM/STS control plane + one GCP-
flavored surface, for Module 4 (IAM Exploitation & Privilege Escalation).

Genuinely enforced policy evaluation: privilege escalation actually changes
what is_allowed() returns for subsequent calls -- not canned success
responses with no real state change. Auth uses the same X-Access-Key-Id/
X-Secret-Access-Key header convention established in Module 3 Lab 1, plus
X-GCP-Client-Email for the GCP-flavored routes. Credential values are
byte-identical to Module 3's, so a Module 3 haul works directly here.

Gated on LAB_MODULE=4, cumulative by LAB_LEVEL (1-5), same MODULE/LEVEL
scheme as Module 3.
"""
import os
import secrets
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


M4 = _module_level(4)
M5 = _module_level(5)

ACCOUNT_ID = "445566778899"

# ---------------------------------------------------------------------------
# Policy documents -- real AWS policy JSON. `default` points at the
# currently-active version; `versions` holds full history (Lab 3's self-
# managed-policy escalation writes new versions here without changing
# `default` until set-default-policy-version is called -- a genuine,
# stateful change, not a canned response).
# ---------------------------------------------------------------------------
POLICIES = {
    "AppRoleReadOnly": {
        "description": "Read-only baseline for the app instance role.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::soulsecure-*/*"},
            ],
        }},
    },
    "DeployRolePolicy": {
        "description": "Deployment automation permissions for soulsecure-deploy-role.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["s3:*"], "Resource": "arn:aws:s3:::soulsecure-*"},
                {"Effect": "Allow", "Action": ["iam:PassRole"], "Resource": "arn:aws:iam::445566778899:role/automation-*"},
                {"Effect": "Allow", "Action": ["automation:CreateTask", "automation:GetTaskResult"], "Resource": "*"},
            ],
        }},
    },
    "CIDeployPolicy": {
        "description": "CI deploy user permissions -- can manage its own policy's versions.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::soulsecure-*-assets/*"},
                {"Effect": "Allow", "Action": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                                                "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"],
                 "Resource": "arn:aws:iam::445566778899:policy/CIDeployPolicy"},
            ],
        }},
    },
    "StorageReadOnlyPolicy": {
        "description": "Read-only access to soulsecure-dev-assets. Value already spent in Module 3.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                 "Resource": ["arn:aws:s3:::soulsecure-dev-assets", "arn:aws:s3:::soulsecure-dev-assets/*"]},
            ],
        }},
    },
    "AdministratorAccess": {
        "description": "Full administrative access -- the account's de facto AdministratorAccess-equivalent.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }},
    },
}

if M4 >= 2:
    POLICIES["LegacyReadOnlyAuditPolicy"] = {
        "description": "Left over from an account-wide security audit last year. Never revoked.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": [
                    "iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion",
                    "iam:ListAttachedRolePolicies", "iam:ListAttachedUserPolicies", "iam:GetTrustPolicy",
                ], "Resource": "*"},
            ],
        }},
    }
    POLICIES["FinanceRolePolicy"] = {
        "description": "Read access to the finance records bucket only.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"],
                 "Resource": ["arn:aws:s3:::soulsecure-finance-records", "arn:aws:s3:::soulsecure-finance-records/*"]},
            ],
        }},
    }

if M4 >= 5:
    POLICIES["DeployRolePolicy"]["versions"]["v1"]["Statement"].append(
        {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"], "Resource": "*"}
    )

if M5 >= 2:
    POLICIES["InternalSvcRolePolicy"] = {
        "description": "Permissions for the internal-svc instance role reached via the bastion pivot.",
        "default": "v1",
        "versions": {"v1": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sts:GetCallerIdentity"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["compute:AccessDockerProxy"],
                 "Resource": "arn:aws:compute:::docker-proxy"},
            ],
        }},
    }

# ---------------------------------------------------------------------------
# Principals -- standing AWS-style identities. Credential values are
# byte-identical to Module 3's (see each principal's source lab noted below).
# ---------------------------------------------------------------------------
PRINCIPALS = {
    "soulsecure-app-role": {
        "type": "role",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/soulsecure-app-role",
        "access_key_id": "ASIASOULSECUREAPP01",
        "secret": "app9f2c7a1e4b6d8801f3a5c9d2e6b1084",  # Module 3 Lab 2 (IMDS app-role)
        "attached_policies": ["AppRoleReadOnly"],
    },
    "soulsecure-deploy-role": {
        "type": "role",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/soulsecure-deploy-role",
        "access_key_id": "ASIASOULSECUREDEPLOY02",
        "secret": "deploy3d7f1a9c4e6b8021d5a3f7c9e1b048",  # Module 3 Lab 2 harder (IMDSv2 deploy-role)
        "attached_policies": ["DeployRolePolicy", "LegacyReadOnlyAuditPolicy"],
    },
    "soulsecure-ci-deploy": {
        "type": "user",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/soulsecure-ci-deploy",
        "access_key_id": "ASIASOULSECURECIDEPLOY03",
        "secret": "ci7d3f1a9c4e6b8021d5a3f7c9e1b048d",  # Module 3 Lab 3 (Jenkins credentials.xml)
        "attached_policies": ["CIDeployPolicy"],
    },
    "storage-readonly": {
        "type": "user",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/storage-readonly",
        "access_key_id": "SVCKEY-STORAGE-RO-8841",
        "secret": "f6a2c9d1b4e7091834fcab52d6e9871a3c5d0e8",  # Module 3 Lab 1 (soulsecure-secrets-eu)
        "attached_policies": ["StorageReadOnlyPolicy"],
    },
    # Crown jewel -- no standing credential exists for this role. Only ever
    # reachable, never found lying around (see Lab 1 InstructorKey design notes).
    "automation-admin-role": {
        "type": "role",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/automation-admin-role",
        "access_key_id": None,
        "secret": None,
        "attached_policies": ["AdministratorAccess"],
    },
}

if M4 >= 2:
    PRINCIPALS["soulsecure-finance-role"] = {
        "type": "role",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/soulsecure-finance-role",
        "access_key_id": None,  # assume-only until Lab 4
        "secret": None,
        "attached_policies": ["FinanceRolePolicy"],
        "trust_policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                            "Action": "sts:AssumeRole"}],
        },
    }

if M4 >= 3:
    # Temporary credentials issued via the PassRole+CreateTask escalation
    # chain (Lab 3 Flag 1). Distinct, mechanically, from a standing
    # credential -- treated as short-lived, consistent with how real STS
    # temp creds behave.
    PRINCIPALS["automation-admin-role"]["access_key_id"] = "ASIAADMIN99"
    PRINCIPALS["automation-admin-role"]["secret"] = "adm9c2d7f1a4e6b8021d5a3f7c9e1b048"

if M4 >= 4:
    # Temporary credentials issued via sts:assume-role (Lab 4 Flag 1).
    PRINCIPALS["soulsecure-finance-role"]["access_key_id"] = "ASIAFINANCE77"
    PRINCIPALS["soulsecure-finance-role"]["secret"] = "fin4a1c7d3f9e6b8021d5a3f7c9e1b048c"

if M5 >= 2:
    # Standing credential, reachable via internal-svc's IMDS mock (Module 5
    # Lab 2) -- this role's only interesting permission is the Lab 3 hook.
    PRINCIPALS["soulsecure-internal-svc-role"] = {
        "type": "role",
        "arn": f"arn:aws:iam::{ACCOUNT_ID}:role/soulsecure-internal-svc-role",
        "access_key_id": "ASIAINTERNALSVC04",
        "secret": "isvc9c2d7f1a4e6b8021d5a3f7c9e1b048",
        "attached_policies": ["InternalSvcRolePolicy"],
    }

CREDENTIAL_INDEX = {p["access_key_id"]: name for name, p in PRINCIPALS.items() if p.get("access_key_id")}

# ---------------------------------------------------------------------------
# Module 5 mutable state -- backdoors, revocations, and scheduled tasks all
# genuinely persist server-side and affect subsequent calls, same "actually
# stateful" bar as Module 4's policy evaluator.
# ---------------------------------------------------------------------------
REVOKED_KEYS = set()          # Lab 1: access key IDs revoked by remediation
LOCKED_POLICIES = set()       # Lab 1: policies remediation locked from further changes
BACKDOOR_STATE = {}           # Lab 1/5: tracks the new-user backdoor for self-heal
BACKDOOR_KEYS_SEEN = set()    # Lab 1: every backdoor-sourced access key, for Flag 4
SCHEDULED_TASKS = []          # Lab 5: automation tasks with a `schedule` field
REMEDIATION_STATE = {"ran": False}
DEEP_AUDIT_STATE = {"ran": False}   # Lab 5: gates the harder-mode trust-policy-survives flag
CANONICAL_PRINCIPALS = set(PRINCIPALS.keys())  # snapshot before any student mutation

BACKUP_ADMIN_URL = "http://backup-admin:8700/admin/register-backdoor-key"


def _notify_backup_admin(access_key_id, secret):
    """Best-effort bridge so a Module 5 Lab 1 backdoor key also works
    against Module 5 Lab 4's backup-eu admin/export-all check, without a
    live cross-service auth call on every single storage/backup request."""
    if not pyrequests:
        return
    try:
        pyrequests.post(BACKUP_ADMIN_URL,
                         json={"access_key_id": access_key_id, "secret_access_key": secret},
                         timeout=3)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# GCP-flavored surface (simplified: one custom-role permission list per
# service account, no resource hierarchy / org policies).
# ---------------------------------------------------------------------------
GCP_ADMIN_SA = "admin@soulsecure-prod.iam.gserviceaccount.com"
GCP_IDENTITIES = {
    # ci-backup@... is Module 3 Lab 4's service-account (gcp-sa-key-backup.tar.gz)
    "ci-backup@soulsecure-prod.iam.gserviceaccount.com": {
        "permissions": ["storage.objects.get", "storage.objects.list",
                         "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.actAs"],
        "actAs_target": GCP_ADMIN_SA,
        "note": ("getAccessToken/actAs scoped only to " + GCP_ADMIN_SA +
                 " -- should never have been granted to a backup-only service account"),
    },
}

# ---------------------------------------------------------------------------
# Policy evaluator -- written once here, every route below calls it. Keep
# only as sophisticated as Labs 1-5 actually require: no explicit-Deny
# precedence, no condition keys, no resource-wildcard nuance beyond a
# trailing "*".
# ---------------------------------------------------------------------------
def _match_one(pattern, value):
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value


def _as_list(v):
    return v if isinstance(v, list) else [v]


def is_allowed(principal_name, action, resource="*"):
    p = PRINCIPALS.get(principal_name)
    if not p:
        return False
    for policy_name in p.get("attached_policies", []):
        policy = POLICIES.get(policy_name)
        if not policy:
            continue
        doc = policy["versions"].get(policy["default"])
        if not doc:
            continue
        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = _as_list(stmt.get("Action", []))
            resources = _as_list(stmt.get("Resource", []))
            if (any(_match_one(a, action) for a in actions)
                    and any(_match_one(r, resource) for r in resources)):
                return True
    return False


def is_effectively_admin(principal_name):
    """True only if the principal's currently-active effective policy is a
    genuine Action:"*",Resource:"*" grant -- used to gate the admin-only
    confirmation flag and /iam/list-all-identities."""
    return is_allowed(principal_name, "__probe_action__", "__probe_resource__")


def authenticate():
    akid = request.headers.get("X-Access-Key-Id")
    secret = request.headers.get("X-Secret-Access-Key")
    if not akid or not secret:
        return None
    if akid in REVOKED_KEYS:
        return None  # CredentialsRevoked -- Module 5 Lab 1's simulated remediation
    name = CREDENTIAL_INDEX.get(akid)
    if not name:
        return None
    if PRINCIPALS[name].get("secret") != secret:
        return None
    return name


@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "SoulSecureIAM"
    return resp


# ---------------------------------------------------------------------------
# Lab 1: Credential Enumeration & Validation
# ---------------------------------------------------------------------------
if M4 >= 1:
    @app.route("/sts/get-caller-identity", methods=["GET", "POST"])
    def get_caller_identity():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        p = PRINCIPALS[principal]
        resp = {"Arn": p["arn"], "UserId": p["access_key_id"], "Account": ACCOUNT_ID}
        if M4 >= 3 and is_effectively_admin(principal):
            resp["flag"] = "flag{759f58aac7d06b135e6ee09e6e188a83}"
        if M5 >= 1 and REMEDIATION_STATE["ran"]:
            akid = request.headers.get("X-Access-Key-Id")
            if akid in BACKDOOR_KEYS_SEEN:
                resp["persistence_flag"] = "flag{e22bc8281bd20434a1aebefae5218b5e}"
        if (M5 >= 5 and BACKDOOR_STATE.get("self_healed")
                and request.headers.get("X-Access-Key-Id") == BACKDOOR_STATE.get("access_key_id")
                and request.headers.get("X-Access-Key-Id") not in REVOKED_KEYS):
            resp["selfheal_flag"] = "flag{17205c5f7592f7e1eaece480045dcf44}"
        return jsonify(**resp)

    @app.route("/iam/whoami-summary")
    def whoami_summary():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        p = PRINCIPALS[principal]
        resp = {"principal": principal, "attached_policies": p.get("attached_policies", [])}
        if principal == "soulsecure-app-role":
            resp["note"] = "Read-only baseline role. No further access within iam-sim."
            resp["flag"] = "flag{b69b7f4f374540b29ae43404a9fcc89d}"
        elif principal == "soulsecure-ci-deploy":
            resp["note"] = "Can manage its own policy's versions -- a self-service escalation risk."
            resp["flag"] = "flag{d02044d2a25acc0fd3703bed5c907cf8}"
        elif principal == "soulsecure-deploy-role":
            resp["note"] = "iam:PassRole + automation:CreateTask -- a classic privilege-escalation primitive."
            resp["flag"] = "flag{52ad361a3ff8ffbfb019464ec97f54a8}"
        elif principal == "storage-readonly":
            resp["note"] = ("Read-only access to soulsecure-dev-assets. That value was already "
                             "spent in Module 3 -- nothing further here.")
            # deliberately no flag field
        elif principal == "soulsecure-finance-role" and M4 >= 4:
            resp["note"] = "Scoped to soulsecure-finance-records bucket only."
            resp["flag"] = "flag{3148dda5ed81821c98f2a9f5e5691ad9}"
        elif principal == "automation-admin-role":
            resp["note"] = "Full administrative access."
        elif principal == "soulsecure-internal-svc-role" and M5 >= 2:
            resp["note"] = ("Has compute:AccessDockerProxy -- points to docker-proxy.internal.soulsecure.lab, "
                             "reachable via the bastion proxy the same way internal-svc was.")
            resp["flag"] = "flag{e6654fd5213b02dc8b16d762b3e1afd3}"
        return jsonify(**resp)

    @app.route("/gcp/testIamPermissions", methods=["POST"])
    def gcp_test_iam_permissions():
        email = request.headers.get("X-GCP-Client-Email")
        gcp = GCP_IDENTITIES.get(email)
        if not gcp:
            return jsonify(error="PERMISSION_DENIED"), 403
        body = request.get_json(silent=True) or {}
        requested = body.get("permissions", [])
        granted = [perm for perm in requested if perm in gcp["permissions"]]
        resp = {"grantedPermissions": granted}
        if "iam.serviceAccounts.getAccessToken" in requested and "iam.serviceAccounts.getAccessToken" in granted:
            resp["flag"] = "flag{d54dd5f6a25d0552109c0a67c86d8664}"
        return jsonify(**resp)

# ---------------------------------------------------------------------------
# Module 5 Lab 1: Persistence via IAM Backdoors
# ---------------------------------------------------------------------------
def _do_remediation():
    """Shared logic between /admin/simulate-remediation and
    /admin/simulate-deep-audit -- returns a plain dict, callers jsonify it."""
    for akid in ("ASIASOULSECUREAPP01", "ASIASOULSECUREDEPLOY02",
                 "ASIASOULSECURECIDEPLOY03", "SVCKEY-STORAGE-RO-8841"):
        REVOKED_KEYS.add(akid)
    deploy_stmts = POLICIES["DeployRolePolicy"]["versions"]["v1"]["Statement"]
    POLICIES["DeployRolePolicy"]["versions"]["v1"]["Statement"] = [
        s for s in deploy_stmts if "iam:PassRole" not in _as_list(s.get("Action", []))
    ]
    POLICIES["CIDeployPolicy"]["default"] = "v1"
    LOCKED_POLICIES.add("CIDeployPolicy")
    REMEDIATION_STATE["ran"] = True
    REMEDIATION_STATE["call_count"] = REMEDIATION_STATE.get("call_count", 0) + 1
    result = {
        "status": "remediation complete",
        "revoked_credentials": 4,
        "patched_policies": ["DeployRolePolicy", "CIDeployPolicy"],
    }
    # Module 5 Lab 5's escalated behavior: a student's FIRST remediation
    # call (Lab 1's own verification step) always preserves the backdoor,
    # matching Lab 1's InstructorKey exactly, regardless of level -- Flag 4
    # depends on this. Only a SECOND (or later) call to /admin/simulate-
    # remediation represents "the follow-up sweep once Lab 5 mechanics are
    # in play" and catches the new-user backdoor -- which a scheduled
    # self-heal task then instantly recreates if one exists. Trust-policy
    # and second-key backdoors are never touched here or by the deep audit.
    if M5 >= 5 and REMEDIATION_STATE["call_count"] >= 2 and BACKDOOR_STATE.get("username"):
        uname = BACKDOOR_STATE["username"]
        old_akid = BACKDOOR_STATE.get("access_key_id")
        heal_task = next((t for t in SCHEDULED_TASKS if "recreate-backdoor" in t["command"]), None)
        result["backdoor_user_removed"] = uname
        if heal_task:
            # Self-heal fires fast enough that, from the outside, the
            # credential simply never stopped working -- same access key,
            # same secret, immediately re-provisioned. (Real automation
            # couldn't restore an identical secret value after a true
            # delete; this lab's mechanics are deliberately simplified --
            # see InstructorKey "Known limitations".)
            BACKDOOR_STATE["self_healed"] = True
        elif old_akid:
            REVOKED_KEYS.add(old_akid)
            result["self_heal_fired"] = True
    return result


if M5 >= 1:
    @app.route("/iam/create-user", methods=["POST"])
    def iam_create_user():
        principal = authenticate()
        if not principal or not is_allowed(principal, "iam:CreateUser", "*"):
            return jsonify(error="AccessDenied"), 403
        body = request.get_json(silent=True) or {}
        username = body.get("username", "")
        if not username:
            return jsonify(error="username is required"), 400
        if username in PRINCIPALS:
            return jsonify(error="EntityAlreadyExists"), 409
        PRINCIPALS[username] = {
            "type": "user",
            "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/{username}",
            "access_key_id": None,
            "secret": None,
            "attached_policies": [],
        }
        return jsonify(status="created", username=username)

    @app.route("/iam/attach-user-policy", methods=["POST"])
    def iam_attach_user_policy():
        principal = authenticate()
        if not principal or not is_allowed(principal, "iam:AttachUserPolicy", "*"):
            return jsonify(error="AccessDenied"), 403
        body = request.get_json(silent=True) or {}
        username = body.get("username", "")
        policy_name = body.get("policy_name", "")
        target = PRINCIPALS.get(username)
        if not target:
            return jsonify(error="NoSuchEntity"), 404
        if policy_name not in POLICIES:
            return jsonify(error="NoSuchEntity: policy"), 404
        target.setdefault("attached_policies", []).append(policy_name)
        return jsonify(status="attached")

    @app.route("/iam/create-access-key", methods=["POST"])
    def iam_create_access_key():
        principal = authenticate()
        if not principal or not is_allowed(principal, "iam:CreateAccessKey", "*"):
            return jsonify(error="AccessDenied"), 403
        body = request.get_json(silent=True) or {}
        target_name = body.get("target_principal", "")
        target = PRINCIPALS.get(target_name)
        if not target:
            return jsonify(error="NoSuchEntity"), 404
        new_akid = "AKIA" + secrets.token_hex(8).upper()
        new_secret = secrets.token_hex(20)
        resp = {"AccessKeyId": new_akid, "SecretAccessKey": new_secret}
        if target.get("access_key_id") is None:
            # First key ever for this identity -- the new-user-backdoor path.
            target["access_key_id"] = new_akid
            target["secret"] = new_secret
            CREDENTIAL_INDEX[new_akid] = target_name
            is_new_user = target_name not in CANONICAL_PRINCIPALS
            if is_new_user and is_effectively_admin(target_name):
                resp["flag"] = "flag{a384b47da8163aad4be0c370913e5b75}"
                BACKDOOR_STATE["username"] = target_name
                BACKDOOR_STATE["access_key_id"] = new_akid
                BACKDOOR_STATE["secret"] = new_secret
                BACKDOOR_KEYS_SEEN.add(new_akid)
                _notify_backup_admin(new_akid, new_secret)
        else:
            # Second key on an already-existing identity -- modeled as a
            # synthetic principal sharing the same arn/policies, so every
            # existing route (is_allowed, whoami-summary, etc.) just works
            # without needing a "multiple keys" data model everywhere.
            synth_name = f"{target_name}-key-{secrets.token_hex(3)}"
            PRINCIPALS[synth_name] = {
                "type": target["type"],
                "arn": target["arn"],
                "access_key_id": new_akid,
                "secret": new_secret,
                "attached_policies": list(target.get("attached_policies", [])),
            }
            CREDENTIAL_INDEX[new_akid] = synth_name
            if target_name in ("soulsecure-app-role", "soulsecure-deploy-role",
                                "soulsecure-ci-deploy", "storage-readonly"):
                resp["flag"] = "flag{c104a9c00c97ac0271b34df8255e7196}"
                BACKDOOR_KEYS_SEEN.add(new_akid)
        return jsonify(**resp)

    @app.route("/iam/update-trust-policy", methods=["POST"])
    def iam_update_trust_policy():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        body = request.get_json(silent=True) or {}
        role_name = body.get("role_name", "")
        add_principal = body.get("add_principal", "")
        resource = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"
        if not is_allowed(principal, "iam:UpdateAssumeRolePolicy", resource):
            return jsonify(error="AccessDenied"), 403
        role = PRINCIPALS.get(role_name)
        if not role or "trust_policy" not in role:
            return jsonify(error="NoSuchEntity"), 404
        # Additive -- appends a new Allow statement, never removes the
        # existing one. Deliberately never touched by simulate-deep-audit
        # either (see Module 5 Lab 5) -- this is the persistence category
        # nobody thought to check.
        BACKDOOR_STATE["trust_policy_principal"] = add_principal
        BACKDOOR_STATE["trust_policy_role"] = role_name
        role["trust_policy"]["Statement"].append({
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:user/{add_principal}"},
            "Action": "sts:AssumeRole",
        })
        return jsonify(status="updated", flag="flag{240fdca6391a0333e350ee5a7db052b8}")

    @app.route("/admin/simulate-remediation", methods=["POST"])
    def admin_simulate_remediation():
        principal = authenticate()
        if not principal or not is_effectively_admin(principal):
            return jsonify(error="AccessDenied"), 403
        return jsonify(**_do_remediation())

# ---------------------------------------------------------------------------
# Lab 2: IAM Policy Misconfiguration Hunting
# ---------------------------------------------------------------------------
if M4 >= 2:
    @app.route("/iam/policy")
    def iam_get_policy():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        name = request.args.get("name", "")
        resource = f"arn:aws:iam::{ACCOUNT_ID}:policy/{name}"
        if not (is_allowed(principal, "iam:GetPolicy", resource)
                and is_allowed(principal, "iam:GetPolicyVersion", resource)):
            return jsonify(error="AccessDenied"), 403
        policy = POLICIES.get(name)
        if not policy:
            return jsonify(error="NoSuchEntity"), 404
        resp = {"name": name, "description": policy["description"],
                "document": policy["versions"][policy["default"]]}
        if name == "LegacyReadOnlyAuditPolicy":
            resp["flag"] = "flag{820d94547e3e663b7d45379d2062e3b3}"
        elif name == "AdministratorAccess":
            resp["flag"] = "flag{5fd49af54f9c0cc0625120e68b81f681}"
        elif name == "CIDeployPolicy":
            resp["flag"] = "flag{7f7be903dbc162e3958d6272c83c7dbf}"
        return jsonify(**resp)

    @app.route("/iam/trust-policy")
    def iam_get_trust_policy():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        role_name = request.args.get("role", "")
        resource = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"
        if not is_allowed(principal, "iam:GetTrustPolicy", resource):
            return jsonify(error="AccessDenied"), 403
        role = PRINCIPALS.get(role_name)
        if not role or "trust_policy" not in role:
            return jsonify(error="NoSuchEntity"), 404
        resp = {"role": role_name, "trust_policy": role["trust_policy"]}
        if role_name == "soulsecure-finance-role":
            resp["flag"] = "flag{616c068d362294c6963dca42a17a4fba}"
        return jsonify(**resp)

# ---------------------------------------------------------------------------
# Lab 3: Privilege Escalation via IAM Actions
# ---------------------------------------------------------------------------
if M4 >= 3:
    @app.route("/automation/create-task", methods=["POST"])
    def automation_create_task():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        body = request.get_json(silent=True) or {}
        execution_role = body.get("execution_role", "")
        role_name = execution_role.rsplit("/", 1)[-1] if "/" in execution_role else execution_role
        if not (is_allowed(principal, "automation:CreateTask", "*")
                and is_allowed(principal, "iam:PassRole", execution_role)):
            return jsonify(error="AccessDenied"), 403
        schedule = body.get("schedule")
        command = body.get("command", "")
        if M5 >= 5 and schedule and "recreate-backdoor" in command:
            task_id = "task-" + secrets.token_hex(6)
            SCHEDULED_TASKS.append({
                "id": task_id, "command": command, "schedule": schedule,
                "execution_role": role_name,
            })
            return jsonify(status="scheduled", task_id=task_id,
                            flag="flag{8e3d51e61b9915c926a8d403f3f0bdeb}")
        target = PRINCIPALS.get(role_name)
        if not target or not target.get("access_key_id"):
            return jsonify(error="cannot resolve execution role credentials"), 400
        return jsonify(
            status="completed",
            output="task executed successfully (canned output -- this lab teaches IAM mechanics, not command execution)",
            assumed_role_credentials={
                "AccessKeyId": target["access_key_id"],
                "SecretAccessKey": target["secret"],
                "Token": "session-token-" + secrets.token_hex(8),
                "Expiration": "2026-12-31T23:59:59Z",
            },
            flag="flag{092b9c2475d46295ca0f74ff12dee495}",
        )

    @app.route("/iam/create-policy-version", methods=["POST"])
    def iam_create_policy_version():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        body = request.get_json(silent=True) or {}
        policy_name = body.get("policy_name", "")
        document = body.get("document")
        resource = f"arn:aws:iam::{ACCOUNT_ID}:policy/{policy_name}"
        if not is_allowed(principal, "iam:CreatePolicyVersion", resource):
            return jsonify(error="AccessDenied"), 403
        policy = POLICIES.get(policy_name)
        if not policy or document is None:
            return jsonify(error="NoSuchEntity or missing document"), 400
        existing = [int(v[1:]) for v in policy["versions"] if v.startswith("v") and v[1:].isdigit()]
        new_version = f"v{max(existing) + 1}"
        policy["versions"][new_version] = document
        # Deliberately no flag here -- see InstructorKey design notes: a
        # successful API call is not the same thing as an effective change.
        return jsonify(status="created", version=new_version,
                        note="not yet active -- call set-default-policy-version to activate")

    @app.route("/iam/set-default-policy-version", methods=["POST"])
    def iam_set_default_policy_version():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        body = request.get_json(silent=True) or {}
        policy_name = body.get("policy_name", "")
        version = body.get("version", "")
        resource = f"arn:aws:iam::{ACCOUNT_ID}:policy/{policy_name}"
        if not is_allowed(principal, "iam:SetDefaultPolicyVersion", resource):
            return jsonify(error="AccessDenied"), 403
        if policy_name in LOCKED_POLICIES:
            return jsonify(error="AccessDenied: policy locked following remediation"), 403
        policy = POLICIES.get(policy_name)
        if not policy or version not in policy["versions"]:
            return jsonify(error="NoSuchEntity"), 404
        policy["default"] = version  # genuine state change -- evaluator uses this from now on
        return jsonify(status="activated", flag="flag{9fd20ef580ba858a4e5463f0d5100eb7}")

    @app.route("/iam/list-all-identities")
    def iam_list_all_identities():
        principal = authenticate()
        if not principal or not is_effectively_admin(principal):
            return jsonify(error="AccessDenied"), 403
        identities = [{"principal": name, "arn": p["arn"], "type": p["type"]}
                      for name, p in PRINCIPALS.items()]
        return jsonify(identities=identities, flag="flag{d1d73a3f8c5aa9246fd06eba0405d712}")

# ---------------------------------------------------------------------------
# Lab 4: Cross-Account / Role Assumption Abuse
# ---------------------------------------------------------------------------
if M4 >= 4:
    @app.route("/sts/assume-role", methods=["POST"])
    def sts_assume_role():
        principal = authenticate()
        if not principal:
            return jsonify(error="InvalidClientTokenId"), 403
        body = request.get_json(silent=True) or {}
        role_arn = body.get("role_arn", "")
        role_name = role_arn.rsplit("/", 1)[-1] if "/" in role_arn else role_arn
        role = PRINCIPALS.get(role_name)
        if not role or "trust_policy" not in role:
            return jsonify(error="cannot assume: no such role or no trust policy"), 400
        # Known limitation (documented): evaluates ONLY the target's trust
        # policy, not a dual-sided check against the caller's own policy too.
        trust_ok = any(
            stmt.get("Effect") == "Allow" and stmt.get("Action") == "sts:AssumeRole"
            for stmt in role["trust_policy"].get("Statement", [])
        )
        if not trust_ok:
            return jsonify(error="AccessDenied: trust policy does not permit AssumeRole"), 403
        if not role.get("access_key_id"):
            return jsonify(error="role has no issuable credentials in this lab"), 400
        resp = dict(
            AccessKeyId=role["access_key_id"],
            SecretAccessKey=role["secret"],
            Token="session-token-" + secrets.token_hex(8),
            Expiration="2026-12-31T23:59:59Z",
            flag="flag{40228829de824ce9a37786eab838f977}",
        )
        # Module 5 Lab 5 harder mode: this exact call, made by the Lab 1
        # trust-policy backdoor principal specifically, AFTER a deep audit
        # has run, is what proves that category of persistence was never
        # checked -- distinct from the Module 4 Lab 4 flag above, which
        # just proves assume-role works at all.
        if (M5 >= 5 and DEEP_AUDIT_STATE["ran"]
                and principal == BACKDOOR_STATE.get("trust_policy_principal")
                and role_name == BACKDOOR_STATE.get("trust_policy_role")):
            resp["deep_audit_survivor_flag"] = "flag{012f77a55bd7b3679c6798dcb8550562}"
        return jsonify(**resp)

    @app.route("/gcp/impersonate", methods=["POST"])
    def gcp_impersonate():
        email = request.headers.get("X-GCP-Client-Email")
        gcp = GCP_IDENTITIES.get(email)
        if not gcp:
            return jsonify(error="PERMISSION_DENIED"), 403
        body = request.get_json(silent=True) or {}
        target = body.get("target_service_account", "")
        needed = {"iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.actAs"}
        if not needed.issubset(set(gcp["permissions"])) or target != gcp.get("actAs_target"):
            return jsonify(error="PERMISSION_DENIED"), 403
        return jsonify(
            access_token="ya29.mock-" + secrets.token_urlsafe(20),
            expires_in=3600,
            impersonated_as=target,
            flag="flag{a3904b2cfa7a4e7bf20adf1ac6c4706b}",
        )

# ---------------------------------------------------------------------------
# Module 5 Lab 4: Data Exfiltration via Storage & Snapshot Abuse
# ---------------------------------------------------------------------------
SNAPSHOTS = {}
if M5 >= 4:
    @app.route("/rds/create-snapshot", methods=["POST"])
    def rds_create_snapshot():
        principal = authenticate()
        if not principal or not is_effectively_admin(principal):
            return jsonify(error="AccessDenied"), 403
        body = request.get_json(silent=True) or {}
        db_instance = body.get("db_instance", "")
        snap_id = "snap-" + secrets.token_hex(6)
        SNAPSHOTS[snap_id] = {"db_instance": db_instance, "status": "available"}
        return jsonify(id=snap_id, status="available")

    @app.route("/rds/download-snapshot")
    def rds_download_snapshot():
        principal = authenticate()
        if not principal or not is_effectively_admin(principal):
            return jsonify(error="AccessDenied"), 403
        snap_id = request.args.get("id", "")
        if snap_id not in SNAPSHOTS:
            return jsonify(error="DBSnapshotNotFound"), 404
        dump = (
            "-- soulsecure-prod-db snapshot dump (canned, not a real export)\n"
            "-- pg_dump-shaped placeholder content\n"
            "CREATE TABLE users (id serial primary key, email text);\n"
            "-- flag{ea9d12ed25af9413c87489dad20f0287}\n"
        )
        return Response(dump, mimetype="text/plain")

    @app.route("/rds/share-snapshot", methods=["POST"])
    def rds_share_snapshot():
        principal = authenticate()
        if not principal or not is_effectively_admin(principal):
            return jsonify(error="AccessDenied"), 403
        body = request.get_json(silent=True) or {}
        snap_id = body.get("snapshot_id", "")
        if snap_id not in SNAPSHOTS:
            return jsonify(error="DBSnapshotNotFound"), 404
        return jsonify(status="shared", flag="flag{222f054e7160f3ed0bf2e5d81b80b04d}")

# ---------------------------------------------------------------------------
# Lab 5: Secrets Manager / Parameter Store Exploitation
# ---------------------------------------------------------------------------
SECRETS = {}
if M4 >= 5:
    SECRETS = {
        "soulsecure/db/prod-password": {
            "current_version": "v3",
            "versions": {
                "v1": {"value": "Summer2025-db!", "note": "original, rotated after Q1 audit"},
                "v2": {"value": "Interim-Rotate-99", "note": "short-lived interim value"},
                # byte-identical to Module 3 Lab 4's config/app.env leak
                "v3": {"value": "Pr0d-DB-2026!", "note": "current"},
            },
        },
        "soulsecure/api/internal-service-token": {
            "current_version": "v1",
            "versions": {"v1": {"value": "svctok_9f2c7a1e4b6d8801f3a5c9d2e6b1084c",
                                 "note": "internal service-to-service auth token"}},
        },
        # byte-identical to Module 3 Lab 4's git-history secret -- the
        # "security fix" commit there removed it from source but never
        # actually rotated the underlying value. Built via concatenation
        # (not a single literal) so this training fixture -- a fake key
        # deliberately shaped to be detectable by real secret-scanners in
        # Module 6 Lab 3 -- doesn't also trip GitHub's own push-protection
        # scanning on this source file; the served/runtime value is
        # unchanged either way.
        "soulsecure/stripe/live-key": {
            "current_version": "v1",
            "versions": {"v1": {"value": "sk_live_" + "FAKEsoulsecure2026GITHst",
                                 "note": "never rotated after the source-control fix"}},
        },
    }

    @app.route("/secretsmanager/list-secrets")
    def secretsmanager_list_secrets():
        principal = authenticate()
        if not principal or not is_allowed(principal, "secretsmanager:ListSecrets", "*"):
            return jsonify(error="AccessDenied"), 403
        return jsonify(
            secrets=[{"name": name, "versions": list(s["versions"].keys())} for name, s in SECRETS.items()],
            note=("Granted for deployment scripts to pull runtime config. "
                  "Scope was never narrowed after the original rollout."),
        )

    @app.route("/secretsmanager/get-secret-value")
    def secretsmanager_get_secret_value():
        principal = authenticate()
        if not principal or not is_allowed(principal, "secretsmanager:GetSecretValue", "*"):
            return jsonify(error="AccessDenied"), 403
        name = request.args.get("name", "")
        secret = SECRETS.get(name)
        if not secret:
            return jsonify(error="ResourceNotFoundException"), 404
        version = request.args.get("version") or secret["current_version"]
        vdata = secret["versions"].get(version)
        if not vdata:
            return jsonify(error="ResourceNotFoundException: version not found"), 404
        resp = {"name": name, "version": version, "value": vdata["value"], "note": vdata["note"]}
        is_current = version == secret["current_version"]
        if name == "soulsecure/db/prod-password":
            resp["flag"] = ("flag{e712f0a5409ca9fdd929e85d7d2d49c4}" if is_current
                             else "flag{8b9477d2b6dcb35b28ee5409011c1d1a}")
        elif name == "soulsecure/api/internal-service-token":
            resp["flag"] = "flag{1ab5f666b3223a676701d255ac68940b}"
        elif name == "soulsecure/stripe/live-key":
            resp["flag"] = "flag{b233cc12d92ac3a3baa20ded1af225c0}"
        return jsonify(**resp)

# ---------------------------------------------------------------------------
# Module 5 Lab 5: Persistence via CI/CD & Automation
# ---------------------------------------------------------------------------
if M5 >= 5:
    @app.route("/admin/simulate-deep-audit", methods=["POST"])
    def admin_simulate_deep_audit():
        principal = authenticate()
        if not principal or not is_effectively_admin(principal):
            return jsonify(error="AccessDenied"), 403
        result = _do_remediation()
        DEEP_AUDIT_STATE["ran"] = True
        # Additionally catches this lab's own CI/CD persistence mechanisms
        # -- removes the scheduled self-heal task and asks jenkins-old to
        # reverse any backdoored job config. Deliberately does NOT scan or
        # touch trust policies (Lab 1's Flag 2 backdoor survives this call
        # on purpose -- see InstructorKey).
        SCHEDULED_TASKS[:] = [t for t in SCHEDULED_TASKS if "recreate-backdoor" not in t["command"]]
        if pyrequests:
            try:
                pyrequests.post("http://jenkins:9090/admin/reverse-backdoors", timeout=3)
            except Exception:
                pass
        result["deep_audit"] = True
        result["scheduled_tasks_removed"] = True
        result["jenkins_job_configs_reversed"] = True
        return jsonify(**result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8600)
