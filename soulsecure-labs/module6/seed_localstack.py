#!/usr/bin/env python3
"""
SoulSecure Inc. -- Module 6, Labs 1-2: LocalStack seed script.

Seeds a LocalStack S3/IAM/STS backend with the SAME misconfiguration *story*
as Modules 3-5's hand-rolled Flask mocks -- independently re-created,
real-AWS-API-shaped, so genuine tools (Prowler, Pacu, the real `aws` CLI)
work against it unmodified. See Lab 1's InstructorKey "Architecture
decision" for why this exists as a separate backend rather than trying to
make the Flask mocks request-signing-compatible.

Idempotent -- safe to re-run any number of times (e.g. after `labctl reset`
restarts the localstack container and wipes its in-memory state, since
PERSISTENCE=0). Gated on M6_LEVEL the same way every other Module 6 asset is:

    M6_LEVEL >= 1  -> Lab 1 resources (posture-assessment findings)
    M6_LEVEL >= 2  -> + Lab 2 additions (Pacu privesc target)

Usage:
    python3 seed_localstack.py <m6_level> [endpoint_url]

Build-time decision (Lab 1 vs Lab 2 user separation): Lab 2's InstructorKey
explicitly calls out that `svc-legacy-app` must be evaluated against
`SelfAttachPolicy` ONLY, not combined with Lab 1's `LegacyBroadPolicy`
(combining them would make Pacu's privesc-scan trivial/uninteresting). Per
that doc's own suggested resolution ("seed svc-legacy-app fresh with only
SelfAttachPolicy and use a different, still-LegacyBroadPolicy-attached user
for Lab1's exercises"), this script:
  - attaches LegacyBroadPolicy to `svc-legacy-billing` (Lab 1's target)
  - attaches SelfAttachPolicy + an access key to `svc-legacy-app` (Lab 2's
    target) -- and nothing else
so the two labs' privilege stories never overlap.
"""
import json
import sys

import boto3
from botocore.exceptions import ClientError

ENDPOINT = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:4566"
M6_LEVEL = int(sys.argv[1]) if len(sys.argv) > 1 else 0

REGION = "us-east-1"
CREDS = dict(aws_access_key_id="test", aws_secret_access_key="test", region_name=REGION)


def client(service):
    return boto3.client(service, endpoint_url=ENDPOINT, **CREDS)


def ignore_exists(fn, *a, **kw):
    """Run fn, swallow the 'already exists' family of ClientErrors so the
    script stays idempotent across re-runs."""
    try:
        return fn(*a, **kw)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in (
            "BucketAlreadyOwnedByYou", "BucketAlreadyExists",
            "EntityAlreadyExists",
        ):
            return None
        raise


def seed_lab1(s3, iam):
    print("== Lab 1: posture-assessment seed ==")

    # Flag 1 -- public-read bucket with a tagged flag. NOTE: S3 tag VALUES
    # reject '{' and '}' (real AWS/LocalStack validation, confirmed against
    # the live LocalStack API -- IAM policy descriptions and IAM tags do NOT
    # have this restriction, only S3 tags do). The tag holds the bare hex
    # body; the flag is submitted as flag{<value>}, same convention as every
    # other flag in the course -- just the tag's raw storage differs.
    #
    # ALSO NOTE: since April 2023 every new S3 bucket defaults to full
    # Public Access Block (all four settings true) -- a public-read ACL
    # alone does NOT make a bucket actually public anymore, and real
    # scanners (confirmed against Prowler 5.37.1) correctly report PASS
    # for a bucket in that state, exactly matching real-world AWS. To make
    # this a genuine "public bucket" finding -- not a naive one a modern
    # tool would rightly no-op on -- the seed must explicitly disable the
    # block, same as a real misconfiguration would require.
    ignore_exists(s3.create_bucket, Bucket="soulsecure-public-assets")
    s3.put_bucket_acl(Bucket="soulsecure-public-assets", ACL="public-read")
    s3.put_public_access_block(
        Bucket="soulsecure-public-assets",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_tagging(
        Bucket="soulsecure-public-assets",
        Tagging={"TagSet": [{"Key": "flag", "Value": "2361eeb8da89a1b0cfed7791affb0d00"}]},
    )
    print("  bucket soulsecure-public-assets: public-read ACL + Public Access Block disabled + Flag 1 tag (submit as flag{<value>})")

    # Control/noise bucket -- private, no finding
    ignore_exists(s3.create_bucket, Bucket="soulsecure-internal-logs")
    print("  bucket soulsecure-internal-logs: private control (no finding)")

    # Flag 2 -- wildcard IAM policy, attached to svc-legacy-billing (see
    # module docstring for why this user is NOT named svc-legacy-app)
    policy_arn = None
    try:
        resp = iam.create_policy(
            PolicyName="LegacyBroadPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }),
            Description="flag{87710d4e5d946788aa34f19227db1293}",
        )
        policy_arn = resp["Policy"]["Arn"]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
            policy_arn = f"arn:aws:iam::000000000000:policy/LegacyBroadPolicy"
        else:
            raise
    ignore_exists(iam.create_user, UserName="svc-legacy-billing")
    try:
        iam.attach_user_policy(UserName="svc-legacy-billing", PolicyArn=policy_arn)
    except ClientError:
        pass
    print(f"  user svc-legacy-billing <- LegacyBroadPolicy ({policy_arn}), Flag 2 in description")

    # Flag 3 -- role with Principal:"*" trust policy (externally assumable)
    ignore_exists(
        iam.create_role,
        RoleName="soulsecure-shared-role",
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "flag", "Value": "flag{86874cf9925295682b701ab1a6c34fc8}"}],
    )
    print("  role soulsecure-shared-role: Principal:* trust policy, Flag 3 tag")

    # Noise -- low-severity filler so the report isn't a 4-line trivial list
    for i in range(6):
        ignore_exists(iam.create_user, UserName=f"svc-noise-{i}")
    print("  6x svc-noise-N users seeded (report volume/realism)")


def seed_lab2(iam):
    print("== Lab 2: Pacu privesc-target seed ==")

    # SelfAttachPolicy -- specifically the AttachUserPolicy privesc primitive,
    # nothing broader. Attached ONLY to svc-legacy-app (never LegacyBroadPolicy).
    policy_arn = None
    try:
        resp = iam.create_policy(
            PolicyName="SelfAttachPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "iam:AttachUserPolicy", "iam:ListAttachedUserPolicies",
                        "iam:ListPolicies", "sts:GetCallerIdentity",
                    ],
                    "Resource": ["arn:aws:iam::*:user/svc-legacy-app", "*"],
                }],
            }),
        )
        policy_arn = resp["Policy"]["Arn"]
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
            policy_arn = "arn:aws:iam::000000000000:policy/SelfAttachPolicy"
        else:
            raise

    ignore_exists(iam.create_user, UserName="svc-legacy-app")
    try:
        iam.attach_user_policy(UserName="svc-legacy-app", PolicyArn=policy_arn)
    except ClientError:
        pass
    print(f"  user svc-legacy-app <- SelfAttachPolicy ONLY ({policy_arn})")

    # Access key -- idempotency guard: LocalStack allows up to 2 keys/user,
    # skip if one's already there from a prior run within the same container
    # lifetime (a fresh container/reset always starts with none).
    existing = iam.list_access_keys(UserName="svc-legacy-app")["AccessKeyMetadata"]
    if not existing:
        key = iam.create_access_key(UserName="svc-legacy-app")["AccessKey"]
        print(f"  access key created: {key['AccessKeyId']} / {key['SecretAccessKey']}")
    else:
        print(f"  access key already present: {existing[0]['AccessKeyId']} (idempotent skip)")


def main():
    if M6_LEVEL < 1:
        print(f"M6_LEVEL={M6_LEVEL} < 1 -- nothing to seed, exiting.")
        return

    s3 = client("s3")
    iam = client("iam")

    seed_lab1(s3, iam)
    if M6_LEVEL >= 2:
        seed_lab2(iam)
    else:
        print("== Lab 2 seed skipped (M6_LEVEL < 2) ==")

    print("seed_localstack.py: done.")


if __name__ == "__main__":
    main()
