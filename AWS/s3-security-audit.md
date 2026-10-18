# AWS S3 Security Audit with Python (Boto3)

## Overview

This script performs a **read-only security audit** of S3 buckets in the AWS account configured in your environment. It checks common bucket-level security controls and reports findings in the terminal.

### Checks performed

- S3 Block Public Access settings at the bucket level
- Bucket ACL grants that may allow public access
- Bucket policies that appear to grant access to everyone (`Principal: "*"`)
- Default server-side encryption configuration
- Bucket versioning status
- Server access logging status
- Object Ownership configuration, when available

> **Important:** This is a practical baseline audit, not a complete compliance assessment. A policy containing `Principal: "*"` is not automatically exploitable in every case; conditions and other AWS controls can restrict access. Review findings before making changes. The script does not modify AWS resources or list object contents.

## Prerequisites

- Python 3.9+
- An AWS identity with permission to list buckets and read the relevant S3 configuration.
- Boto3 installed.

Install Boto3:

```bash
python -m pip install boto3
```

Configure credentials using an AWS profile, environment variables, IAM role, or another supported AWS credential provider:

```bash
aws configure
aws sts get-caller-identity
```

Use least-privilege permissions. Depending on the checks available in your account, the identity may need these read permissions:

- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketVersioning`
- `s3:GetBucketLogging`
- `s3:GetBucketOwnershipControls`

Some APIs may return `AccessDenied` if a permission is missing. The script records those cases as `UNKNOWN` rather than treating them as secure.

## Python script

Save as `s3_security_audit.py`.

```python
#!/usr/bin/env python3
\"\"\"Read-only baseline security audit for Amazon S3 buckets.\"\"\"

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError, BotoCoreError


PUBLIC_GROUP_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def api_error_code(exc):
    \"\"\"Return the AWS error code from a ClientError.\"\"\"
    return exc.response.get("Error", {}).get("Code", "Unknown")


def check_public_access_block(s3, bucket):
    \"\"\"Return bucket-level Block Public Access settings.\"\"\"
    try:
        response = s3.get_public_access_block(Bucket=bucket)
        config = response["PublicAccessBlockConfiguration"]
        required = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        missing = [key for key in required if not config.get(key, False)]
        if missing:
            return "FAIL", f"Disabled or unset: {', '.join(missing)}"
        return "PASS", "All four settings enabled"
    except ClientError as exc:
        code = api_error_code(exc)
        if code == "NoSuchPublicAccessBlockConfiguration":
            return "FAIL", "Bucket-level Block Public Access is not configured"
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"


def check_acl(s3, bucket):
    \"\"\"Look for ACL grants to public or all authenticated AWS users.\"\"\"
    try:
        response = s3.get_bucket_acl(Bucket=bucket)
        public_grants = []
        for grant in response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") == "Group" and grantee.get("URI") in PUBLIC_GROUP_URIS:
                public_grants.append(
                    f"{grantee.get('URI')} ({grant.get('Permission', 'UNKNOWN')})"
                )

        if public_grants:
            return "FAIL", "; ".join(public_grants)
        return "PASS", "No public or authenticated-user ACL grants found"
    except ClientError as exc:
        code = api_error_code(exc)
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"


def check_bucket_policy(s3, bucket):
    \"\"\"Flag wildcard principals for manual review, including conditional policies.\"\"\"
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
        policy = json.loads(response["Policy"])
        findings = []

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal")
            wildcard = principal == "*"
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS")
                wildcard = aws_principal == "*" or (
                    isinstance(aws_principal, list) and "*" in aws_principal
                )

            if wildcard:
                sid = statement.get("Sid", "(no Sid)")
                actions = statement.get("Action", "(unspecified)")
                resources = statement.get("Resource", "(unspecified)")
                conditions = statement.get("Condition")
                note = f"Sid={sid}; Action={actions}; Resource={resources}"
                if conditions:
                    note += "; has Condition (review manually)"
                else:
                    note += "; no Condition shown"
                findings.append(note)

        if findings:
            return "REVIEW", "Wildcard principal in Allow statement: " + " | ".join(findings)
        return "PASS", "No wildcard principal found in an Allow statement"
    except ClientError as exc:
        code = api_error_code(exc)
        if code == "NoSuchBucketPolicy":
            return "PASS", "No bucket policy configured"
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"
    except (json.JSONDecodeError, TypeError):
        return "UNKNOWN", "Could not parse bucket policy response"


def check_encryption(s3, bucket):
    \"\"\"Check whether default bucket encryption is configured.\"\"\"
    try:
        response = s3.get_bucket_encryption(Bucket=bucket)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            return "FAIL", "No default encryption rules found"

        descriptions = []
        for rule in rules:
            config = rule.get("ApplyServerSideEncryptionByDefault", {})
            algorithm = config.get("SSEAlgorithm", "UNKNOWN")
            kms_key = config.get("KMSMasterKeyID")
            desc = algorithm
            if kms_key:
                desc += f" (KMS key: {kms_key})"
            descriptions.append(desc)

        return "PASS", ", ".join(descriptions)
    except ClientError as exc:
        code = api_error_code(exc)
        if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"}:
            return "FAIL", "Default encryption is not configured"
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"


def check_versioning(s3, bucket):
    \"\"\"Check whether bucket versioning is enabled.\"\"\"
    try:
        response = s3.get_bucket_versioning(Bucket=bucket)
        status = response.get("Status", "Disabled")
        if status == "Enabled":
            return "PASS", "Versioning enabled"
        if status == "Suspended":
            return "REVIEW", "Versioning suspended"
        return "REVIEW", "Versioning is not enabled"
    except ClientError as exc:
        code = api_error_code(exc)
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"


def check_logging(s3, bucket):
    \"\"\"Check whether S3 server access logging is configured.\"\"\"
    try:
        response = s3.get_bucket_logging(Bucket=bucket)
        logging = response.get("LoggingEnabled")
        if logging:
            target = logging.get("TargetBucket", "UNKNOWN")
            return "PASS", f"Enabled; target bucket: {target}"
        return "REVIEW", "Server access logging is not enabled"
    except ClientError as exc:
        code = api_error_code(exc)
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"


def check_object_ownership(s3, bucket):
    \"\"\"Report the bucket's Object Ownership setting when supported.\"\"\"
    try:
        response = s3.get_bucket_ownership_controls(Bucket=bucket)
        rules = response.get("OwnershipControls", {}).get("Rules", [])
        if not rules:
            return "REVIEW", "No Object Ownership rules returned"

        ownership = rules[0].get("ObjectOwnership", "UNKNOWN")
        if ownership == "BucketOwnerEnforced":
            return "PASS", "BucketOwnerEnforced (ACLs disabled)"
        return "REVIEW", f"Object Ownership is {ownership}"
    except ClientError as exc:
        code = api_error_code(exc)
        if code == "OwnershipControlsNotFoundError":
            return "REVIEW", "Object Ownership controls not explicitly configured"
        if code in {"AccessDenied", "AllAccessDisabled"}:
            return "UNKNOWN", f"Permission or access issue ({code})"
        return "UNKNOWN", f"AWS API error ({code})"


def audit_bucket(s3, bucket):
    \"\"\"Run all checks for one bucket and return structured findings.\"\"\"
    checks = [
        ("Block Public Access", check_public_access_block),
        ("Bucket ACL", check_acl),
        ("Bucket Policy", check_bucket_policy),
        ("Default Encryption", check_encryption),
        ("Versioning", check_versioning),
        ("Server Access Logging", check_logging),
        ("Object Ownership", check_object_ownership),
    ]

    results = []
    for check_name, check_function in checks:
        status, details = check_function(s3, bucket)
        results.append({
            "bucket": bucket,
            "check": check_name,
            "status": status,
            "details": details,
        })
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Run a read-only baseline security audit of S3 buckets."
    )
    parser.add_argument(
        "--profile",
        help="Optional AWS CLI profile name, for example dev or production.",
    )
    parser.add_argument(
        "--region",
        help="Optional AWS region for the S3 client. Bucket locations are global/account-specific.",
    )
    parser.add_argument(
        "--output",
        default="s3_security_audit.json",
        help="JSON report path (default: s3_security_audit.json).",
    )
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        s3 = session.client("s3")
        identity = session.client("sts").get_caller_identity()
        account_id = identity.get("Account", "UNKNOWN")

        buckets = s3.list_buckets().get("Buckets", [])
        if not buckets:
            print("No S3 buckets found in this account.")
            return 0

        report = {
            "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "account_id": account_id,
            "bucket_count": len(buckets),
            "results": [],
        }

        for bucket_info in buckets:
            bucket = bucket_info["Name"]
            print(f"Auditing: {bucket}")
            report["results"].extend(audit_bucket(s3, bucket))

        with open(args.output, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2)

        print("\\nS3 Security Audit Summary")
        print("=" * 80)
        for result in report["results"]:
            print(
                f"[{result['status']:<7}] "
                f"{result['bucket']} | {result['check']}: {result['details']}"
            )

        counts = {}
        for result in report["results"]:
            counts[result["status"]] = counts.get(result["status"], 0) + 1

        print("\\nFinding counts:")
        for status in ("FAIL", "REVIEW", "UNKNOWN", "PASS"):
            print(f"  {status}: {counts.get(status, 0)}")
        print(f"\\nJSON report written to: {args.output}")
        print("Review FAIL, REVIEW, and UNKNOWN findings before taking action.")
        return 0

    except (ClientError, BotoCoreError) as exc:
        print(f"AWS error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Run the audit

Use the default AWS credential chain:

```bash
python s3_security_audit.py
```

Use a named AWS profile:

```bash
python s3_security_audit.py --profile dev
```

Specify a region for the S3 client and a custom report path:

```bash
python s3_security_audit.py --profile production --region ap-south-1 --output reports/s3-audit.json
```

Create the `reports` directory first if it does not exist.

## Understanding the results

| Status | Meaning |
|---|---|
| `PASS` | The check passed the script's baseline rule. |
| `FAIL` | A likely security gap was detected, such as missing bucket-level Block Public Access or default encryption. |
| `REVIEW` | Manual review is needed; for example, a wildcard-principal policy or disabled versioning/logging. |
| `UNKNOWN` | The check could not be completed, commonly due to missing IAM permissions or an API error. |

## Recommended remediation

1. Enable all four S3 Block Public Access settings unless public access is an intentional, approved requirement.
2. Review bucket ACLs and bucket policies before removing grants or changing policy statements.
3. Enable default encryption. Use SSE-KMS where your security requirements call for customer-managed keys.
4. Enable versioning where recovery from accidental deletion or overwrites is required.
5. Configure server access logging or an approved alternative audit trail based on your organization's logging requirements.
6. Review Object Ownership and prefer `BucketOwnerEnforced` where disabling ACLs is compatible with the workload.
7. Re-run the audit after approved changes and retain the JSON report.

## Production notes

- The script is **read-only**; it does not remediate findings.
- Bucket-level Block Public Access does not show account-level or organization-level controls. Review those separately.
- The wildcard-principal policy check is intentionally conservative and can flag statements whose conditions restrict access.
- Encryption status checks default bucket encryption; they do not inspect every object's encryption metadata.
- Versioning and logging are workload-dependent recommendations, not universal compliance guarantees.
- Avoid committing audit reports to public repositories; they can reveal bucket names, account IDs, and configuration details.
