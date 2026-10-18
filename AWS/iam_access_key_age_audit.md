# IAM Access Key Age Audit with Python (Boto3)

Audit IAM users' access keys, calculate their age, and flag keys that exceed a configurable age threshold. The script is **read-only**: it does not disable or delete keys.

## Features

- Lists IAM users and their access keys.
- Reports key ID, status, creation date, age in days, and last-used information when available.
- Flags keys older than the configured threshold.
- Supports CSV output for reporting and follow-up.
- Uses the AWS SDK credential chain; no credentials are hardcoded.

> **Security note:** Access key IDs are identifiers, not secret access keys. Never print, store, or commit secret access keys.

## Prerequisites

- Python 3.9+
- Boto3 installed
- AWS credentials configured through an IAM role, AWS profile, environment, or another supported AWS credential provider
- IAM permissions:
  - `iam:ListUsers`
  - `iam:ListAccessKeys`
  - `iam:GetAccessKeyLastUsed`

Install Boto3:

```bash
python -m pip install boto3
```

## Script: `iam_access_key_age_audit.py`

```python
#!/usr/bin/env python3
\"\"\"Audit IAM access-key age and export findings to CSV (read-only).\"\"\"

import argparse
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def age_in_days(created_at, now):
    \"\"\"Return the age in whole days, or None if creation time is unavailable.\"\"\"
    if not created_at:
        return None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return (now - created_at.astimezone(timezone.utc)).days


def audit_access_keys(session, max_age_days):
    \"\"\"Return one report row per IAM access key.\"\"\"
    iam = session.client("iam")
    now = datetime.now(timezone.utc)
    rows = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            username = user["UserName"]

            key_paginator = iam.get_paginator("list_access_keys")
            for key_page in key_paginator.paginate(UserName=username):
                for key in key_page.get("AccessKeyMetadata", []):
                    key_id = key["AccessKeyId"]
                    created_at = key.get("CreateDate")
                    age_days = age_in_days(created_at, now)

                    try:
                        last_used_response = iam.get_access_key_last_used(
                            AccessKeyId=key_id
                        )
                        last_used = last_used_response.get(
                            "AccessKeyLastUsed", {}
                        )
                        last_used_date = last_used.get("LastUsedDate")
                        last_used_service = last_used.get("ServiceName", "N/A")
                        last_used_region = last_used.get("Region", "N/A")
                    except (ClientError, BotoCoreError) as exc:
                        # Keep the audit running, but make incomplete data visible.
                        last_used_date = None
                        last_used_service = "LOOKUP_ERROR"
                        last_used_region = "LOOKUP_ERROR"
                        print(
                            f"Warning: couldn't retrieve last-used data for "
                            f"{key_id}: {exc}",
                            file=sys.stderr,
                        )

                    age_status = (
                        "OVER_AGE_THRESHOLD"
                        if age_days is not None and age_days > max_age_days
                        else "WITHIN_THRESHOLD"
                    )

                    rows.append(
                        {
                            "username": username,
                            "access_key_id": key_id,
                            "status": key.get("Status", "UNKNOWN"),
                            "created_at_utc": (
                                created_at.astimezone(timezone.utc).isoformat()
                                if created_at
                                else ""
                            ),
                            "age_days": age_days if age_days is not None else "",
                            "max_age_days": max_age_days,
                            "age_status": age_status,
                            "last_used_at_utc": (
                                last_used_date.astimezone(timezone.utc).isoformat()
                                if last_used_date
                                else "Never/Not reported"
                            ),
                            "last_used_service": last_used_service,
                            "last_used_region": last_used_region,
                        }
                    )

    return rows


def write_csv(rows, output_path):
    fields = [
        "username",
        "access_key_id",
        "status",
        "created_at_utc",
        "age_days",
        "max_age_days",
        "age_status",
        "last_used_at_utc",
        "last_used_service",
        "last_used_region",
    ]
    with Path(output_path).open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Read-only IAM access key age audit."
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=90,
        help="Flag keys older than this number of days (default: 90).",
    )
    parser.add_argument(
        "--profile",
        help="Optional AWS CLI profile name, e.g. audit.",
    )
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for the SDK client configuration (default: us-east-1). "
             "IAM is a global service.",
    )
    parser.add_argument(
        "--output",
        default="iam_access_key_age_audit.csv",
        help="CSV report path (default: iam_access_key_age_audit.csv).",
    )
    args = parser.parse_args()

    if args.max_age_days < 0:
        parser.error("--max-age-days must be zero or greater")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)

    try:
        rows = audit_access_keys(session, args.max_age_days)
    except (ClientError, BotoCoreError) as exc:
        print(f"AWS audit failed: {exc}", file=sys.stderr)
        return 1

    write_csv(rows, args.output)

    flagged = [
        row for row in rows
        if row["age_status"] == "OVER_AGE_THRESHOLD"
    ]
    print(f"Access keys audited: {len(rows)}")
    print(f"Keys older than {args.max_age_days} days: {len(flagged)}")
    print(f"CSV report saved to: {args.output}")

    for row in flagged:
        print(
            f"[OVER AGE] user={row['username']} "
            f"key_id={row['access_key_id']} "
            f"status={row['status']} age_days={row['age_days']} "
            f"last_used={row['last_used_at_utc']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Configure AWS credentials

Use an IAM role when running on AWS (for example, an EC2 instance role or an approved CI/CD role). For local use, configure a named profile:

```bash
aws configure --profile audit
aws sts get-caller-identity --profile audit
```

Avoid placing access keys directly in the script or committing credentials to Git.

## Run the audit

Use the default 90-day threshold:

```bash
python iam_access_key_age_audit.py
```

Use a named profile and a 60-day threshold:

```bash
python iam_access_key_age_audit.py --profile audit --max-age-days 60
```

Choose a custom report path:

```bash
python iam_access_key_age_audit.py --profile audit --max-age-days 90 --output reports/iam-key-audit.csv
```

Create the output directory first if it does not exist:

```bash
mkdir -p reports
```

## Example output

```text
Access keys audited: 4
Keys older than 90 days: 2
CSV report saved to: iam_access_key_age_audit.csv
[OVER AGE] user=deployment-user key_id=AKIAEXAMPLE000000001 age_days=143 status=Active last_used=2026-10-12T07:30:00+00:00
[OVER AGE] user=legacy-user key_id=AKIAEXAMPLE000000002 age_days=231 status=Inactive last_used=Never/Not reported
```

The sample key IDs and dates above are illustrative only.

## How to interpret the report

- `OVER_AGE_THRESHOLD`: the key age is greater than the configured threshold.
- `WITHIN_THRESHOLD`: the key is at or below the threshold.
- `Never/Not reported`: AWS has no last-used timestamp available for the key. Verify before deciding whether it is unused; last-used tracking has limitations.
- `LOOKUP_ERROR`: the script could not retrieve last-used details. Review the warning and IAM permissions.

The script reports key age, not whether a key is safe to keep. Review ownership, workload dependencies, rotation plans, and last-used information before taking action. A common operational policy is to rotate long-lived access keys and prefer temporary credentials through IAM roles wherever possible.

## Recommended security improvements

1. Prefer IAM roles and short-lived credentials over long-lived IAM user access keys.
2. Rotate keys using a planned process that avoids application downtime.
3. Investigate old or unused keys with their owners before disabling them.
4. Never automatically delete or disable keys solely because they exceed an age threshold.
5. Run the audit on a schedule and store reports in an access-controlled location.
6. Consider using AWS IAM Access Analyzer and AWS Config rules alongside this script for broader governance.

## Troubleshooting

**`AccessDenied`**

Confirm that the identity running the script has `iam:ListUsers`, `iam:ListAccessKeys`, and `iam:GetAccessKeyLastUsed` permissions.

**No users or keys appear**

Check that the intended AWS account is selected:

```bash
aws sts get-caller-identity --profile audit
```

IAM is account-wide and global; the `--region` argument configures the SDK client but does not scope IAM users to a region.

**CSV output path fails**

Create the parent directory before running the script.

---

**Disclaimer:** Test in a non-production account first. This script performs read-only auditing and does not modify IAM users or access keys.
