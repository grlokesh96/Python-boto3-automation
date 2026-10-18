# AWS CloudWatch Log Retention Automation with Python (Boto3)

Automatically identify CloudWatch Log Groups with missing or excessive
retention periods and optionally apply a standard retention policy.

## Problem Statement

CloudWatch Logs can accumulate indefinitely when log groups have no
retention policy. This can increase AWS costs and leave operational or
application logs stored longer than your organization requires.

## Solution

This script uses **Python and Boto3** to:

-   Discover CloudWatch Log Groups in the configured AWS Region.
-   Report each log group's current retention setting.
-   Identify groups with no retention policy or a retention period
    longer than the target.
-   Apply the target retention period only when you explicitly pass
    `--apply`.
-   Leave groups with a shorter retention period unchanged.
-   Paginate through log groups so larger accounts are handled
    correctly.

> **Safety:** The script runs in dry-run mode by default. It does not
> change retention settings unless you pass `--apply`. Review the
> proposed changes and ensure the target retention period meets your
> organization's compliance and audit requirements.

## Prerequisites

-   Python 3.9+
-   AWS CLI configured, or another supported Boto3 credential provider
-   IAM permissions:
    -   `logs:DescribeLogGroups`
    -   `logs:PutRetentionPolicy` (required only when applying changes)

Install Boto3:

``` bash
python -m pip install boto3
```

Configure credentials using an IAM role, AWS profile, or another
approved credential provider. Avoid hardcoding AWS access keys in the
script.

## Python Script

Save as `cloudwatch_log_retention.py`:

``` python
#!/usr/bin/env python3

import argparse
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# CloudWatch Logs supported retention periods, in days.
VALID_RETENTION_DAYS = {
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180,
    365, 400, 545, 731, 1096, 1827, 2192, 2557,
    2922, 3288, 3653,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit and optionally standardize CloudWatch Log Group retention."
    )
    parser.add_argument(
        "--region",
        default=None,
        help="AWS Region (defaults to the configured AWS region).",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=30,
        help="Target retention period in days (default: 30).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, the script only reports proposed changes.",
    )
    return parser.parse_args()


def get_log_groups(client):
    """Yield all log groups, handling AWS API pagination."""
    paginator = client.get_paginator("describe_log_groups")
    for page in paginator.paginate():
        yield from page.get("logGroups", [])


def main():
    args = parse_args()

    if args.retention_days not in VALID_RETENTION_DAYS:
        valid = ", ".join(map(str, sorted(VALID_RETENTION_DAYS)))
        print(
            f"Error: unsupported retention period {args.retention_days}. "
            f"Choose one of: {valid}",
            file=sys.stderr,
        )
        return 2

    try:
        session = boto3.Session(region_name=args.region)
        client = session.client("logs")

        region = session.region_name
        if not region:
            print(
                "Error: AWS Region is not configured. Set AWS_DEFAULT_REGION "
                "or pass --region.",
                file=sys.stderr,
            )
            return 2

        mode = "APPLY" if args.apply else "DRY RUN"
        print(f"Region: {region}")
        print(f"Target retention: {args.retention_days} days")
        print(f"Mode: {mode}\\n")

        scanned = 0
        proposed = 0
        updated = 0
        unchanged = 0
        failed = 0

        for group in get_log_groups(client):
            scanned += 1
            name = group["logGroupName"]
            current = group.get("retentionInDays")

            if current is None or current > args.retention_days:
                proposed += 1
                current_label = "Never expire" if current is None else f"{current} days"
                action_label = (
                    f"Set to {args.retention_days} days"
                    if args.apply
                    else f"Would set to {args.retention_days} days"
                )
                print(f"[CHANGE] {name}: {current_label} -> {action_label}")

                if args.apply:
                    try:
                        client.put_retention_policy(
                            logGroupName=name,
                            retentionInDays=args.retention_days,
                        )
                        updated += 1
                    except (ClientError, BotoCoreError) as exc:
                        failed += 1
                        print(f"  [ERROR] Could not update {name}: {exc}")
            else:
                unchanged += 1
                print(f"[KEEP]   {name}: {current} days (already at or below target)")

        print("\\n--- Summary ---")
        print(f"Log groups scanned: {scanned}")
        print(f"Groups requiring a change: {proposed}")
        print(f"Groups unchanged: {unchanged}")
        if args.apply:
            print(f"Successfully updated: {updated}")
            print(f"Failed updates: {failed}")
        else:
            print("Dry run only: no changes were made.")
            print("Re-run with --apply to apply the proposed updates.")

        return 1 if failed else 0

    except (ClientError, BotoCoreError) as exc:
        print(f"AWS API error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Usage

### 1. Audit in dry-run mode

This is the default and makes no changes:

``` bash
python cloudwatch_log_retention.py --region ap-south-1 --retention-days 30
```

### 2. Apply the retention policy

After reviewing the dry-run output:

``` bash
python cloudwatch_log_retention.py --region ap-south-1 --retention-days 30 --apply
```

### 3. Use another supported retention period

For example, retain logs for 90 days:

``` bash
python cloudwatch_log_retention.py --region ap-south-1 --retention-days 90
```

Add `--apply` only when you are ready to make the changes.

## How It Works

1.  Creates a Boto3 CloudWatch Logs client for the selected Region.
2.  Retrieves log groups using the `describe_log_groups` paginator.
3.  Checks each group's `retentionInDays` value.
4.  Proposes a change if retention is not configured or exceeds the
    target.
5.  Calls `put_retention_policy` only when `--apply` is supplied.
6.  Prints a summary of scanned, changed, unchanged, and failed groups.

## Important Notes

-   The script processes **one AWS Region per run**. Run it for each
    Region you manage.
-   It does not delete log groups.
-   A shorter existing retention period is preserved; the script does
    not extend it.
-   Setting a shorter retention period can make older log events
    eligible for deletion. Confirm retention, legal hold, and audit
    requirements before applying changes.
-   For production use, prefer an appropriately scoped IAM role and
    consider running the script through a reviewed scheduled workflow.
-   AWS account and Region selection depend on the credentials and
    configuration used by Boto3.

## Example IAM Policy

Attach a policy like the following to the role or identity running the
script. Replace the Region and account ID with your own values. The
`Resource` scope should be narrowed to approved log groups where
practical.

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeCloudWatchLogGroups",
      "Effect": "Allow",
      "Action": "logs:DescribeLogGroups",
      "Resource": "*"
    },
    {
      "Sid": "UpdateCloudWatchLogRetention",
      "Effect": "Allow",
      "Action": "logs:PutRetentionPolicy",
      "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:*"
    }
  ]
}
```

## Expected Outcome

The script helps standardize CloudWatch Logs retention, reduce
indefinite log storage, and make retention settings easier to
audit---while keeping changes opt-in through dry-run mode.

**Recommended workflow:** Audit → review proposed changes → confirm
compliance requirements → run with `--apply`.
