# Find Unattached AWS EBS Volumes Using Python (Boto3)

## Overview

This script identifies **unattached Amazon Elastic Block Store (EBS) volumes** in one or more AWS regions. EBS volumes in the `available` state are not currently attached to an EC2 instance and may be candidates for review during cloud-cost optimization.

> **Safety:** This script is read-only. It lists and optionally exports unattached volumes; it does **not** delete, modify, or detach any resources. Review each volume before taking action because an unattached volume may contain data that must be retained.

## Features

- Finds EBS volumes with state `available`.
- Supports one region or multiple regions.
- Displays volume ID, size, type, AZ, creation time, encryption status, and tags.
- Exports results to CSV.
- Uses the AWS SDK for Python (Boto3) and AWS credential provider chain.
- Handles AWS API errors and continues to the next region when possible.

## Prerequisites

- Python 3.9 or newer.
- An AWS account and credentials configured through an AWS profile, environment variables, or an IAM role.
- IAM permission: `ec2:DescribeVolumes`.

## Installation

```bash
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install boto3
```

## Configure AWS credentials

Using an AWS CLI profile:

```bash
aws configure --profile dev
aws sts get-caller-identity --profile dev
```

For EC2, Lambda, or other AWS-hosted execution, prefer an IAM role rather than long-lived access keys.

## Python script

Save as `find_unattached_ebs.py`.

```python
#!/usr/bin/env python3
"""
Find unattached EBS volumes in specified AWS regions.

Read-only: this script only calls DescribeVolumes and optionally writes a CSV.
It does not detach, delete, or modify AWS resources.
"""

import argparse
import csv
import sys
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


CSV_FIELDS = [
    "Region",
    "VolumeId",
    "SizeGiB",
    "VolumeType",
    "State",
    "AvailabilityZone",
    "CreateTime",
    "Encrypted",
    "KmsKeyId",
    "SnapshotId",
    "Tags",
]


def format_tags(tags: list[dict[str, str]]) -> str:
    """Return tags in a compact, readable key=value format."""
    return "; ".join(
        f"{tag.get('Key', '')}={tag.get('Value', '')}"
        for tag in sorted(tags, key=lambda item: item.get("Key", ""))
    )


def find_unattached_volumes(
    session: boto3.Session, region: str
) -> list[dict[str, Any]]:
    """Return EBS volumes in the available state for a region."""
    ec2 = session.client("ec2", region_name=region)
    volumes: list[dict[str, Any]] = []

    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[{"Name": "status", "Values": ["available"]}]
    ):
        volumes.extend(page.get("Volumes", []))

    return volumes


def to_csv_row(region: str, volume: dict[str, Any]) -> dict[str, str]:
    """Convert an AWS volume response into a CSV-safe row."""
    created = volume.get("CreateTime")
    if created:
        created = created.astimezone(timezone.utc).isoformat()
    else:
        created = ""

    return {
        "Region": region,
        "VolumeId": volume.get("VolumeId", ""),
        "SizeGiB": str(volume.get("Size", "")),
        "VolumeType": volume.get("VolumeType", ""),
        "State": volume.get("State", ""),
        "AvailabilityZone": volume.get("AvailabilityZone", ""),
        "CreateTime": created,
        "Encrypted": str(volume.get("Encrypted", "")),
        "KmsKeyId": volume.get("KmsKeyId", ""),
        "SnapshotId": volume.get("SnapshotId", ""),
        "Tags": format_tags(volume.get("Tags", [])),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find unattached EBS volumes (read-only)."
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        required=True,
        help="AWS region names, for example ap-south-1 us-east-1",
    )
    parser.add_argument(
        "--profile",
        help="Optional AWS CLI profile name, for example dev",
    )
    parser.add_argument(
        "--csv",
        default="unattached_ebs_volumes.csv",
        help="CSV output path (default: unattached_ebs_volumes.csv)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    all_rows: list[dict[str, str]] = []
    failed_regions: list[str] = []

    print("Unattached EBS Volume Inventory")
    print(f"Scan started: {datetime.now(timezone.utc).isoformat()}")
    print("Mode: READ-ONLY — no AWS resources will be changed.\n")

    for region in args.regions:
        print(f"Scanning region: {region}")
        try:
            volumes = find_unattached_volumes(session, region)
        except (ClientError, BotoCoreError) as exc:
            print(f"ERROR: Could not scan {region}: {exc}", file=sys.stderr)
            failed_regions.append(region)
            continue

        if not volumes:
            print("  No unattached EBS volumes found.\n")
            continue

        for volume in volumes:
            row = to_csv_row(region, volume)
            all_rows.append(row)
            print(
                f"  Volume ID: {row['VolumeId']}\n"
                f"    Size: {row['SizeGiB']} GiB | Type: {row['VolumeType']}\n"
                f"    AZ: {row['AvailabilityZone']} | State: {row['State']}\n"
                f"    Encrypted: {row['Encrypted']} | Created: {row['CreateTime']}\n"
                f"    Tags: {row['Tags'] or '(none)'}"
            )
        print()

    try:
        with open(args.csv, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(all_rows)
        print(f"CSV report saved to: {args.csv}")
    except OSError as exc:
        print(f"ERROR: Could not write CSV report: {exc}", file=sys.stderr)
        return 1

    print(f"Total unattached volumes found: {len(all_rows)}")
    if failed_regions:
        print(f"Regions that failed: {', '.join(failed_regions)}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Usage

Scan one region:

```bash
python find_unattached_ebs.py --regions ap-south-1
```

Scan multiple regions:

```bash
python find_unattached_ebs.py --regions ap-south-1 us-east-1 eu-west-1
```

Use a named AWS profile:

```bash
python find_unattached_ebs.py --regions ap-south-1 --profile dev
```

Choose a CSV output path:

```bash
python find_unattached_ebs.py \
  --regions ap-south-1 us-east-1 \
  --csv reports/unattached-volumes.csv
```

Ensure the parent directory for a custom CSV path exists before running the script.

## Required IAM permission

The identity running the script needs permission to describe EBS volumes. A minimal policy for this script is:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ec2:DescribeVolumes",
      "Resource": "*"
    }
  ]
}
```

`ec2:DescribeVolumes` is a list/describe action and generally requires `"Resource": "*"`.

## Sample output

```text
Unattached EBS Volume Inventory
Mode: READ-ONLY — no AWS resources will be changed.

Scanning region: ap-south-1
  Volume ID: vol-0123456789abcdef0
    Size: 100 GiB | Type: gp3
    AZ: ap-south-1a | State: available
    Encrypted: True | Created: 2026-09-01T10:00:00+00:00
    Tags: Environment=dev; Name=old-data-volume

CSV report saved to: unattached_ebs_volumes.csv
Total unattached volumes found: 1
```

The volume ID, dates, and tags above are illustrative examples, not live AWS results.

## How it works

1. Creates a Boto3 session using the configured credentials or optional profile.
2. Calls the EC2 `DescribeVolumes` API with the `status=available` filter.
3. Uses a paginator so all matching volumes are retrieved.
4. Prints useful inventory details.
5. Writes all successfully discovered volumes to a CSV report.

## Cost optimization and cleanup checklist

Before deleting any volume:

1. Confirm the volume is not needed for recovery, forensics, migration, or a future deployment.
2. Check its `Name`, `Environment`, `Owner`, and other tags.
3. Review its creation date and associated snapshot or backup strategy.
4. Confirm retention requirements with the application or infrastructure owner.
5. Take and verify a snapshot if required by your recovery policy.
6. Obtain approval and follow your organization's change-management process.

An unattached volume can still incur storage charges. Do not assume it is safe to delete just because its state is `available`.

## Troubleshooting

### `AccessDenied` or `UnauthorizedOperation`

Grant the executing IAM identity `ec2:DescribeVolumes` and verify the active identity:

```bash
aws sts get-caller-identity
```

### No volumes are found

- Confirm the AWS account and profile.
- Verify the selected regions.
- Remember that the script only finds volumes in the `available` state; attached volumes are excluded.
- Check whether AWS Organizations policies or other access controls limit visibility.

### Credentials not found

Configure an AWS CLI profile, provide credentials through the supported environment/provider chain, or use an IAM role. Avoid committing access keys to source control.

## Security notes

- The script makes no changes to AWS resources.
- Keep CSV reports in an approved location; inventory data may reveal infrastructure details.
- Add this script to a scheduled reporting workflow only after validating account and region scope.
- Review findings before any cleanup automation is introduced.

## License

Use and adapt this script according to your repository's license and organizational policies.
