# Find Unused AWS Elastic IPs with Python (Boto3)

## Problem Statement

AWS Elastic IPs (EIPs) that are allocated but not associated with a
running resource can create unnecessary costs. This script identifies
**unassociated Elastic IP addresses** across AWS Regions so you can
review and release them if they are no longer needed.

> **Safety:** This script is read-only. It reports unused Elastic IPs
> and does not release or modify any AWS resources.

## Prerequisites

-   Python 3.9+
-   AWS CLI credentials configured, or an IAM role attached to the
    execution environment
-   Boto3 installed

``` bash
python -m pip install boto3
aws configure
```

The IAM identity needs permission to describe Regions and Elastic IPs:

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "ec2:DescribeAddresses"
      ],
      "Resource": "*"
    }
  ]
}
```

## Python Script

Save this script as `find_unused_elastic_ips.py`.

``` python
#!/usr/bin/env python3
\"\"\"Report unassociated AWS Elastic IP addresses across Regions.\"\"\"

import argparse
import sys
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def get_regions(session: boto3.Session) -> list[str]:
    \"\"\"Return enabled Regions that are available to this account.\"\"\"
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response["Regions"])


def find_unused_eips(session: boto3.Session, regions: list[str]) -> list[dict[str, Any]]:
    \"\"\"Collect Elastic IPs that have no AssociationId in each requested Region.\"\"\"
    unused: list[dict[str, Any]] = []

    for region in regions:
        print(f"Checking Region: {region}", file=sys.stderr)
        ec2 = session.client("ec2", region_name=region)

        try:
            paginator = ec2.get_paginator("describe_addresses")
            for page in paginator.paginate():
                for address in page.get("Addresses", []):
                    # An absent AssociationId means the EIP is not associated
                    # with an EC2 instance or another supported network resource.
                    if not address.get("AssociationId"):
                        unused.append(
                            {
                                "Region": region,
                                "PublicIp": address.get("PublicIp", "N/A"),
                                "AllocationId": address.get("AllocationId", "N/A"),
                                "Domain": address.get("Domain", "N/A"),
                                "NetworkBorderGroup": address.get(
                                    "NetworkBorderGroup", "N/A"
                                ),
                                "Tags": address.get("Tags", []),
                            }
                        )
        except (BotoCoreError, ClientError) as exc:
            print(
                f"WARNING: Could not inspect {region}: {exc}",
                file=sys.stderr,
            )

    return unused


def format_tags(tags: list[dict[str, str]]) -> str:
    \"\"\"Format AWS tags into a compact key=value string.\"\"\"
    if not tags:
        return "-"
    return ", ".join(
        f"{tag.get('Key', '')}={tag.get('Value', '')}" for tag in tags
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find unassociated AWS Elastic IP addresses."
    )
    parser.add_argument(
        "--region",
        help="Inspect one Region only (example: ap-south-1). Default: all enabled Regions.",
    )
    parser.add_argument(
        "--profile",
        help="AWS CLI profile to use (optional). Defaults to the normal Boto3 credential chain.",
    )
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        regions = [args.region] if args.region else get_regions(session)
        unused = find_unused_eips(session, regions)
    except (BotoCoreError, ClientError) as exc:
        print(f"ERROR: AWS request failed: {exc}", file=sys.stderr)
        return 1

    if not unused:
        print("\\nNo unassociated Elastic IPs were found in the Regions checked.")
        return 0

    print(f"\\nFound {len(unused)} unassociated Elastic IP(s):\\n")
    print(
        f"{'REGION':<16} {'PUBLIC IP':<16} {'ALLOCATION ID':<25} "
        f"{'DOMAIN':<10} {'NETWORK BORDER GROUP':<24} TAGS"
    )
    print("-" * 115)

    for item in unused:
        print(
            f"{item['Region']:<16} {item['PublicIp']:<16} "
            f"{item['AllocationId']:<25} {item['Domain']:<10} "
            f"{item['NetworkBorderGroup']:<24} {format_tags(item['Tags'])}"
        )

    print(
        "\\nReview these addresses before releasing them. An address may be "
        "intentionally reserved for later use."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Run the Script

### Scan all enabled AWS Regions

``` bash
python find_unused_elastic_ips.py
```

### Scan a single Region

Example for Mumbai:

``` bash
python find_unused_elastic_ips.py --region ap-south-1
```

### Use a named AWS CLI profile

``` bash
python find_unused_elastic_ips.py --profile production
```

You can combine options:

``` bash
python find_unused_elastic_ips.py --profile production --region ap-south-1
```

## Example Output

``` text
Checking Region: ap-south-1
Checking Region: us-east-1

Found 2 unassociated Elastic IP(s):

REGION           PUBLIC IP        ALLOCATION ID             DOMAIN     NETWORK BORDER GROUP     TAGS
-------------------------------------------------------------------------------------------------------------------
ap-south-1       203.0.113.10     eipalloc-0123456789abcdef0 vpc        ap-south-1               Environment=dev
us-east-1        198.51.100.20    eipalloc-0abcdef1234567890 vpc        us-east-1                -

Review these addresses before releasing them. An address may be intentionally reserved for later use.
```

*The IP addresses and allocation IDs above are illustrative examples.*

## How It Works

1.  Creates a Boto3 session using the default credential chain or an
    optional named profile.
2.  Retrieves the account's enabled AWS Regions, unless `--region` is
    specified.
3.  Uses the `DescribeAddresses` API with pagination in each Region.
4.  Flags addresses that do not have an `AssociationId`.
5.  Prints the Region, public IP, allocation ID, network border group,
    and tags.

## Important Notes

-   The script only reports EIPs that are **not associated**. It does
    not determine whether an address is operationally safe to release.
-   Review ownership, tags, infrastructure-as-code definitions, DNS
    records, and planned usage before taking action.
-   AWS charges can apply to public IPv4 addresses, including Elastic
    IPs, depending on current AWS pricing and usage. Check the current
    AWS pricing page for your account and Region.
-   For production use, run with a read-only IAM identity and consider
    saving the output to a report for review.

## Troubleshooting

**`NoCredentialsError`** - Configure credentials with `aws configure`,
use `--profile`, or run from an AWS environment with an attached IAM
role.

**`AccessDenied`** - Confirm the IAM identity can call
`ec2:DescribeRegions` and `ec2:DescribeAddresses`.

**A Region fails to scan** - Check that the Region is enabled for the
account and that the identity has the required permissions there. The
script warns and continues to other Regions when an individual Region
cannot be inspected.
