# EC2 Security Group Audit with Python (Boto3)

Audit AWS EC2 security groups to identify potentially risky inbound
rules, including public access from `0.0.0.0/0` or `::/0`, unrestricted
access to all ports, and public exposure of commonly sensitive ports
such as SSH and RDP.

> **Safety:** This script is read-only. It reports findings and does not
> modify security groups or AWS resources. Review findings against your
> application requirements before making changes.

## 1. Prerequisites

-   Python 3.9+
-   AWS account permissions to describe EC2 security groups and regions
-   AWS credentials configured through an AWS profile, environment
    variables, or an IAM role

Install Boto3:

``` bash
python -m pip install boto3
```

Configure credentials if needed:

``` bash
aws configure
```

Use least-privilege permissions. The script needs these read-only
actions:

-   `ec2:DescribeRegions`
-   `ec2:DescribeSecurityGroups`

## 2. Python script

Save as `ec2_security_group_audit.py`.

``` python
#!/usr/bin/env python3
"""
EC2 Security Group Audit

Read-only audit for potentially risky inbound security group rules.
Finds public IPv4/IPv6 ingress, unrestricted port ranges, and public
exposure of commonly sensitive ports. Writes findings to CSV.
"""

import argparse
import csv
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# Ports frequently worth reviewing when exposed to the public internet.
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "Microsoft SQL Server",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

PUBLIC_IPV4 = "0.0.0.0/0"
PUBLIC_IPV6 = "::/0"


def format_port_range(permission):
    """Return a readable port or port range."""
    protocol = permission.get("IpProtocol", "-")

    if protocol == "-1":
        return "ALL PORTS"

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if from_port is None:
        return f"Protocol {protocol} (ports not applicable)"

    if to_port is None or from_port == to_port:
        return str(from_port)

    return f"{from_port}-{to_port}"


def get_public_sources(permission):
    """Extract public IPv4/IPv6 CIDRs from one ingress permission."""
    sources = []

    for item in permission.get("IpRanges", []):
        cidr = item.get("CidrIp")
        if cidr == PUBLIC_IPV4:
            sources.append(cidr)

    for item in permission.get("Ipv6Ranges", []):
        cidr = item.get("CidrIpv6")
        if cidr == PUBLIC_IPV6:
            sources.append(cidr)

    return sources


def classify_risk(permission, public_sources):
    """Return a risk level and explanatory finding."""
    protocol = permission.get("IpProtocol", "-1")
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if protocol == "-1":
        return "CRITICAL", "Public ingress allows all protocols and ports"

    exposed_ports = set()
    if from_port is not None:
        end_port = to_port if to_port is not None else from_port
        # Avoid expanding very large ranges into a huge set.
        if end_port - from_port <= 1000:
            exposed_ports.update(range(from_port, end_port + 1))

    labels = [
        f"{port}/{SENSITIVE_PORTS[port]}"
        for port in sorted(exposed_ports)
        if port in SENSITIVE_PORTS
    ]

    if labels:
        severity = "CRITICAL" if 22 in exposed_ports or 3389 in exposed_ports else "HIGH"
        return severity, "Publicly exposed sensitive port(s): " + ", ".join(labels)

    if from_port == 0 and (to_port is None or to_port >= 65535):
        return "CRITICAL", "Public ingress covers the full TCP/UDP port range"

    return "HIGH", "Inbound rule is open to the entire internet; verify business need"


def audit_security_groups(ec2, region):
    """Inspect security groups and return one record per risky ingress rule."""
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for group in page.get("SecurityGroups", []):
            for permission in group.get("IpPermissions", []):
                public_sources = get_public_sources(permission)
                if not public_sources:
                    continue

                severity, reason = classify_risk(permission, public_sources)
                description = permission.get("Description", "")

                for source in public_sources:
                    findings.append({
                        "audit_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "region": region,
                        "group_id": group.get("GroupId", ""),
                        "group_name": group.get("GroupName", ""),
                        "vpc_id": group.get("VpcId", ""),
                        "rule_protocol": permission.get("IpProtocol", ""),
                        "port_range": format_port_range(permission),
                        "public_source": source,
                        "severity": severity,
                        "finding": reason,
                        "rule_description": description,
                        "owner_id": group.get("OwnerId", ""),
                    })

    return findings


def resolve_regions(session, requested_region):
    """Use one requested region, or all enabled regions when set to 'all'."""
    if requested_region and requested_region.lower() != "all":
        return [requested_region]

    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response["Regions"])


def main():
    parser = argparse.ArgumentParser(
        description="Read-only audit for publicly exposed EC2 security group ingress."
    )
    parser.add_argument(
        "--region",
        default="all",
        help="AWS region to audit (default: all enabled regions, e.g. ap-south-1).",
    )
    parser.add_argument(
        "--profile",
        help="Optional AWS CLI profile name.",
    )
    parser.add_argument(
        "--output",
        default="ec2_security_group_audit.csv",
        help="CSV output path (default: ec2_security_group_audit.csv).",
    )
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
        regions = resolve_regions(session, args.region)
        all_findings = []

        for region in regions:
            print(f"Auditing security groups in {region}...", file=sys.stderr)
            ec2 = session.client("ec2", region_name=region)
            all_findings.extend(audit_security_groups(ec2, region))

        fieldnames = [
            "audit_timestamp_utc",
            "region",
            "group_id",
            "group_name",
            "vpc_id",
            "rule_protocol",
            "port_range",
            "public_source",
            "severity",
            "finding",
            "rule_description",
            "owner_id",
        ]

        with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_findings)

        print(f"\nAudit complete. Regions checked: {len(regions)}")
        print(f"Potentially risky rules found: {len(all_findings)}")
        print(f"CSV report: {args.output}")

        if all_findings:
            print("\nFindings summary:")
            for finding in all_findings:
                print(
                    f"[{finding['severity']}] {finding['region']} "
                    f"{finding['group_id']} ({finding['group_name']}) "
                    f"ports={finding['port_range']} source={finding['public_source']} "
                    f"- {finding['finding']}"
                )
        else:
            print("No matching public ingress rules were found.")

    except (BotoCoreError, ClientError) as exc:
        print(f"AWS API error: {exc}", file=sys.stderr)
        sys.exit(1)
    except OSError as exc:
        print(f"Could not write report: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

## 3. Run the audit

Audit all enabled regions:

``` bash
python ec2_security_group_audit.py
```

Audit one region:

``` bash
python ec2_security_group_audit.py --region ap-south-1
```

Use a named AWS profile:

``` bash
python ec2_security_group_audit.py --profile security-audit --region all
```

Choose a report filename:

``` bash
python ec2_security_group_audit.py --region us-east-1 --output security_group_findings.csv
```

## 4. What the script checks

-   Inbound rules open to `0.0.0.0/0` (all IPv4 addresses).
-   Inbound rules open to `::/0` (all IPv6 addresses).
-   Rules allowing all protocols and ports.
-   Public access to sensitive ports such as SSH (`22`), Telnet (`23`),
    RDP (`3389`), databases, Redis, and Elasticsearch.
-   Security group ID, name, VPC, region, port range, rule description,
    and a suggested severity.

The CSV contains one row per public CIDR match in a security group
ingress rule. This is a triage report, not a definitive compliance
verdict; some public-facing ports may be intentional.

## 5. Recommended remediation

1.  Confirm whether each public rule is required.
2.  Replace broad CIDRs with approved source IP ranges, VPN CIDRs, or
    trusted security-group references where possible.
3.  Avoid exposing SSH/RDP and databases directly to the internet;
    prefer a VPN, bastion, or managed access path.
4.  Review IPv4 and IPv6 rules separately.
5.  Re-run the audit after changes and retain the CSV report for
    evidence.

**Important:** The script deliberately does not revoke or modify rules.
Make changes through your approved change-management process and test
application connectivity afterward.
