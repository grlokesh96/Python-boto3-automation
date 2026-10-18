# AWS EKS Cluster Audit with Python (Boto3)

A read-only Python script to audit Amazon EKS clusters across one AWS
Region. It reports cluster status, Kubernetes version, endpoint access
configuration, control-plane logging, encryption configuration, node
groups, Fargate profiles, and EKS add-ons.

> **Safety:** This script only calls read-only AWS APIs. It does not
> modify or delete AWS resources. Findings are informational checks, not
> a complete compliance certification.

## 1. Prerequisites

-   Python 3.9+
-   AWS CLI configured with credentials, or an attached IAM role
-   Permission to call the read-only EKS APIs listed below

Install the dependency:

``` bash
python -m pip install boto3
```

Configure credentials if needed:

``` bash
aws configure
aws sts get-caller-identity
```

## 2. IAM permissions

Attach a least-privilege policy like the following to the identity
running the script. Scope resources more narrowly where supported by
your environment.

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "eks:ListClusters",
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup",
        "eks:ListFargateProfiles",
        "eks:DescribeFargateProfile",
        "eks:ListAddons",
        "eks:DescribeAddon"
      ],
      "Resource": "*"
    }
  ]
}
```

## 3. Python script

Save as `eks_cluster_audit.py`.

``` python
#!/usr/bin/env python3
"""Read-only audit of Amazon EKS clusters using boto3."""

import argparse
import json
import sys
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def finding(condition, pass_message, fail_message):
    """Return a simple PASS/REVIEW result for a check."""
    return {
        "status": "PASS" if condition else "REVIEW",
        "message": pass_message if condition else fail_message,
    }


def audit_cluster(eks, cluster_name):
    """Collect cluster configuration and produce basic audit findings."""
    details = eks.describe_cluster(name=cluster_name)["cluster"]
    vpc_config = details.get("resourcesVpcConfig", {})
    logging = details.get("logging", {}).get("clusterLogging", [])
    enabled_log_types = sorted({
        log_type
        for entry in logging
        if entry.get("enabled")
        for log_type in entry.get("types", [])
    })

    encryption = details.get("encryptionConfig", [])
    secrets_encryption_configured = any(
        "secrets" in entry.get("resources", [])
        and bool(entry.get("provider", {}).get("keyArn"))
        for entry in encryption
    )

    public_access = vpc_config.get("endpointPublicAccess", False)
    private_access = vpc_config.get("endpointPrivateAccess", False)
    public_cidrs = vpc_config.get("publicAccessCidrs", [])

    findings = {
        "cluster_active": finding(
            details.get("status") == "ACTIVE",
            "Cluster status is ACTIVE.",
            f"Cluster status is {details.get('status', 'UNKNOWN')}.",
        ),
        "private_endpoint": finding(
            private_access,
            "Private Kubernetes API endpoint access is enabled.",
            "Private Kubernetes API endpoint access is disabled.",
        ),
        "public_endpoint_restricted": finding(
            (not public_access) or (
                bool(public_cidrs)
                and all(cidr != "0.0.0.0/0" and cidr != "::/0"
                        for cidr in public_cidrs)
            ),
            "Public endpoint is disabled or its CIDRs do not include universal access.",
            "Public endpoint allows all IPv4 or IPv6 addresses, or has no explicit CIDR list.",
        ),
        "control_plane_logging": finding(
            all(log_type in enabled_log_types for log_type in
                ("api", "audit", "authenticator", "controllerManager", "scheduler")),
            "All five common EKS control-plane log types are enabled.",
            "One or more common control-plane log types are disabled: "
            + ", ".join(sorted(set(
                ("api", "audit", "authenticator", "controllerManager", "scheduler")
            ) - set(enabled_log_types))),
        ),
        "secrets_encryption": finding(
            secrets_encryption_configured,
            "EKS Secrets encryption configuration with a KMS key is present.",
            "No EKS Secrets encryption configuration with a KMS key was found.",
        ),
    }

    nodegroups = []
    for nodegroup_name in eks.list_nodegroups(clusterName=cluster_name).get(
        "nodegroups", []
    ):
        ng = eks.describe_nodegroup(
            clusterName=cluster_name, nodegroupName=nodegroup_name
        )["nodegroup"]
        nodegroups.append({
            "name": nodegroup_name,
            "status": ng.get("status"),
            "instance_types": ng.get("instanceTypes", []),
            "ami_type": ng.get("amiType"),
            "capacity_type": ng.get("capacityType"),
            "version": ng.get("version"),
            "release_version": ng.get("releaseVersion"),
            "desired_size": ng.get("scalingConfig", {}).get("desiredSize"),
            "min_size": ng.get("scalingConfig", {}).get("minSize"),
            "max_size": ng.get("scalingConfig", {}).get("maxSize"),
            "subnets": ng.get("subnets", []),
        })

    fargate_profiles = []
    for profile_name in eks.list_fargate_profiles(
        clusterName=cluster_name
    ).get("fargateProfileNames", []):
        profile = eks.describe_fargate_profile(
            clusterName=cluster_name, fargateProfileName=profile_name
        )["fargateProfile"]
        fargate_profiles.append({
            "name": profile_name,
            "status": profile.get("status"),
            "selectors": profile.get("selectors", []),
            "subnets": profile.get("subnets", []),
        })

    addons = []
    for addon_name in eks.list_addons(clusterName=cluster_name).get("addons", []):
        addon = eks.describe_addon(
            clusterName=cluster_name, addonName=addon_name
        )["addon"]
        addons.append({
            "name": addon_name,
            "status": addon.get("status"),
            "version": addon.get("addonVersion"),
            "health_issues": addon.get("health", {}).get("issues", []),
        })

    return {
        "cluster": {
            "name": details.get("name"),
            "arn": details.get("arn"),
            "status": details.get("status"),
            "version": details.get("version"),
            "platform_version": details.get("platformVersion"),
            "created_at": details.get("createdAt").isoformat()
                if details.get("createdAt") else None,
            "endpoint": details.get("endpoint"),
            "role_arn": details.get("roleArn"),
            "region": eks.meta.region_name,
            "vpc_id": vpc_config.get("vpcId"),
            "subnets": vpc_config.get("subnetIds", []),
            "security_groups": vpc_config.get("securityGroupIds", []),
            "endpoint_public_access": public_access,
            "endpoint_private_access": private_access,
            "public_access_cidrs": public_cidrs,
            "enabled_control_plane_logs": enabled_log_types,
            "secrets_encryption_configured": secrets_encryption_configured,
            "kubernetes_network_config": details.get("kubernetesNetworkConfig", {}),
        },
        "findings": findings,
        "nodegroups": nodegroups,
        "fargate_profiles": fargate_profiles,
        "addons": addons,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Read-only audit of Amazon EKS clusters."
    )
    parser.add_argument("--region", required=True, help="AWS Region, e.g. ap-south-1")
    parser.add_argument(
        "--cluster",
        help="Optional cluster name. If omitted, audit every cluster in the Region.",
    )
    parser.add_argument(
        "--output",
        default="eks-audit-report.json",
        help="Output JSON filename (default: eks-audit-report.json)",
    )
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    eks = session.client("eks")

    try:
        if args.cluster:
            cluster_names = [args.cluster]
        else:
            paginator = eks.get_paginator("list_clusters")
            cluster_names = [
                name
                for page in paginator.paginate()
                for name in page.get("clusters", [])
            ]

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "region": args.region,
            "cluster_count": len(cluster_names),
            "clusters": [],
            "errors": [],
        }

        for cluster_name in cluster_names:
            try:
                report["clusters"].append(audit_cluster(eks, cluster_name))
                print(f"[OK] Audited cluster: {cluster_name}")
            except (ClientError, BotoCoreError) as exc:
                message = str(exc)
                report["errors"].append({
                    "cluster": cluster_name,
                    "error": message,
                })
                print(f"[ERROR] {cluster_name}: {message}", file=sys.stderr)

        with open(args.output, "w", encoding="utf-8") as output_file:
            json.dump(report, output_file, indent=2, default=str)

        print(f"\\nAudit complete. Clusters found: {len(cluster_names)}")
        print(f"Report written to: {args.output}")
        if report["errors"]:
            print(f"Clusters with audit errors: {len(report['errors'])}")
            sys.exit(1)

    except (ClientError, BotoCoreError) as exc:
        print(f"AWS API error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

## 4. Run the audit

Audit all EKS clusters in Mumbai (`ap-south-1`):

``` bash
python eks_cluster_audit.py --region ap-south-1
```

Audit one cluster only:

``` bash
python eks_cluster_audit.py --region ap-south-1 --cluster my-eks-cluster
```

Choose a report filename:

``` bash
python eks_cluster_audit.py \
  --region ap-south-1 \
  --output eks-audit-report.json
```

The script writes a JSON report containing cluster configuration,
findings, managed node groups, Fargate profiles, add-ons, and any
per-cluster API errors.

## 5. What the audit checks

  -----------------------------------------------------------------------
  Area                                What is reported
  ----------------------------------- -----------------------------------
  Cluster health                      Status, Kubernetes version,
                                      platform version, creation time

  API endpoint                        Public/private access, allowed
                                      public CIDRs

  Control-plane logs                  API, audit, authenticator,
                                      controller manager, scheduler

  Secrets encryption                  Whether a KMS-backed EKS Secrets
                                      encryption configuration is present

  Networking                          VPC, subnet IDs, security group
                                      IDs, Kubernetes network
                                      configuration

  Managed node groups                 Status, instance types, AMI type,
                                      capacity type, scaling settings

  Fargate                             Profile status, selectors, subnet
                                      IDs

  Add-ons                             Status, version, reported health
                                      issues
  -----------------------------------------------------------------------

## 6. Important notes

-   Run the audit in each AWS Region where you operate EKS clusters.
-   A `REVIEW` result is a prompt for human review, not proof of a
    vulnerability. For example, a public endpoint can be appropriate
    when tightly restricted to trusted CIDRs.
-   The encryption check reports the EKS cluster's Secrets encryption
    configuration; it does not inspect application-level secrets or
    every encryption setting in the account.
-   The script reports Kubernetes versions but does not determine
    whether a version is currently supported. Check AWS EKS version
    lifecycle guidance before using the report for upgrade decisions.
-   This is a baseline configuration audit, not a full CIS benchmark or
    AWS compliance assessment.
-   Protect the generated JSON report because it contains infrastructure
    metadata.

## 7. Troubleshooting

**`AccessDeniedException`**\
Confirm the caller has the required `eks:List*` and `eks:Describe*`
permissions.

**No clusters found**\
Verify the AWS account and Region:

``` bash
aws sts get-caller-identity
aws eks list-clusters --region ap-south-1
```

**Expired or missing credentials**\
Refresh your AWS SSO session or configure a valid credential source.
Prefer IAM roles or AWS IAM Identity Center over long-lived access keys.
