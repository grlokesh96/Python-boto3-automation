# Stop Idle Amazon EC2 Instances with Python (Boto3)

This project identifies **running EC2 instances with low average CPU
utilization** and stops only instances explicitly opted in with the tag
`AutoStop=true`.

> **Safety first:** The script runs in **dry-run mode by default**.
> Review candidates before enabling actual stops. CPU usage alone does
> not prove that an instance is unused; validate workloads and business
> requirements before stopping anything.

## Features

-   Uses AWS SDK for Python (`boto3`).
-   Reads CPU utilization from Amazon CloudWatch over a configurable
    lookback period.
-   Stops only running instances tagged `AutoStop=true`.
-   Skips instances without a usable CloudWatch datapoint.
-   Supports dry-run mode and configurable CPU threshold/lookback.
-   Prints instance ID, name, average CPU, and planned action.

## Prerequisites

-   Python 3.9+
-   AWS account permissions to describe instances, read CloudWatch
    metrics, and (when applying changes) stop opted-in instances.
-   AWS credentials configured through an IAM role, AWS profile, or
    environment credentials.

Install Boto3:

``` bash
python -m pip install boto3
```

Configure credentials using an IAM role where possible, or an AWS
profile:

``` bash
aws configure --profile dev
aws sts get-caller-identity --profile dev
```

## Opt in instances with a tag

Add this tag to each instance approved for automated stopping:

  Key          Value
  ------------ --------
  `AutoStop`   `true`

Do not tag production or stateful workloads until their owners have
confirmed they can be stopped safely.

## Script: `stop_idle_ec2.py`

``` python
#!/usr/bin/env python3
"""Stop opted-in EC2 instances whose average CPU is below a threshold.

Dry-run is enabled by default. Pass --apply to actually stop instances.
This script uses CPU utilization only; review candidates before applying.
"""

import argparse
import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError


LOG = logging.getLogger("stop-idle-ec2")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Find and optionally stop opted-in idle EC2 instances."
    )
    parser.add_argument("--region", required=True, help="AWS region, e.g. ap-south-1")
    parser.add_argument("--profile", help="Optional AWS CLI profile name")
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        default=5.0,
        help="Stop candidates with average CPU below this percentage (default: 5).",
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
        help="CloudWatch lookback window in hours (default: 24).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually stop eligible instances. Without this flag, only report candidates.",
    )
    parser.add_argument(
        "--minimum-age-hours",
        type=int,
        default=24,
        help="Require instance launch time to be at least this old (default: 24).",
    )
    return parser.parse_args()


def get_name(tags):
    return next(
        (tag["Value"] for tag in (tags or []) if tag["Key"] == "Name"),
        "N/A",
    )


def average_cpu(cloudwatch, instance_id, start_time, end_time):
    response = cloudwatch.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
        StartTime=start_time,
        EndTime=end_time,
        Period=3600,
        Statistics=["Average"],
    )
    datapoints = response.get("Datapoints", [])
    if not datapoints:
        return None

    return sum(point["Average"] for point in datapoints) / len(datapoints)


def main():
    args = parse_args()

    if not 0 <= args.cpu_threshold <= 100:
        raise SystemExit("--cpu-threshold must be between 0 and 100.")
    if args.lookback_hours < 1 or args.minimum_age_hours < 0:
        raise SystemExit("--lookback-hours must be >= 1 and --minimum-age-hours >= 0.")

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    session_args = {"region_name": args.region}
    if args.profile:
        session_args["profile_name"] = args.profile

    session = boto3.Session(**session_args)
    ec2 = session.client("ec2")
    cloudwatch = session.client("cloudwatch")

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=args.lookback_hours)
    minimum_launch_time = now - timedelta(hours=args.minimum_age_hours)

    filters = [
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "tag:AutoStop", "Values": ["true", "True", "TRUE"]},
    ]

    candidates = []
    paginator = ec2.get_paginator("describe_instances")

    try:
        for page in paginator.paginate(Filters=filters):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    instance_id = instance["InstanceId"]
                    name = get_name(instance.get("Tags", []))
                    launch_time = instance.get("LaunchTime")

                    if launch_time and launch_time > minimum_launch_time:
                        LOG.info(
                            "SKIP %s (%s): launched less than %s hours ago.",
                            instance_id, name, args.minimum_age_hours,
                        )
                        continue

                    cpu = average_cpu(cloudwatch, instance_id, start_time, now)

                    # Missing data is not proof that an instance is idle.
                    if cpu is None:
                        LOG.info(
                            "SKIP %s (%s): no CPU datapoints for lookback window.",
                            instance_id, name,
                        )
                        continue

                    if cpu < args.cpu_threshold:
                        candidates.append((instance_id, name, cpu))

        if not candidates:
            LOG.info("No eligible idle instances found.")
            return

        LOG.info("Eligible instances:")
        for instance_id, name, cpu in candidates:
            LOG.info(
                "InstanceId=%s Name=%s AvgCPU=%.2f%%",
                instance_id, name, cpu,
            )

        if not args.apply:
            LOG.warning(
                "DRY RUN: no instances were stopped. Re-run with --apply "
                "after reviewing the candidates."
            )
            return

        response = ec2.stop_instances(
            InstanceIds=[item[0] for item in candidates]
        )
        for item in response.get("StoppingInstances", []):
            LOG.info(
                "Stop requested for %s (previous=%s, current=%s).",
                item["InstanceId"],
                item["PreviousState"]["Name"],
                item["CurrentState"]["Name"],
            )

    except (BotoCoreError, ClientError) as exc:
        LOG.error("AWS API request failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
```

## Run the script

### 1. Dry run (recommended)

Reports eligible instances but does not stop them:

``` bash
python stop_idle_ec2.py --region ap-south-1
```

Use a named AWS profile if required:

``` bash
python stop_idle_ec2.py --region ap-south-1 --profile dev
```

Customize the threshold and lookback window:

``` bash
python stop_idle_ec2.py \
  --region ap-south-1 \
  --cpu-threshold 5 \
  --lookback-hours 24 \
  --minimum-age-hours 24
```

### 2. Actually stop eligible instances

Only after reviewing the dry-run output and confirming the instances are
safe to stop:

``` bash
python stop_idle_ec2.py --region ap-south-1 --apply
```

## Minimum IAM permissions

Attach a least-privilege policy to the execution role/user. Scope
`ec2:StopInstances` to the intended instance ARNs and consider enforcing
the `AutoStop=true` tag condition. The example below shows the core
actions; tighten resource scope and conditions for your environment.

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DescribeInstances",
      "Effect": "Allow",
      "Action": ["ec2:DescribeInstances"],
      "Resource": "*"
    },
    {
      "Sid": "ReadInstanceCpuMetrics",
      "Effect": "Allow",
      "Action": ["cloudwatch:GetMetricStatistics"],
      "Resource": "*"
    },
    {
      "Sid": "StopApprovedInstances",
      "Effect": "Allow",
      "Action": ["ec2:StopInstances"],
      "Resource": "arn:aws:ec2:ap-south-1:123456789012:instance/*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/AutoStop": "true"
        }
      }
    }
  ]
}
```

Replace `123456789012` with your AWS account ID and adjust the region
and resource scope. IAM condition keys and tag matching are
case-sensitive; use a consistent tag value of `true`.

## Important limitations

-   **Low CPU does not necessarily mean idle.** An instance may be
    waiting for scheduled work, serving infrequent requests, or
    performing disk/network operations.
-   This script does not evaluate network traffic, disk I/O, application
    health, or Auto Scaling Group membership. Add safeguards before
    using it broadly.
-   CloudWatch datapoints may be sparse or delayed. Instances with no
    datapoints are skipped.
-   Stopping an instance can interrupt workloads. Instance-store data is
    lost when the instance stops, and public IPv4 addresses may change
    unless an Elastic IP is used.
-   Stopping and starting may not be appropriate for databases,
    production services, or instances managed by Auto Scaling.
-   Test in a non-production account first. For scheduled governance,
    consider AWS Instance Scheduler or a reviewed EventBridge/Lambda
    workflow.

## Suggested improvements

For a production-ready version, consider adding: - Exclusions for
production environments and Auto Scaling Groups. - Multiple signals such
as CPU, network, and disk activity. - An allowlist of approved instance
IDs or environments. - Notifications to SNS or Slack before stopping. -
CloudTrail/audit logging and a mandatory approval window. - Scheduled
execution with EventBridge and a dedicated IAM role.

## Troubleshooting

-   **`NoCredentialsError`:** configure an AWS profile or use an
    attached IAM role.
-   **`AccessDenied`:** verify the execution identity has the required
    EC2 and CloudWatch permissions.
-   **No candidates found:** confirm instances are running, tagged
    `AutoStop=true`, old enough, and have CloudWatch CPU datapoints
    below the threshold.
-   **Wrong region:** pass the region where the instances run, such as
    `ap-south-1`.

## License

Use and adapt this script according to your organization's security and
change-management policies.
