# AWS ECR Image Cleanup with Python (Boto3)

This guide provides a cautious cleanup script for removing old Amazon
Elastic Container Registry (ECR) images while retaining the newest
images in each repository.

## What the script does

-   Lists ECR repositories, or processes repositories explicitly
    supplied on the command line.
-   Sorts images by `imagePushedAt` (newest first).
-   Retains the newest **N unique image digests** per repository.
-   Protects images that have tags such as `latest`, `prod`,
    `production`, `stable`, or `release`.
-   Runs in **dry-run mode by default**. It only deletes when you pass
    `--execute`.
-   Uses AWS SDK pagination and reports failures without silently
    treating them as successful deletions.

> **Important:** ECR image deletion is destructive. Review the dry-run
> output and confirm your deployment/rollback retention requirements
> before running with `--execute`. An image digest can have multiple
> tags; deleting that digest removes all its tags. Protected-tag images
> are skipped.

## Prerequisites

-   Python 3.9+
-   AWS CLI credentials or an IAM role configured for the target account
-   `boto3`

Install the dependency:

``` bash
python -m pip install boto3
```

Configure credentials using an AWS profile, environment variables, or an
attached IAM role. Avoid hard-coding AWS access keys in the script.

## IAM permissions

Grant the identity running the script only the permissions it needs. For
dry-run inventory, it needs:

-   `ecr:DescribeRepositories`
-   `ecr:DescribeImages`

For actual cleanup, it also needs:

-   `ecr:BatchDeleteImage`

Example policy (scope the resource ARN to the specific repositories
wherever possible):

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListECRRepositoriesAndImages",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DeleteECRImages",
      "Effect": "Allow",
      "Action": "ecr:BatchDeleteImage",
      "Resource": "arn:aws:ecr:REGION:ACCOUNT_ID:repository/*"
    }
  ]
}
```

For stricter least privilege, replace the wildcard repository suffix
with the exact repository ARNs. `DescribeRepositories` and some listing
operations may require `"Resource": "*"`.

## Script: `ecr_image_cleanup.py`

``` python
#!/usr/bin/env python3
\"\"\"Safely prune old Amazon ECR images, retaining the newest N digests.\"\"\"

import argparse
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError


DEFAULT_PROTECTED_TAGS = {
    "latest",
    "prod",
    "production",
    "stable",
    "release",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Prune old ECR image digests; dry-run unless --execute is supplied."
    )
    parser.add_argument("--region", required=True, help="AWS region, e.g. ap-south-1")
    parser.add_argument(
        "--repository",
        action="append",
        dest="repositories",
        help="Repository name to process. Repeat for multiple repositories. "
             "If omitted, all repositories in the region are considered.",
    )
    parser.add_argument(
        "--keep", type=int, default=10,
        help="Number of newest unique image digests to retain per repository (default: 10).",
    )
    parser.add_argument(
        "--protected-tag",
        action="append",
        dest="protected_tags",
        help="Tag that protects an image digest from deletion. Repeat as needed. "
             "Defaults include latest, prod, production, stable, and release.",
    )
    parser.add_argument(
        "--execute", action="store_true",
        help="Actually delete eligible images. Without this flag, the script is dry-run only.",
    )
    parser.add_argument(
        "--profile", help="Optional AWS CLI profile name."
    )
    return parser.parse_args()


def get_ecr_client(region: str, profile: Optional[str]):
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("ecr", region_name=region)


def list_repositories(ecr, requested: Optional[List[str]]) -> List[str]:
    if requested:
        # Preserve order while removing duplicates.
        return list(dict.fromkeys(requested))

    names = []
    paginator = ecr.get_paginator("describe_repositories")
    for page in paginator.paginate():
        names.extend(repo["repositoryName"] for repo in page.get("repositories", []))
    return names


def list_images(ecr, repository: str) -> List[dict]:
    images = []
    paginator = ecr.get_paginator("describe_images")
    for page in paginator.paginate(
        repositoryName=repository,
        filter={"tagStatus": "ANY"},
    ):
        images.extend(page.get("imageDetails", []))
    return images


def image_datetime(image: dict) -> datetime:
    pushed_at = image.get("imagePushedAt")
    if pushed_at is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    # boto3 usually returns a timezone-aware datetime.
    if pushed_at.tzinfo is None:
        return pushed_at.replace(tzinfo=timezone.utc)
    return pushed_at.astimezone(timezone.utc)


def protected(image: dict, protected_tags: Set[str]) -> bool:
    return bool(set(image.get("imageTags", [])) & protected_tags)


def cleanup_repository(ecr, repository: str, keep: int,
                       protected_tags: Set[str], execute: bool) -> int:
    images = list_images(ecr, repository)

    # ECR can return entries without a digest in unusual/partial responses; ignore those.
    by_digest: Dict[str, dict] = {
        image["imageDigest"]: image
        for image in images
        if image.get("imageDigest")
    }
    ordered = sorted(
        by_digest.values(),
        key=image_datetime,
        reverse=True,
    )

    # Always retain the newest `keep` digests, plus any digest carrying a protected tag.
    retained_digests = {
        image["imageDigest"] for image in ordered[:keep]
    }
    candidates = []
    for image in ordered[keep:]:
        if image["imageDigest"] in retained_digests:
            continue
        if protected(image, protected_tags):
            continue
        candidates.append(image)

    print(f"\nRepository: {repository}")
    print(f"  Images found: {len(ordered)}")
    print(f"  Retaining newest digests: {min(keep, len(ordered))}")
    print(f"  Protected tags: {', '.join(sorted(protected_tags))}")
    print(f"  Eligible for deletion: {len(candidates)}")

    deleted_count = 0
    for image in candidates:
        digest = image["imageDigest"]
        tags = image.get("imageTags", [])
        pushed = image_datetime(image).isoformat()
        tag_display = ",".join(tags) if tags else "<untagged>"
        message = f"  digest={digest} tags={tag_display} pushed={pushed}"

        if not execute:
            print(f"  [DRY-RUN] Would delete {message}")
            continue

        try:
            response = ecr.batch_delete_image(
                repositoryName=repository,
                imageIds=[{"imageDigest": digest}],
            )
            failures = response.get("failures", [])
            if failures:
                print(f"  [FAILED] {message}: {failures}", file=sys.stderr)
            else:
                print(f"  [DELETED] {message}")
                deleted_count += 1
        except (ClientError, BotoCoreError) as exc:
            print(f"  [ERROR] Could not delete {message}: {exc}", file=sys.stderr)

    if not execute:
        print("  Dry-run only: no images were deleted.")
    else:
        print(f"  Successfully deleted digests: {deleted_count}")
    return deleted_count


def main():
    args = parse_args()
    if args.keep < 0:
        print("--keep must be zero or greater.", file=sys.stderr)
        return 2

    protected_tags = set(DEFAULT_PROTECTED_TAGS)
    if args.protected_tags:
        protected_tags.update(tag.strip() for tag in args.protected_tags if tag.strip())

    try:
        ecr = get_ecr_client(args.region, args.profile)
        repositories = list_repositories(ecr, args.repositories)
        if not repositories:
            print("No ECR repositories found.")
            return 0

        mode = "EXECUTE — images may be deleted" if args.execute else "DRY-RUN — no deletion"
        print(f"Mode: {mode}")
        print(f"Region: {args.region}")
        print(f"Keep per repository: {args.keep}")

        total_deleted = 0
        for repository in repositories:
            try:
                total_deleted += cleanup_repository(
                    ecr=ecr,
                    repository=repository,
                    keep=args.keep,
                    protected_tags=protected_tags,
                    execute=args.execute,
                )
            except (ClientError, BotoCoreError) as exc:
                print(
                    f"[ERROR] Could not process repository {repository}: {exc}",
                    file=sys.stderr,
                )

        print(f"\nTotal digests successfully deleted: {total_deleted}")
        return 0
    except (ClientError, BotoCoreError) as exc:
        print(f"AWS error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
```

## Usage

### 1. Dry-run against all repositories

This is the recommended first step:

``` bash
python ecr_image_cleanup.py --region ap-south-1 --keep 10
```

### 2. Dry-run against selected repositories

``` bash
python ecr_image_cleanup.py \
  --region ap-south-1 \
  --repository my-backend \
  --repository my-frontend \
  --keep 8
```

### 3. Actually delete eligible images

Only after reviewing the dry-run output:

``` bash
python ecr_image_cleanup.py \
  --region ap-south-1 \
  --repository my-backend \
  --keep 10 \
  --execute
```

### 4. Add a custom protected tag

``` bash
python ecr_image_cleanup.py \
  --region ap-south-1 \
  --repository my-backend \
  --keep 10 \
  --protected-tag staging \
  --execute
```

Custom protected tags are added to the default protected tags; they do
not replace them.

## Operational recommendations

1.  Run the script in dry-run mode and review every candidate before
    deletion.
2.  Start with a specific repository and a conservative `--keep` value.
3.  Ensure the retained images cover your rollback and release
    requirements.
4.  Consider using ECR lifecycle policies for routine tag-based cleanup;
    they are often simpler to operate and can apply automatically.
5.  Run cleanup with a dedicated IAM role, scoped to the intended
    repositories, and log output to your normal audit system.
6.  Test in a non-production account before enabling deletion in
    production.

## How retention works

The script retains the newest `--keep` unique image digests in each
repository. It also skips any older digest carrying one of the protected
tags. Images with multiple tags count as one digest, and deleting a
digest removes all tags attached to it.

**Note:** This script uses image push time, not semantic version
ordering or deployment status. If your release process depends on
particular version tags, add those tags to the protected list or use an
ECR lifecycle policy designed for your tagging scheme.
