# AWS Boto3 Automation Runbook

A practical reference for Python-based AWS automation, DevOps operations, cloud security, monitoring, and cost optimization using **Boto3**.

## Table of Contents

- [Overview](#overview)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Reference Topics](#reference-topics)
- [Security Best Practices](#security-best-practices)
- [Development and Testing](#development-and-testing)
- [CI/CD](#cicd)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

## Overview

This repository organizes reusable scripts and notes for common AWS operations. It is intended as a learning resource and day-to-day reference for DevOps and DevSecOps engineering.

### Goals

- Automate repetitive AWS tasks with Python.
- Inventory and manage AWS resources through APIs.
- Use secure AWS authentication and least-privilege permissions.
- Improve operational visibility and troubleshooting.
- Identify potential cloud cost savings.
- Validate scripts with automated tests and CI workflows.

## Technology Stack

- **Language:** Python
- **AWS SDK:** Boto3 and Botocore
- **Cloud services:** EC2, S3, IAM, STS, CloudWatch, EBS, and EKS
- **Testing and quality:** Pytest and Ruff
- **CI/CD:** GitHub Actions with OpenID Connect (OIDC)

## Repository Structure

```text
aws-boto3-automation-runbook/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
├── docs/
│   ├── boto3-fundamentals.md
│   ├── authentication.md
│   ├── ec2-automation.md
│   ├── s3-automation.md
│   ├── iam-security.md
│   ├── monitoring.md
│   ├── cost-optimization.md
│   └── troubleshooting.md
├── scripts/
│   ├── ec2/
│   ├── s3/
│   ├── iam/
│   ├── cloudwatch/
│   └── cost_optimization/
├── tests/
└── .github/
    └── workflows/
        └── python-checks.yml
```

Add folders and files as you implement each topic; this structure is a suggested organization.

## Getting Started

### 1. Prerequisites

- Python 3.10 or later
- An AWS account and permissions for the services you use
- AWS CLI configured with a named profile, or an appropriate IAM role

### 2. Create a virtual environment

```bash
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

Create a `requirements.txt` file with the dependencies used by your project, for example:

```text
boto3
pytest
ruff
```

Then install them:

```bash
python -m pip install -r requirements.txt
```

### 4. Configure and verify AWS access

Use an AWS profile for local development:

```bash
aws configure --profile dev
aws sts get-caller-identity --profile dev
```

Run scripts with the profile:

```bash
python scripts/ec2/list_instances.py --profile dev --region us-east-1
```

The example command assumes you create a script with those arguments. Prefer IAM roles or temporary credentials in hosted environments; never hardcode access keys in source code.

## Reference Topics

| Topic | Important examples |
|---|---|
| **Boto3 basics** | Sessions, clients, resources, regions, and pagination |
| **Authentication** | IAM roles, AWS profiles, STS, and temporary credentials |
| **EC2 automation** | Instance inventory, start/stop operations, and tagging |
| **S3 automation** | Bucket inventory, lifecycle configuration, and object listing |
| **IAM security** | Role and policy inventory, and least-privilege checks |
| **Monitoring** | CloudWatch metrics, alarms, and logs |
| **Cost optimization** | Unattached EBS volumes, idle resources, and inventory reports |
| **Reliability** | Retries, Botocore exceptions, timeouts, and logging |
| **DevSecOps** | Secrets scanning, dependency checks, linting, and unit tests |
| **CI/CD** | GitHub Actions with OIDC and AWS role assumption |

### Suggested implementation order

1. Start with read-only inventory scripts.
2. Add EC2 and S3 operations with input validation.
3. Add IAM and CloudWatch reporting.
4. Add cost-optimization reports before any cleanup actions.
5. Add unit tests, linting, and CI checks.
6. Add write or destructive operations only with safeguards and explicit confirmation.

## Security Best Practices

- **Do not commit secrets:** Keep access keys, session tokens, private keys, and real `.env` files out of Git.
- **Use temporary credentials:** Prefer IAM roles and AWS STS. Use GitHub Actions OIDC instead of long-lived AWS keys in CI/CD.
- **Apply least privilege:** Grant only the actions and resources each script requires.
- **Default to read-only:** Make inventory and reporting scripts read-only where possible.
- **Protect destructive actions:** Require explicit confirmation for deletion, termination, or other high-impact changes.
- **Handle output carefully:** Redact account-sensitive details and never commit production logs or inventories.
- **Validate inputs:** Check regions, resource IDs, and requested actions before calling AWS APIs.
- **Use pagination:** Avoid silently missing resources when APIs return multiple pages.

## Development and Testing

Install the development tools:

```bash
python -m pip install boto3 pytest ruff
```

Run lint checks:

```bash
ruff check .
```

Run tests:

```bash
pytest -q
```

Use mocked AWS clients in unit tests so tests do not require real AWS resources or incur cloud charges.

## CI/CD

Use GitHub Actions to run linting and unit tests on pull requests and pushes. If a workflow needs access to AWS, configure GitHub OIDC with an AWS IAM role and restrict the trust policy to the intended repository and branch or environment.

Do not store AWS access keys in repository files. Use GitHub repository or environment configuration only for non-secret settings; use OIDC for short-lived AWS credentials.

## Contributing

1. Create a branch for your change.
2. Keep scripts focused and documented.
3. Include tests for new logic where practical.
4. Run `ruff check .` and `pytest -q`.
5. Open a pull request describing the change and required IAM permissions.

## Disclaimer

This repository is a technical reference and starting point. Review each script's permissions and behavior before use, test in a non-production environment, and obtain appropriate approval before running changes against production resources.

