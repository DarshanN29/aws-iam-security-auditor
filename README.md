# AWS IAM Security Auditor

A Python-based AWS IAM security auditing tool that identifies common IAM security misconfigurations using the AWS SDK for Python (`boto3`).

## Features

- Detect IAM users without MFA
- Detect wildcard permissions
- Check IAM password policy
- Find inactive IAM users
- Detect old access keys
- Generate JSON reports
- Generate CSV reports

## Technologies

- Python 3.13
- AWS IAM
- boto3
- Git
- GitHub

## Project Structure

```
config/
checks/
reports/
docs/
screenshots/
sample_output/
```