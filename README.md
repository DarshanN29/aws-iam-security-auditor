# AWS IAM Security Auditor

A Python-based security auditing tool that analyzes AWS IAM configuration using Boto3 and identifies common Identity and Access Management (IAM) security issues.

The project performs read-only security checks and generates structured JSON and CSV audit reports.

---

## Features

The auditor performs the following security checks:

### 1. MFA Check

- Identifies IAM users without MFA enabled.
- Reports missing MFA as a HIGH-severity finding.

### 2. Access Key Check

- Reviews IAM access keys.
- Checks access-key age and security status.
- Helps identify potentially risky or outdated access keys.

### 3. Password Policy Check

- Checks whether an account-level IAM password policy exists.
- Validates minimum password length.
- Checks uppercase, lowercase, number, and symbol requirements.
- Checks password expiration.
- Checks password reuse prevention.

### 4. Wildcard Permission Check

- Examines policies attached directly to IAM users.
- Detects policies allowing:

```text
Action: "*"
Resource: "*"
```

- Reports unrestricted permissions as CRITICAL because they violate the principle of least privilege.

### 5. Inactive User Check

- Reviews IAM user authentication activity.
- Checks console password activity.
- Checks access-key usage.
- Identifies users with prolonged inactivity or no recorded authentication activity.

---

## Report Generation

The auditor collects findings from all security checks and generates two structured reports:

- `reports/iam_audit_report.json`
- `reports/iam_audit_report.csv`

Each finding can contain:

- Severity
- Security check
- User or account scope
- Finding description
- Recommendation
- Policy information
- Access-key information
- Activity information

---

## Architecture

```text
                         AWS Account
                              |
                              v
                            Boto3
                              |
                              v
                 +-------------------------+
                 | AWS IAM Security        |
                 | Auditor                 |
                 +-----------+-------------+
                             |
          +------------------+------------------+
          |          |          |        |       |
          v          v          v        v       v
         MFA    Access Keys  Password  Wildcard  Inactive
                              Policy   Permissions Users
          |          |          |        |       |
          +----------+----------+--------+-------+
                             |
                             v
                    Findings Collection
                             |
                      +------+------+
                      |             |
                      v             v
                    JSON           CSV
                   Report         Report
```

---

## Project Structure

```text
aws-iam-security-auditor/
│
├── checks/
│   ├── __init__.py
│   ├── mfa_check.py
│   ├── access_keys.py
│   ├── password_policy.py
│   ├── policies.py
│   └── inactive_users.py
│
├── config/
│   ├── __init__.py
│   └── settings.py
│
├── reports/
│   ├── __init__.py
│   ├── json_report.py
│   └── csv_report.py
│
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Requirements

- Python 3.x
- AWS account
- AWS CLI
- AWS IAM permissions required by the implemented checks
- Boto3

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/DarshanN29/aws-iam-security-auditor.git
cd aws-iam-security-auditor
```

### 2. Create a virtual environment

#### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

#### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## AWS Configuration

Configure AWS credentials using the AWS CLI:

```bash
aws configure
```

Verify the AWS identity:

```bash
aws sts get-caller-identity
```

The auditor uses the configured AWS credentials through Boto3.

The AWS identity used to run the auditor must have sufficient read permissions for the IAM operations required by the implemented checks.

The auditor itself does not modify:

- IAM users
- IAM policies
- MFA devices
- Access keys
- Password policies

The tool is designed as a read-only security auditing application.

---

## Usage

Run the auditor from the project root:

```bash
python main.py
```

The tool executes each security check sequentially and displays the results in the terminal.

After the checks complete, JSON and CSV reports are generated automatically.

Example:

```text
AWS IAM Security Auditor
==============================

Running MFA security check...

Found 2 MFA issue(s):

Severity       : HIGH
Check          : MFA
User           : admin-darshan
Finding        : User does not have MFA enabled
Recommendation : Enable MFA for this IAM user
--------------------------------------------------

Running access key security check...

No access key issues found.

Running password policy security check...

Found 1 password policy issue(s):

Severity       : MEDIUM
Check          : Password Policy
Scope          : ACCOUNT
Finding        : No IAM password policy is configured
Recommendation : Configure a strong IAM password policy
--------------------------------------------------

Running wildcard permission security check...

No wildcard permission issues found.

Running inactive user security check...

No inactive user issues found.

Generating JSON security report...
JSON report generated: reports\iam_audit_report.json

Generating CSV security report...
CSV report generated: reports\iam_audit_report.csv

Total findings: 3
```

---

## Example Audit Result

During testing, the auditor identified the following issues:

| Severity | Check | Finding |
|---|---|---|
| HIGH | MFA | `admin-darshan` does not have MFA enabled |
| HIGH | MFA | `iam-auditor` does not have MFA enabled |
| MEDIUM | Password Policy | No IAM password policy is configured |

The access-key, wildcard-permission, and inactive-user checks reported no issues in the final test environment.

---

## Security Principles

### Least Privilege

The auditor is intended to operate with read-only IAM permissions rather than administrative permissions.

### Defense in Depth

Multiple independent IAM security checks are performed instead of relying on a single security control.

### Security Automation

Manual IAM configuration reviews are automated using Python and the AWS SDK.

### Centralized Findings

Results from all security checks are aggregated into a common findings collection before report generation.

### Structured Reporting

Audit results are exported in JSON and CSV formats for easier review and further processing.

---

## Security Considerations

AWS credentials must never be hard-coded into the source code.

Do not commit AWS access keys, secret keys, passwords, or other credentials to GitHub.

Use the AWS CLI credential configuration, environment variables, IAM roles, or another appropriate AWS credential provider.

Generated audit reports may contain AWS account and IAM information. Production audit reports should therefore not be committed to a public repository.

---

## Limitations

This project currently focuses on common IAM security checks.

It does not currently provide:

- Automatic remediation
- Root-account security auditing
- IAM group analysis
- Complete IAM policy privilege analysis
- AWS Organizations/SCP analysis
- Continuous monitoring
- CloudTrail-based historical activity analysis
- Multi-account auditing
- Web-based dashboard

These could be added as future improvements.

---

## Technologies Used

- Python
- Boto3
- AWS IAM
- AWS CLI
- JSON
- CSV
- Git
- GitHub

---

## Project Objective

The objective of this project is to demonstrate how Python and AWS SDKs can be used to automate basic IAM security auditing.

The project provides practical experience with:

- AWS IAM
- Cloud security
- Identity and Access Management
- Least privilege
- MFA security
- Access-key security
- IAM policy analysis
- Security automation
- Audit reporting

---

## Future Improvements

Possible future improvements include:

- IAM group analysis
- More detailed IAM policy privilege analysis
- Configurable severity levels
- Command-line arguments
- Multi-account auditing
- CloudTrail integration
- Continuous monitoring
- Web-based security dashboard

---

## Author

**Darshan N**

Cybersecurity-focused engineering student interested in:

- Cloud Security
- IAM Security
- SOC
- SIEM
- Vulnerability Management
- Security Automation