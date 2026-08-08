import json
from datetime import datetime, timezone
from pathlib import Path

import boto3


def generate_json_report(findings):
    """
    Generate a JSON report containing all IAM security findings.
    """

    sts = boto3.client("sts")
    identity = sts.get_caller_identity()

    report = {
        "report_name": "AWS IAM Security Audit Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "aws_account": identity["Account"],
        "total_findings": len(findings),
        "findings": findings,
    }

    output_directory = Path("reports")
    output_directory.mkdir(exist_ok=True)

    output_file = output_directory / "iam_audit_report.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            default=str
        )

    return output_file