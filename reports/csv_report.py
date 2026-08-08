import csv
from pathlib import Path


def generate_csv_report(findings):
    """
    Generate a CSV report containing all IAM security findings.
    """

    output_directory = Path("reports")
    output_directory.mkdir(exist_ok=True)

    output_file = output_directory / "iam_audit_report.csv"

    fieldnames = [
        "severity",
        "check",
        "user",
        "scope",
        "policy",
        "finding",
        "recommendation",
        "access_key_id",
        "age_days",
        "last_activity",
    ]

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore"
        )

        writer.writeheader()

        for finding in findings:
            writer.writerow(finding)

    return output_file
