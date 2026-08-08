import boto3
from datetime import datetime, timezone


MAX_KEY_AGE_DAYS = 90


def check_access_keys():
    iam = boto3.client("iam")
    findings = []

    response = iam.list_users()

    for user in response["Users"]:
        username = user["UserName"]

        keys_response = iam.list_access_keys(
            UserName=username
        )

        for key in keys_response["AccessKeyMetadata"]:
            access_key_id = key["AccessKeyId"]
            status = key["Status"]
            create_date = key["CreateDate"]

            age_days = (
                datetime.now(timezone.utc) - create_date
            ).days

            if status == "Active" and age_days > MAX_KEY_AGE_DAYS:
                findings.append({
                    "severity": "HIGH",
                    "check": "Access Key Age",
                    "user": username,
                    "finding": (
                        f"Active access key is {age_days} days old"
                    ),
                    "recommendation": (
                        "Rotate or replace the access key"
                    ),
                    "access_key_id": access_key_id,
                    "age_days": age_days
                })

    return findings