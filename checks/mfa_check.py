import boto3


def check_users_without_mfa():
    iam = boto3.client("iam")

    findings = []

    response = iam.list_users()

    for user in response["Users"]:
        username = user["UserName"]

        mfa_response = iam.list_mfa_devices(
            UserName=username
        )

        if not mfa_response["MFADevices"]:
            finding = {
                "severity": "HIGH",
                "check": "MFA",
                "user": username,
                "finding": "User does not have MFA enabled",
                "recommendation": "Enable MFA for this IAM user"
            }

            findings.append(finding)

    return findings