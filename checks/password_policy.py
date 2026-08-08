import boto3

from config.settings import (
    MIN_PASSWORD_LENGTH,
    REQUIRE_UPPERCASE,
    REQUIRE_LOWERCASE,
    REQUIRE_NUMBERS,
    REQUIRE_SYMBOLS,
    MAX_PASSWORD_AGE_DAYS,
    PASSWORD_REUSE_PREVENTION,
)


def check_password_policy():
    iam = boto3.client("iam")
    findings = []

    try:
        response = iam.get_account_password_policy()
        policy = response["PasswordPolicy"]

    except iam.exceptions.NoSuchEntityException:
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": "No IAM password policy is configured",
            "recommendation": "Configure a strong IAM password policy",
        })

        return findings

    if policy.get("MinimumPasswordLength", 0) < MIN_PASSWORD_LENGTH:
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": (
                f"Minimum password length is "
                f"{policy.get('MinimumPasswordLength', 0)}"
            ),
            "recommendation": (
                f"Configure minimum password length to at least "
                f"{MIN_PASSWORD_LENGTH}"
            ),
        })

    if REQUIRE_UPPERCASE and not policy.get("RequireUppercaseCharacters", False):
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": "Uppercase characters are not required",
            "recommendation": "Require uppercase characters in passwords",
        })

    if REQUIRE_LOWERCASE and not policy.get("RequireLowercaseCharacters", False):
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": "Lowercase characters are not required",
            "recommendation": "Require lowercase characters in passwords",
        })

    if REQUIRE_NUMBERS and not policy.get("RequireNumbers", False):
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": "Numbers are not required",
            "recommendation": "Require numbers in passwords",
        })

    if REQUIRE_SYMBOLS and not policy.get("RequireSymbols", False):
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": "Symbols are not required",
            "recommendation": "Require symbols in passwords",
        })

    if policy.get("MaxPasswordAge", 0) == 0:
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": "Password expiration is disabled",
            "recommendation": (
                f"Configure password expiration within "
                f"{MAX_PASSWORD_AGE_DAYS} days"
            ),
        })

    elif policy["MaxPasswordAge"] > MAX_PASSWORD_AGE_DAYS:
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": (
                f"Maximum password age is "
                f"{policy['MaxPasswordAge']} days"
            ),
            "recommendation": (
                f"Configure maximum password age to "
                f"{MAX_PASSWORD_AGE_DAYS} days or less"
            ),
        })

    if (
        policy.get("PasswordReusePrevention", 0)
        < PASSWORD_REUSE_PREVENTION
    ):
        findings.append({
            "severity": "MEDIUM",
            "check": "Password Policy",
            "user": "ACCOUNT",
            "finding": (
                f"Password reuse prevention is set to "
                f"{policy.get('PasswordReusePrevention', 0)}"
            ),
            "recommendation": (
                f"Prevent reuse of at least "
                f"{PASSWORD_REUSE_PREVENTION} previous passwords"
            ),
        })

    return findings
