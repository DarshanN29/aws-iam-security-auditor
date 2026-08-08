from checks.mfa_check import check_users_without_mfa
from checks.access_keys import check_access_keys
from checks.password_policy import check_password_policy
from checks.policies import check_wildcard_permissions
from checks.inactive_users import check_inactive_users
from reports.json_report import generate_json_report


def main():
    print("AWS IAM Security Auditor")
    print("=" * 30)
    print()

    # Store findings from every security check
    all_findings = []

    # MFA Check
    print("Running MFA security check...")

    findings = check_users_without_mfa()
    all_findings.extend(findings)

    print()

    if not findings:
        print("No MFA issues found.")
    else:
        print(f"Found {len(findings)} MFA issue(s):")
        print()

        for finding in findings:
            print(f"Severity       : {finding['severity']}")
            print(f"Check          : {finding['check']}")
            print(f"User           : {finding['user']}")
            print(f"Finding        : {finding['finding']}")
            print(f"Recommendation : {finding['recommendation']}")
            print("-" * 50)

    # Access Key Check
    print("\nRunning access key security check...")

    access_key_findings = check_access_keys()
    all_findings.extend(access_key_findings)

    if access_key_findings:
        print(f"\nFound {len(access_key_findings)} access key issue(s):")

        for finding in access_key_findings:
            print(f"\nSeverity       : {finding['severity']}")
            print(f"Check          : {finding['check']}")
            print(f"User           : {finding['user']}")
            print(f"Finding        : {finding['finding']}")
            print(f"Recommendation : {finding['recommendation']}")
            print(f"Access Key     : {finding['access_key_id']}")
            print(f"Key Age        : {finding['age_days']} days")
            print("-" * 50)
    else:
        print("\nNo access key issues found.")

    # Password Policy Check
    print("\nRunning password policy security check...")

    password_policy_findings = check_password_policy()
    all_findings.extend(password_policy_findings)

    if password_policy_findings:
        print(
            f"\nFound {len(password_policy_findings)} "
            "password policy issue(s):"
        )

        for finding in password_policy_findings:
            print(f"\nSeverity       : {finding['severity']}")
            print(f"Check          : {finding['check']}")
            print(f"Scope          : {finding['scope']}")
            print(f"Finding        : {finding['finding']}")
            print(f"Recommendation : {finding['recommendation']}")
            print("-" * 50)
    else:
        print("\nNo password policy issues found.")

    # Wildcard Permissions Check
    print("\nRunning wildcard permission security check...")

    policy_findings = check_wildcard_permissions()
    all_findings.extend(policy_findings)

    if policy_findings:
        print(
            f"\nFound {len(policy_findings)} "
            "wildcard permission issue(s):"
        )

        for finding in policy_findings:
            print(f"\nSeverity       : {finding['severity']}")
            print(f"Check          : {finding['check']}")
            print(f"User           : {finding['user']}")
            print(f"Policy         : {finding['policy']}")
            print(f"Finding        : {finding['finding']}")
            print(f"Recommendation : {finding['recommendation']}")
            print("-" * 50)
    else:
        print("\nNo wildcard permission issues found.")

    # Inactive User Check
    print("\nRunning inactive user security check...")

    inactive_findings = check_inactive_users()
    all_findings.extend(inactive_findings)

    if inactive_findings:
        print(
            f"\nFound {len(inactive_findings)} "
            "inactive user issue(s):"
        )

        for finding in inactive_findings:
            print(f"\nSeverity       : {finding['severity']}")
            print(f"Check          : {finding['check']}")
            print(f"User           : {finding['user']}")
            print(f"Finding        : {finding['finding']}")
            print(f"Recommendation : {finding['recommendation']}")

            if "last_activity" in finding:
                print(f"Last Activity  : {finding['last_activity']}")
                print(f"Inactive Days  : {finding['age_days']}")

            print("-" * 50)

    else:
        print("\nNo inactive user issues found.")

    # Generate JSON Report
    print("\nGenerating JSON security report...")

    report_file = generate_json_report(all_findings)

    print(f"JSON report generated: {report_file}")
    print(f"Total findings: {len(all_findings)}")


if __name__ == "__main__":
    main()