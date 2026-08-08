from checks.mfa_check import check_users_without_mfa
from checks.access_keys import check_access_keys


def main():
    print("AWS IAM Security Auditor")
    print("=" * 30)
    print()

    print("Running MFA security check...")
    
    findings = check_users_without_mfa()

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

    print("\nRunning access key security check...")
    access_key_findings = check_access_keys()

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


if __name__ == "__main__":
    main()