from checks.mfa_check import check_users_without_mfa


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


if __name__ == "__main__":
    main()