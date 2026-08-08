import boto3
import json
from urllib.parse import unquote


def check_wildcard_permissions():
    iam = boto3.client("iam")
    findings = []

    response = iam.list_users()

    for user in response["Users"]:
        username = user["UserName"]

        policies_response = iam.list_attached_user_policies(
            UserName=username
        )

        for policy in policies_response["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]

            policy_response = iam.get_policy(
                PolicyArn=policy_arn
            )

            default_version_id = policy_response["Policy"]["DefaultVersionId"]

            version_response = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )

            policy_document = version_response["PolicyVersion"]["Document"]

            if isinstance(policy_document, str):
                policy_document = json.loads(unquote(policy_document))

            statements = policy_document.get("Statement", [])

            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:

                if statement.get("Effect") != "Allow":
                    continue

                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])

                if isinstance(actions, str):
                    actions = [actions]

                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions and "*" in resources:
                    findings.append({
                        "severity": "CRITICAL",
                        "check": "Wildcard Permissions",
                        "user": username,
                        "policy": policy["PolicyName"],
                        "finding": "Policy allows all actions on all resources",
                        "recommendation": "Apply least-privilege permissions"
                    })

    return findings
