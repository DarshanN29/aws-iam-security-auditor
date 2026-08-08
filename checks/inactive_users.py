import boto3
from datetime import datetime, timezone


INACTIVE_DAYS = 90


def check_inactive_users():
    iam = boto3.client("iam")
    findings = []

    response = iam.list_users()

    for user in response["Users"]:
        username = user["UserName"]

        # ---------------------------------------------------------
        # 1. Check console password activity
        # ---------------------------------------------------------
        password_last_used = user.get("PasswordLastUsed")

        # ---------------------------------------------------------
        # 2. Check access-key activity
        # ---------------------------------------------------------
        keys_response = iam.list_access_keys(
            UserName=username
        )

        key_activity = []

        for key in keys_response["AccessKeyMetadata"]:
            key_id = key["AccessKeyId"]

            try:
                last_used_response = iam.get_access_key_last_used(
                    AccessKeyId=key_id
                )

                last_used = last_used_response.get(
                    "AccessKeyLastUsed", {}
                )

                last_used_date = last_used.get("LastUsedDate")

                if last_used_date:
                    key_activity.append(last_used_date)

            except Exception:
                continue

        # ---------------------------------------------------------
        # 3. Determine the most recent recorded activity
        # ---------------------------------------------------------
        activity_dates = []

        if password_last_used:
            activity_dates.append(password_last_used)

        activity_dates.extend(key_activity)

        # ---------------------------------------------------------
        # 4. Handle users with NO recorded activity
        #
        # No activity does NOT automatically mean inactive.
        # A newly created user may simply not have been used yet.
        # Therefore, use the account creation date.
        # ---------------------------------------------------------
        if not activity_dates:
            create_date = user["CreateDate"]

            user_age_days = (
                datetime.now(timezone.utc) - create_date
            ).days

            if user_age_days >= INACTIVE_DAYS:
                findings.append({
                    "severity": "HIGH",
                    "check": "Inactive Users",
                    "user": username,
                    "finding": (
                        f"User has no recorded authentication activity "
                        f"and was created {user_age_days} days ago"
                    ),
                    "recommendation": (
                        "Review the user and disable or remove it "
                        "if no longer required"
                    ),
                    "age_days": user_age_days,
                })

            continue

        # ---------------------------------------------------------
        # 5. Calculate age of the most recent activity
        # ---------------------------------------------------------
        last_activity = max(activity_dates)

        age_days = (
            datetime.now(timezone.utc) - last_activity
        ).days

        # ---------------------------------------------------------
        # 6. Flag users inactive for 90+ days
        # ---------------------------------------------------------
        if age_days >= INACTIVE_DAYS:
            findings.append({
                "severity": "HIGH",
                "check": "Inactive Users",
                "user": username,
                "finding": (
                    f"User has not been active for {age_days} days"
                ),
                "recommendation": (
                    "Review the user and disable or remove it "
                    "if no longer required"
                ),
                "last_activity": last_activity.isoformat(),
                "age_days": age_days,
            })

    return findings