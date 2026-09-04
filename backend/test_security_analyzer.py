from app.security_analyzer import analyze_email


result = analyze_email(
    sender="Microsoft Security <security@gmail.com>",
    subject="URGENT: Your account will be suspended",
    body="""
    Immediate action required!

    Your Microsoft account has detected unusual activity.
    Your account will be suspended unless you verify your account immediately.

    Please confirm your password and verification code using the link below:

    http://example.com/verify-account

    Security Support Team
    """,
    links=["http://example.com/verify-account"]
)

print("\nZERO GUARD COMBINED ANALYSIS")
print("============================")
print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])

print("\nReasons:")
for reason in result["reasons"]:
    print("-", reason)