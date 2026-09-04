from app.ai_analyzer import analyze_with_ai


result = analyze_with_ai(
    sender="Microsoft Security <security@gmail.com>",

    subject="URGENT: Your account will be suspended",

    body="""
    Your Microsoft account has detected unusual activity.

    Your account will be suspended unless you verify your account
    immediately.

    Please confirm your password and verification code using the
    verification link below.

    https://example.com/verify-account

    Security Support Team
    """,

    links=[
        "https://example.com/verify-account"
    ]
)


print("\n")
print("========================================")
print("       ZERO GUARD - AI ANALYSIS")
print("========================================")

print("Risk Score:", result["risk_score"])
print("Risk Level:", result["risk_level"])

print("\nReason:")
print(result["reason"])

print("\n----------------------------------------")
print("           INTENT SHIELD")
print("----------------------------------------")

print("Attacker Intent:")
print(result["attacker_intent"])

print("\nExpected User Action:")
print(result["expected_user_action"])

print("\nPotential Consequence:")
print(result["potential_consequence"])

print("\nRecommended Defense:")
print(result["recommended_defense"])

print("\nAI Available:")
print(result["ai_available"])

print("========================================")