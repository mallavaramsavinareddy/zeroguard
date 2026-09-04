from app.security_analyzer import analyze_email


# TEST 1: Safe email
safe_email = analyze_email(
    "friend@gmail.com",
    "Meeting tomorrow",
    "Hi, let's meet tomorrow at 10 AM. See you!",
    []
)

print("\n========== SAFE EMAIL ==========")
print(safe_email)


# TEST 2: Phishing email
phishing_email = analyze_email(
    "security@paypa1-support.com",
    "URGENT: Verify your account",
    """
    Your account will be suspended.
    Verify your account immediately.
    Please click the link and enter your password and OTP.
    """,
    ["http://paypa1-support.com/login"]
)

print("\n========== PHISHING EMAIL ==========")
print(phishing_email)


# TEST 3: Suspicious URL
suspicious_email = analyze_email(
    "admin@gmail.com",
    "Account verification required",
    """
    Your account requires verification.
    Click here immediately.
    """,
    ["http://192.168.1.50/login"]
)

print("\n========== SUSPICIOUS URL EMAIL ==========")
print(suspicious_email)