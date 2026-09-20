from app.security_analyzer import analyze_message

print("--- Test 1: Clean/empty message ---")
res1 = analyze_message("Hello", "")
print("Score:", res1["risk_score"], "Severity:", res1["severity"])

print("\n--- Test 2: WhatsApp OTP harvesting scam ---")
res2 = analyze_message(
    "Hi, I accidentally sent my 6-digit WhatsApp code to your phone number. Please send it back immediately, urgent!",
    ""
)
print("Score:", res2["risk_score"], "Severity:", res2["severity"])
print("Reasons:", res2["reasons"])
print("Recommendation:", res2["recommendation"])

print("\n--- Test 3: Lookalike URL + Credential Theft ---")
res3 = analyze_message(
    "Your PayPal account is locked due to unauthorized activity. Verify your account and password within 24 hours: http://paypa1-security-check.xyz/login",
    ""
)
print("Score:", res3["risk_score"], "Severity:", res3["severity"])
print("Detected URLs:", res3["detected_urls"])
print("Reasons:", res3["reasons"])
print("Recommendation:", res3["recommendation"])

print("\n--- Test 4: Standalone suspicious URL ---")
res4 = analyze_message(
    "",
    "http://192.168.1.55/admin/login.php"
)
print("Score:", res4["risk_score"], "Severity:", res4["severity"])
print("Reasons:", res4["reasons"])

print("\n--- Test 5: Safe message ---")
res5 = analyze_message(
    "Hey! Are we still meeting for lunch today at 1 PM?",
    ""
)
print("Score:", res5["risk_score"], "Severity:", res5["severity"])
print("Reasons:", res5["reasons"])
