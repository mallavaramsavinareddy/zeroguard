from fastapi.testclient import TestClient
from app.main import app
from app.security_analyzer import analyze_message

client = TestClient(app)

print("========================================")
print("RUNNING ZERO GUARD EDGE CASE TEST SUITE")
print("========================================")

# 1. Empty input
print("\n[Case 1] Empty input (message='' and url=''):")
resp1 = client.post("/analyze-message", json={"message": "   ", "url": "   "})
print("Status code:", resp1.status_code)
assert resp1.status_code == 400
assert resp1.json()["status"] == "error"
print("[PASS] Returned 400 Bad Request with error message")

# 2. Message without URL
print("\n[Case 2] Message without URL:")
resp2 = client.post("/analyze-message", json={
    "message": "Action required! Your bank account will be suspended within 24 hours. Send OTP immediately to prevent closure.",
    "url": ""
})
print("Status code:", resp2.status_code)
assert resp2.status_code == 200
data2 = resp2.json()
print("Risk score:", data2["risk_score"])
print("Severity:", data2["severity"])
print("Detected URLs:", data2["detected_urls"])
assert data2["detected_urls"] == []
assert data2["risk_score"] >= 40
print("[PASS] Analyzed message-only with heightened urgency and OTP risk")

# 3. URL without message
print("\n[Case 3] URL without message:")
resp3 = client.post("/analyze-message", json={
    "message": "",
    "url": "http://netflix-billing-update.top/login"
})
print("Status code:", resp3.status_code)
assert resp3.status_code == 200
data3 = resp3.json()
print("Risk score:", data3["risk_score"])
print("Severity:", data3["severity"])
print("Detected URLs:", data3["detected_urls"])
assert len(data3["detected_urls"]) == 1
assert data3["risk_score"] >= 40
print("[PASS] Analyzed standalone suspicious URL")

# 4. Message containing multiple URLs
print("\n[Case 4] Message containing multiple URLs:")
resp4 = client.post("/analyze-message", json={
    "message": "Update your credentials here: https://bit.ly/update-acc or backup link: http://192.168.0.1/verify",
    "url": "https://secure-apple-update.xyz"
})
print("Status code:", resp4.status_code)
assert resp4.status_code == 200
data4 = resp4.json()
print("Risk score:", data4["risk_score"])
print("Severity:", data4["severity"])
print("Detected URLs count:", len(data4["detected_urls"]))
print("Detected URLs:", data4["detected_urls"])
assert len(data4["detected_urls"]) == 3
assert data4["risk_score"] >= 70
print("[PASS] Extracted and aggregated multiple URLs from text and URL input")

# 5. Safe input
print("\n[Case 5] Clean / Safe input:")
resp5 = client.post("/analyze-message", json={
    "message": "Hi team, please find attached the notes from our weekly sync. Have a great weekend!",
    "url": ""
})
print("Status code:", resp5.status_code)
assert resp5.status_code == 200
data5 = resp5.json()
print("Risk score:", data5["risk_score"])
print("Severity:", data5["severity"])
print("Recommendation:", data5["recommendation"])
assert data5["severity"] in ("SAFE", "LOW")
print("[PASS] Clean message classified as SAFE/LOW")

# 6. AI/API Failure simulation
print("\n[Case 6] AI Failure simulation (falls back cleanly to rule-based):")
import app.ai_analyzer as ai_mod
original_client = ai_mod.client
try:
    ai_mod.client = None  # Simulate AI failure
    fallback_res = analyze_message(
        message="Urgent: verify your account password immediately http://fake-login.xyz",
        url=""
    )
    print("Fallback Score:", fallback_res["risk_score"])
    print("Fallback Severity:", fallback_res["severity"])
    print("AI Available flag:", fallback_res["ai_analysis"]["available"])
    assert fallback_res["ai_analysis"]["available"] is False
    assert fallback_res["risk_score"] >= 40
    print("[PASS] Handled AI failure gracefully with rule-based fallback")
finally:
    ai_mod.client = original_client

print("\n========================================")
print("ALL EDGE CASES VERIFIED AND PASSING!")
print("========================================")
