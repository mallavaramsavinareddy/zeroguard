from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

# Test 1: Empty input returns 400 Bad Request
r1 = client.post("/analyze-message", json={"message": "", "url": ""})
print("Empty input status:", r1.status_code)
print("Empty input response:", r1.json())
assert r1.status_code == 400

# Test 2: Message only
r2 = client.post("/analyze-message", json={
    "message": "Urgent! Your account is suspended. Send your OTP immediately.",
    "url": ""
})
print("\nMessage only status:", r2.status_code)
print("Risk Score:", r2.json()["risk_score"])
print("Severity:", r2.json()["severity"])
print("Reasons count:", len(r2.json()["reasons"]))
assert r2.status_code == 200
assert "risk_score" in r2.json()
assert "severity" in r2.json()
assert "reasons" in r2.json()
assert "detected_urls" in r2.json()
assert "recommendation" in r2.json()

# Test 3: Standalone URL
r3 = client.post("/analyze-message", json={
    "message": "",
    "url": "http://google-secure-login.top/account"
})
print("\nURL only status:", r3.status_code)
print("Risk Score:", r3.json()["risk_score"])
print("Severity:", r3.json()["severity"])
print("Detected URLs:", r3.json()["detected_urls"])
assert r3.status_code == 200

# Test 4: Existing Gmail endpoints still work
r4 = client.get("/")
print("\nRoot status:", r4.status_code)
assert r4.status_code == 200

r5 = client.get("/auth/status")
print("Auth status endpoint:", r5.status_code)
assert r5.status_code == 200

print("\nALL API ENDPOINT TESTS PASSED SUCCESSFULLY!")
