import sys
import os
import json
from unittest.mock import MagicMock, patch

# Ensure backend is on sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from fastapi.testclient import TestClient
from app.main import app
from app.user_store import (
    save_user_credentials,
    create_session,
    get_user_by_session,
    delete_user,
    delete_session,
    save_oauth_state,
    validate_oauth_state
)
from app.security_analyzer import analyze_email

client = TestClient(app)

print("\n" + "="*60)
print("  ZEROGUARD COMPREHENSIVE END-TO-END VERIFICATION SUITE")
print("="*60)

# ============================================================
# TEST 1: MULTI-USER TOKEN & SESSION ISOLATION
# ============================================================
print("\n[TEST 1] Verifying Multi-User Storage & Isolation...")

user1_email = "alice@example.com"
user2_email = "bob@example.com"

# Setup credentials for two different users
user1_creds = {
    "token": "access_token_alice_123",
    "refresh_token": "refresh_token_alice_456",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_id": "client_id_123",
    "client_secret": "secret_123",
    "scopes": ["https://www.googleapis.com/auth/gmail.modify"],
    "expiry": "2099-01-01T00:00:00"
}

user2_creds = {
    "token": "access_token_bob_789",
    "refresh_token": "refresh_token_bob_012",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_id": "client_id_123",
    "client_secret": "secret_123",
    "scopes": ["https://www.googleapis.com/auth/gmail.modify"],
    "expiry": "2099-01-01T00:00:00"
}

save_user_credentials(user1_email, user1_creds)
save_user_credentials(user2_email, user2_creds)

session1 = create_session(user1_email)
session2 = create_session(user2_email)

assert session1 != session2, "Sessions must be unique!"

# Verify session lookup returns correct isolated credentials
lookup1 = get_user_by_session(session1)
lookup2 = get_user_by_session(session2)

assert lookup1["email"] == user1_email
assert lookup1["credentials"]["token"] == "access_token_alice_123"
assert lookup1["credentials"]["refresh_token"] == "refresh_token_alice_456"

assert lookup2["email"] == user2_email
assert lookup2["credentials"]["token"] == "access_token_bob_789"
assert lookup2["credentials"]["refresh_token"] == "refresh_token_bob_012"

print("  [PASS] User A and User B credentials strictly isolated")

# Test auth status endpoint for both sessions
res1 = client.get("/auth/status", headers={"Authorization": f"Bearer {session1}"})
assert res1.status_code == 200
assert res1.json()["connected"] is True
assert res1.json()["email"] == user1_email

res2 = client.get("/auth/status", headers={"Authorization": f"Bearer {session2}"})
assert res2.status_code == 200
assert res2.json()["connected"] is True
assert res2.json()["email"] == user2_email

print("  [PASS] /auth/status reports correct user for each session")

# Test disconnect for session 1
client.post("/auth/disconnect", headers={"Authorization": f"Bearer {session1}"})
res1_disconnected = client.get("/auth/status", headers={"Authorization": f"Bearer {session1}"})
assert res1_disconnected.json()["connected"] is False, "Session 1 should be disconnected"

# Session 2 must remain connected!
res2_still_connected = client.get("/auth/status", headers={"Authorization": f"Bearer {session2}"})
assert res2_still_connected.json()["connected"] is True, "Session 2 must remain unaffected"
print("  [PASS] Disconnecting User A does not affect User B")

# Cleanup
delete_user(user1_email)
delete_user(user2_email)


# ============================================================
# TEST 2: GOOGLE OAUTH URL & CALLBACK FLOW
# ============================================================
print("\n[TEST 2] Verifying OAuth URL Generation & State Security...")

res_url = client.get("/auth/google/url")
assert res_url.status_code == 200
data_url = res_url.json()
assert "auth_url" in data_url
assert "accounts.google.com" in data_url["auth_url"]
assert "prompt=consent" in data_url["auth_url"]
assert "access_type=offline" in data_url["auth_url"]
print("  [PASS] OAuth URL generated with offline consent")

# Test duplicate callback handling
from app.user_store import save_oauth_state
from app.gmail_auth import handle_oauth_callback

dup_state = "test_dup_state_123"
save_oauth_state(dup_state, "http://localhost:8000/auth/google/callback", "http://localhost:5173")

with patch("app.gmail_auth.create_oauth_flow") as mock_flow, \
     patch("app.gmail_auth.build") as mock_build:

    mock_flow_inst = MagicMock()
    mock_flow.return_value = mock_flow_inst
    mock_creds = MagicMock()
    mock_creds.token = "tok_abc"
    mock_creds.refresh_token = "ref_abc"
    mock_creds.token_uri = "https://oauth2.googleapis.com/token"
    mock_creds.client_id = "cid"
    mock_creds.client_secret = "csec"
    mock_creds.scopes = ["https://www.googleapis.com/auth/gmail.modify"]
    mock_creds.expiry = None
    mock_flow_inst.credentials = mock_creds

    mock_svc = MagicMock()
    mock_build.return_value = mock_svc
    mock_svc.users().getProfile().execute.return_value = {"emailAddress": "testdup@gmail.com"}

    # First callback execution
    s_tok_1, email_1, f_url_1 = handle_oauth_callback("code_123", dup_state)
    assert email_1 == "testdup@gmail.com"
    assert s_tok_1 is not None

    # SECOND callback execution with the SAME state (duplicate request simulation)
    s_tok_2, email_2, f_url_2 = handle_oauth_callback("code_123", dup_state)
    assert s_tok_2 == s_tok_1, "Duplicate callback must return the same session token"
    assert email_2 == "testdup@gmail.com"
    print("  [PASS] Duplicate callback safely absorbed without state invalidation or grant error")

delete_user("testdup@gmail.com")



# ============================================================
# TEST 3: EMAIL SECURITY DETECTION ACCURACY
# ============================================================
print("\n[TEST 3] Verifying Security Detection Accuracy...")

# 3a. Legitimate Netflix email (Previously false-positive)
netflix_email = analyze_email(
    sender="Netflix <info@mailer.netflix.com>",
    subject="Your membership update",
    body="Thank you for being a Netflix member. Here is your monthly statement.",
    links=["https://www.netflix.com/account"]
)
assert netflix_email["risk_level"] == "LOW", f"Netflix should be LOW, got {netflix_email['risk_level']}"
assert netflix_email["risk_score"] < 20
print(f"  [PASS] Legitimate Netflix email: Score {netflix_email['risk_score']} ({netflix_email['risk_level']}) - No false positive")

# 3b. Deceptive Spoofed Link (Display Text != Href destination)
spoofed_email = analyze_email(
    sender="Support <support@random-service.com>",
    subject="Account review",
    body="Please review your account at the link below.",
    links=["http://credential-stealer.xyz/login"],
    link_details=[{
        "url": "http://credential-stealer.xyz/login",
        "anchor_text": "https://paypal.com/signin"
    }]
)
assert spoofed_email["risk_score"] >= 40
assert any("Deceptive spoofed link" in r for r in spoofed_email["reasons"])
print(f"  [PASS] Deceptive spoofed link detected: Score {spoofed_email['risk_score']} ({spoofed_email['risk_level']})")

# 3c. Punycode Lookalike Phishing
punycode_email = analyze_email(
    sender="Google Security <security@xn--gogle-qqa.com>",
    subject="Critical Security Alert",
    body="Your account was accessed from an unknown device. Verify immediately.",
    links=["https://xn--gogle-qqa.com/verify"]
)
assert punycode_email["risk_score"] >= 40
assert any("Punycode" in r for r in punycode_email["reasons"])
print(f"  [PASS] Punycode lookalike detected: Score {punycode_email['risk_score']} ({punycode_email['risk_level']})")

# 3d. Credential harvesting with urgent suspension
urgent_phish = analyze_email(
    sender="Security Team <security@outlook-verify-account.com>",
    subject="URGENT: Your account will be suspended within 24 hours",
    body="Immediate action required. Please confirm your password and OTP using the link below.",
    links=["http://outlook-verify-account.com/login"]
)
assert urgent_phish["risk_level"] in ["HIGH", "CRITICAL"]
print(f"  [PASS] Phishing credential theft: Score {urgent_phish['risk_score']} ({urgent_phish['risk_level']})")


# ============================================================
# TEST 4: AUTHENTICATED ENDPOINT FLOW (MOCKED GMAIL SERVICE)
# ============================================================
print("\n[TEST 4] Verifying Authenticated Pipeline Flow...")

test_user = "charlie@gmail.com"
save_user_credentials(test_user, {
    "token": "valid_token",
    "refresh_token": "valid_refresh",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_id": "test_client",
    "client_secret": "test_secret",
    "scopes": ["https://www.googleapis.com/auth/gmail.modify"],
    "expiry": "2099-01-01T00:00:00"
})
charlie_session = create_session(test_user)

mock_email = {
    "id": "msg_001",
    "sender": "HR <hr@company.com>",
    "subject": "Benefits Update",
    "body": "Please review the updated policy for this quarter.",
    "links": ["https://company.com/benefits"],
    "link_details": [],
    "mailbox": "INBOX"
}

with patch("app.main.get_gmail_service_for_user") as mock_get_service, \
     patch("app.main.get_latest_emails") as mock_get_emails:

    mock_service_instance = MagicMock()
    mock_get_service.return_value = mock_service_instance
    mock_get_emails.return_value = [mock_email]

    res_emails = client.get(
        "/emails",
        headers={"Authorization": f"Bearer {charlie_session}"}
    )

    assert res_emails.status_code == 200
    res_data = res_emails.json()
    assert res_data["status"] == "success"
    assert res_data["count"] == 1
    analyzed = res_data["emails"][0]
    assert "security" in analyzed
    assert "risk_score" in analyzed["security"]
    assert "risk_level" in analyzed["security"]
    assert "intent" in analyzed["security"]
    print("  [PASS] /emails returned analyzed email with IntentShield & risk score for authenticated user")

# Cleanup
delete_user(test_user)

print("\n" + "="*60)
print("  ALL TESTS PASSED SUCCESSFULLY! ")
print("="*60 + "\n")
