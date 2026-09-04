import os

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")


def get_gmail_service():
    creds = None

    # Load existing OAuth token
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(
            TOKEN_FILE,
            SCOPES
        )

    # If token is valid, use it directly
    if creds and creds.valid:
        return build(
            "gmail",
            "v1",
            credentials=creds
        )

    # Refresh expired token automatically
    if creds and creds.expired and creds.refresh_token:
        from google.auth.transport.requests import Request

        creds.refresh(Request())

        with open(TOKEN_FILE, "w") as token:
            token.write(creds.to_json())

        return build(
            "gmail",
            "v1",
            credentials=creds
        )

    # No usable token
    raise RuntimeError(
        "Gmail authentication is not configured on the server. "
        "Please provide a valid token.json."
    )