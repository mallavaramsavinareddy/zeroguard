import json
import os
import secrets
from urllib.parse import quote

from dotenv import load_dotenv

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from .user_store import (
    save_user_credentials,
    get_user_credentials,
    create_session,
    get_user_by_session,
    save_oauth_state,
    get_oauth_state,
    complete_oauth_state,
    validate_oauth_state,
    list_users,
)
def log_trace(message: str):
    print(f"[OAuth] {message}")


load_dotenv()


# ---------------------------------------------------------
# GOOGLE OAUTH SCOPES
# ---------------------------------------------------------

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]


# ---------------------------------------------------------
# PATHS
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

CREDENTIALS_FILE = os.path.join(
    BASE_DIR,
    "credentials.json"
)

TOKEN_FILE = os.path.join(
    BASE_DIR,
    "token.json"
)


DEFAULT_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://localhost:8000/auth/google/callback"
)


# ---------------------------------------------------------
# CLIENT CONFIG
# ---------------------------------------------------------

def get_client_config():
    """
    Load Google OAuth client configuration.

    Supports:
    1. GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET environment variables
    2. credentials.json
    """

    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    if client_id and client_secret:
        return {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [
                    DEFAULT_REDIRECT_URI
                ],
            }
        }

    if not os.path.exists(CREDENTIALS_FILE):
        raise FileNotFoundError(
            f"Google OAuth credentials file not found: "
            f"{CREDENTIALS_FILE}"
        )

    with open(CREDENTIALS_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


# ---------------------------------------------------------
# CREATE OAUTH FLOW
# ---------------------------------------------------------

def create_oauth_flow(
    redirect_uri=None,
    state=None,
    code_verifier=None
):
    """
    Create a Google OAuth Flow.

    PKCE is explicitly controlled here so that the verifier
    can be persisted and restored across the callback request.
    """

    config = get_client_config()

    flow = Flow.from_client_config(
        config,
        scopes=SCOPES,
        redirect_uri=redirect_uri or DEFAULT_REDIRECT_URI,
        state=state,
        code_verifier=code_verifier,
        autogenerate_code_verifier=False,
    )

    return flow


# ---------------------------------------------------------
# GENERATE GOOGLE AUTH URL
# ---------------------------------------------------------

def generate_auth_url(
    redirect_uri=None,
    frontend_url=None
):
    """
    Generate Google authorization URL.

    A PKCE verifier is generated here and saved in SQLite.
    The same verifier is restored during the callback.
    """

    state = secrets.token_urlsafe(32)

    # PKCE verifier must be between 43 and 128 characters.
    code_verifier = secrets.token_urlsafe(64)

    chosen_redirect_uri = (
        redirect_uri
        or DEFAULT_REDIRECT_URI
    )

    chosen_frontend_url = (
        frontend_url
        or "http://localhost:5173"
    )

    flow = create_oauth_flow(
        redirect_uri=chosen_redirect_uri,
        state=state,
        code_verifier=code_verifier,
    )

    authorization_url, returned_state = (
        flow.authorization_url(
            access_type="offline",
            prompt="consent",
            # IMPORTANT:
            # Do NOT use include_granted_scopes=True here.
            # It can cause Google to return previously granted
            # scopes that do not exactly match our requested scopes.
            include_granted_scopes="false",
        )
    )

    # Use the state returned by Google's OAuth library.
    # In normal operation it should equal our generated state.
    if returned_state != state:
        state = returned_state

    save_oauth_state(
        state=state,
        redirect_uri=chosen_redirect_uri,
        frontend_url=chosen_frontend_url,
        code_verifier=code_verifier,
    )

    print(
        "[OAuth] Authorization URL generated "
        f"(state={state[:8]}...)"
    )

    return authorization_url, state


# ---------------------------------------------------------
# HANDLE GOOGLE CALLBACK
# ---------------------------------------------------------

def handle_oauth_callback(
    code: str,
    state: str,
    fallback_redirect_uri=None
):
    """
    Exchange Google's authorization code for credentials.

    IMPORTANT:
    The PKCE verifier saved during generate_auth_url()
    is restored before fetch_token().
    """

    if not code:
        raise ValueError(
            "Missing authorization code."
        )

    if not state:
        raise ValueError(
            "Missing OAuth state."
        )

    # Retrieve stored OAuth state.
    state_info = get_oauth_state(state)

    if not state_info:
        raise ValueError(
            "Invalid or expired OAuth state."
        )

    # Prevent replaying an already completed callback.
    if state_info["status"] != "pending":
        raise ValueError(
            "This OAuth request has already been completed."
        )

    # Validate timestamp.
    if not validate_oauth_state(state):
        raise ValueError(
            "OAuth state is invalid or expired."
        )

    redirect_uri = state_info["redirect_uri"]
    code_verifier = state_info.get("code_verifier")

    if not code_verifier:
        raise ValueError(
            "Missing PKCE code verifier for this OAuth request."
        )

    # IMPORTANT:
    # Create a NEW Flow but restore the SAME verifier.
    flow = create_oauth_flow(
        redirect_uri=redirect_uri,
        state=state,
        code_verifier=code_verifier,
    )

    # Exchange authorization code for Google credentials.
    flow.fetch_token(
        code=code
    )

    credentials = flow.credentials

    # -----------------------------------------------------
    # GET USER EMAIL
    # -----------------------------------------------------

    userinfo_service = build(
        "oauth2",
        "v2",
        credentials=credentials,
        cache_discovery=False,
    )

    user_info = userinfo_service.userinfo().get().execute()

    email = user_info.get("email")

    if not email:
        raise ValueError(
            "Google did not return the user's email address."
        )

    # -----------------------------------------------------
    # SAVE USER CREDENTIALS
    # -----------------------------------------------------

    save_user_credentials(
        email,
        credentials
    )

    # -----------------------------------------------------
    # CREATE SESSION
    # -----------------------------------------------------

    session_token = create_session(email)

    # Mark OAuth state as completed.
    complete_oauth_state(
        state=state,
        email=email,
        session_token=session_token,
    )

    print(
        "[OAuth] Google authorization successful "
        f"for {email}"
    )

    return {
        "email": email,
        "session_token": session_token,
        "frontend_url": state_info["frontend_url"],
    }


# ---------------------------------------------------------
# GET GMAIL SERVICE FOR USER
# ---------------------------------------------------------

def get_gmail_service_for_user(
    session_token=None,
    email=None
):
    """
    Return an authenticated Gmail API service.

    Priority:
    1. session_token
    2. explicit email
    3. first stored user
    4. legacy token.json
    """

    user_email = None

    # -----------------------------------------------------
    # SESSION TOKEN
    # -----------------------------------------------------

    if session_token:
        user_email = get_user_by_session(
            session_token
        )

        if not user_email:
            raise ValueError(
                "Invalid or expired session."
            )

    # -----------------------------------------------------
    # EXPLICIT EMAIL
    # -----------------------------------------------------

    elif email:
        user_email = email

    # -----------------------------------------------------
    # FIRST STORED USER
    # -----------------------------------------------------

    else:
        users = list_users()

        if users:
            user_email = users[0]

    # -----------------------------------------------------
    # LOAD STORED USER CREDENTIALS
    # -----------------------------------------------------

    if user_email:
        credentials_data = get_user_credentials(
            user_email
        )

        if not credentials_data:
            raise ValueError(
                f"No Gmail credentials found for {user_email}."
            )

        credentials = Credentials.from_authorized_user_info(
            credentials_data,
            SCOPES
        )

        # Refresh expired access token.
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(
                Request()
            )

            save_user_credentials(
                user_email,
                credentials
            )

        if not credentials.valid:
            raise ValueError(
                "Stored Gmail credentials are no longer valid."
            )

        return build(
            "gmail",
            "v1",
            credentials=credentials,
            cache_discovery=False,
        )

    # -----------------------------------------------------
    # LEGACY TOKEN.JSON FALLBACK
    # -----------------------------------------------------

    if os.path.exists(TOKEN_FILE):
        credentials = Credentials.from_authorized_user_file(
            TOKEN_FILE,
            SCOPES
        )

        if credentials.expired and credentials.refresh_token:
            credentials.refresh(
                Request()
            )

        if credentials.valid:
            return build(
                "gmail",
                "v1",
                credentials=credentials,
                cache_discovery=False,
            )

    raise ValueError(
        "No authenticated Gmail account found. "
        "Please connect a Gmail account first."
    )
def get_gmail_service(session_token=None, email=None):
    """
    Backward-compatible wrapper used by main.py.
    """
    return get_gmail_service_for_user(
        session_token=session_token,
        email=email
    )