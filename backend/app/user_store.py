import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_FILE = os.path.join(DATA_DIR, "zeroguard.db")


def _get_connection():
    os.makedirs(DATA_DIR, exist_ok=True)

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


def _init_db():
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                credentials_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_token TEXT PRIMARY KEY,
                email TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                redirect_uri TEXT NOT NULL,
                frontend_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                session_token TEXT,
                email TEXT,
                code_verifier TEXT,
                created_at TEXT NOT NULL
            )
        """)

        # Migration for databases created by an older version.
        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(oauth_states)"
            ).fetchall()
        }

        if "code_verifier" not in columns:
            conn.execute(
                "ALTER TABLE oauth_states ADD COLUMN code_verifier TEXT"
            )

        if "session_token" not in columns:
            conn.execute(
                "ALTER TABLE oauth_states ADD COLUMN session_token TEXT"
            )

        if "email" not in columns:
            conn.execute(
                "ALTER TABLE oauth_states ADD COLUMN email TEXT"
            )

        conn.commit()


_init_db()


# ---------------------------------------------------------
# USER CREDENTIALS
# ---------------------------------------------------------

def save_user_credentials(email: str, credentials):
    """
    Save or update Gmail OAuth credentials for a user.
    """

    now = datetime.now(timezone.utc).isoformat()

    credentials_json = credentials.to_json()

    with _get_connection() as conn:
        existing = conn.execute(
            "SELECT email FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE users
                SET credentials_json = ?,
                    updated_at = ?
                WHERE email = ?
            """, (
                credentials_json,
                now,
                email
            ))
        else:
            conn.execute("""
                INSERT INTO users (
                    email,
                    credentials_json,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?)
            """, (
                email,
                credentials_json,
                now,
                now
            ))

        conn.commit()


def get_user_credentials(email: str):
    """
    Return stored Google credentials for a user.
    """

    with _get_connection() as conn:
        row = conn.execute("""
            SELECT credentials_json
            FROM users
            WHERE email = ?
        """, (email,)).fetchone()

    if not row:
        return None

    return json.loads(row["credentials_json"])


def list_users():
    """
    Return all stored user emails.
    """

    with _get_connection() as conn:
        rows = conn.execute("""
            SELECT email
            FROM users
            ORDER BY email
        """).fetchall()

    return [row["email"] for row in rows]


# ---------------------------------------------------------
# SESSIONS
# ---------------------------------------------------------

def create_session(email: str, days: int = 30) -> str:
    """
    Create a session token for a logged-in user.
    """

    session_token = secrets.token_urlsafe(32)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=days)

    with _get_connection() as conn:
        conn.execute("""
            INSERT INTO sessions (
                session_token,
                email,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?)
        """, (
            session_token,
            email,
            now.isoformat(),
            expires_at.isoformat()
        ))

        conn.commit()

    return session_token


def get_user_by_session(session_token: str):
    """
    Return the user email associated with a valid session token.
    """

    if not session_token:
        return None

    now = datetime.now(timezone.utc)

    with _get_connection() as conn:
        row = conn.execute("""
            SELECT email, expires_at
            FROM sessions
            WHERE session_token = ?
        """, (session_token,)).fetchone()

        if not row:
            return None

        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None

        if expires_at <= now:
            conn.execute(
                "DELETE FROM sessions WHERE session_token = ?",
                (session_token,)
            )
            conn.commit()
            return None

        return row["email"]


def delete_session(session_token: str):
    """
    Delete a session token.
    """

    if not session_token:
        return

    with _get_connection() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE session_token = ?",
            (session_token,)
        )
        conn.commit()


# ---------------------------------------------------------
# OAUTH STATE
# ---------------------------------------------------------

def save_oauth_state(
    state: str,
    redirect_uri: str,
    frontend_url: str,
    code_verifier: Optional[str] = None
):
    """
    Store OAuth state together with the PKCE code verifier.

    The code verifier MUST survive from the authorization request
    until the callback because Google requires the same verifier
    when exchanging the authorization code for tokens.
    """

    now = datetime.now(timezone.utc).isoformat()

    with _get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO oauth_states (
                state,
                redirect_uri,
                frontend_url,
                status,
                session_token,
                email,
                code_verifier,
                created_at
            )
            VALUES (?, ?, ?, 'pending', NULL, NULL, ?, ?)
        """, (
            state,
            redirect_uri,
            frontend_url,
            code_verifier,
            now
        ))

        conn.commit()


def get_oauth_state(state: str):
    """
    Retrieve OAuth state information.
    """

    if not state:
        return None

    with _get_connection() as conn:
        row = conn.execute("""
            SELECT
                state,
                redirect_uri,
                frontend_url,
                status,
                session_token,
                email,
                code_verifier,
                created_at
            FROM oauth_states
            WHERE state = ?
        """, (state,)).fetchone()

    if not row:
        return None

    return dict(row)


def validate_oauth_state(
    state: str,
    max_age_seconds: int = 1800
) -> bool:
    """
    Validate that an OAuth state exists, is pending,
    and has not expired.

    OAuth state is valid for 30 minutes.
    """

    oauth_state = get_oauth_state(state)

    if not oauth_state:
        return False

    # State must still be pending
    if oauth_state["status"] != "pending":
        return False

    try:
        created_at = datetime.fromisoformat(
            oauth_state["created_at"]
        )
    except (TypeError, ValueError):
        return False

    now = datetime.now(timezone.utc)

    # Calculate state age
    age = (now - created_at).total_seconds()

    # Invalid future timestamp
    if age < 0:
        return False

    # OAuth state expires after 30 minutes
    if age > max_age_seconds:
        return False

    return True
def complete_oauth_state(
    state: str,
    email: Optional[str] = None,
    session_token: Optional[str] = None
):
    """
    Mark an OAuth state as completed.
    """

    with _get_connection() as conn:
        conn.execute("""
            UPDATE oauth_states
            SET status = 'completed',
                email = ?,
                session_token = ?
            WHERE state = ?
        """, (
            email,
            session_token,
            state
        ))

        conn.commit()