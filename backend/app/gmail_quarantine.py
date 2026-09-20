from .gmail_auth import get_gmail_service_for_user

QUARANTINE_LABEL = "ZeroGuard-Quarantine"


def get_quarantine_label_id(service):
    """
    Get or create the ZeroGuard-Quarantine label in the user's Gmail account.
    """
    # ============================================================
    # GET EXISTING LABELS
    # ============================================================
    response = (
        service.users()
        .labels()
        .list(
            userId="me"
        )
        .execute()
    )

    labels = response.get("labels", [])

    # Check if label already exists
    for label in labels:
        if label.get("name") == QUARANTINE_LABEL:
            return label["id"]

    # Create label if it does not exist
    try:
        created_label = (
            service.users()
            .labels()
            .create(
                userId="me",
                body={
                    "name": QUARANTINE_LABEL,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show"
                }
            )
            .execute()
        )
        return created_label["id"]
    except Exception as e:
        # Handle race condition if label was created concurrently
        refreshed = service.users().labels().list(userId="me").execute()
        for label in refreshed.get("labels", []):
            if label.get("name") == QUARANTINE_LABEL:
                return label["id"]
        raise e


# ================================================================
# QUARANTINE EMAIL
# ================================================================

def quarantine_email(email_id: str, service=None, session_token: str | None = None):
    """
    Quarantine an email by adding the ZeroGuard-Quarantine label
    and removing it from INBOX and SPAM.
    """
    if service is None:
        service = get_gmail_service_for_user(session_token)

    label_id = get_quarantine_label_id(service)

    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={
            "addLabelIds": [label_id],
            "removeLabelIds": ["INBOX", "SPAM"]
        }
    ).execute()

    return {
        "status": "success",
        "message": "Email successfully quarantined",
        "email_id": email_id,
        "label": QUARANTINE_LABEL
    }


# ================================================================
# MOVE SPAM EMAIL TO INBOX
# ================================================================

def move_to_inbox(email_id: str, service=None, session_token: str | None = None):
    """
    Move a false-positive email from SPAM to INBOX.
    """
    if service is None:
        service = get_gmail_service_for_user(session_token)

    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={
            "addLabelIds": ["INBOX"],
            "removeLabelIds": ["SPAM"]
        }
    ).execute()

    return {
        "status": "success",
        "message": "Email moved from Spam to Inbox",
        "email_id": email_id
    }
    # ================================================================
# RELEASE FROM ZERO GUARD QUARANTINE
# ================================================================

def release_from_quarantine(
    email_id: str,
    service=None,
    session_token: str | None = None
):
    """
    Remove ZeroGuard quarantine label and restore the email
    to the Inbox.
    """
    if service is None:
        service = get_gmail_service_for_user(session_token)

    label_id = get_quarantine_label_id(service)

    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={
            "addLabelIds": ["INBOX"],
            "removeLabelIds": [
                label_id,
                "SPAM"
            ]
        }
    ).execute()

    return {
        "status": "success",
        "message": "Email released from ZeroGuard quarantine",
        "email_id": email_id
    }