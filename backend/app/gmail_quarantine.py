from .gmail_auth import get_gmail_service


QUARANTINE_LABEL = "ZeroGuard-Quarantine"


def get_quarantine_label_id(service):

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

    labels = response.get(
        "labels",
        []
    )

    # ============================================================
    # CHECK IF LABEL ALREADY EXISTS
    # ============================================================

    for label in labels:

        if label["name"] == QUARANTINE_LABEL:
            return label["id"]

    # ============================================================
    # CREATE LABEL
    # ============================================================

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


# ================================================================
# QUARANTINE EMAIL
# ================================================================

def quarantine_email(email_id: str):

    service = get_gmail_service()

    label_id = get_quarantine_label_id(
        service
    )

    # ============================================================
    # ADD ZERO GUARD QUARANTINE
    #
    # REMOVE:
    # - INBOX
    # - SPAM
    #
    # This makes the quarantine location independent of
    # where the email originally came from.
    # ============================================================

    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={
            "addLabelIds": [
                label_id
            ],
            "removeLabelIds": [
                "INBOX",
                "SPAM"
            ]
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

def move_to_inbox(email_id: str):

    service = get_gmail_service()

    # ============================================================
    # REMOVE GMAIL SPAM LABEL
    # ADD INBOX LABEL
    # ============================================================

    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={
            "addLabelIds": [
                "INBOX"
            ],
            "removeLabelIds": [
                "SPAM"
            ]
        }
    ).execute()

    return {
        "status": "success",
        "message": "Email moved from Spam to Inbox",
        "email_id": email_id
    }