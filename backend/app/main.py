import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .gmail_auth import get_gmail_service
from .gmail_reader import get_latest_emails
from .security_analyzer import analyze_email
from .gmail_quarantine import (
    quarantine_email,
    move_to_inbox
)


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="ZeroGuard API"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "message": "ZeroGuard is running!",
        "status": "active"
    }


# ============================================================
# GMAIL AUTHENTICATION
# ============================================================

@app.get("/gmail-auth")
def gmail_auth():

    try:

        get_gmail_service()

        return {
            "message": "Gmail authentication successful!",
            "status": "connected"
        }

    except Exception as e:

        return {
            "message": "Gmail authentication failed",
            "status": "error",
            "error": str(e)
        }


# ============================================================
# GET + ANALYZE EMAILS
#
# Gmail Inbox + Gmail Spam
#
# LOW:
#     Inbox
#
# MEDIUM:
#     Inbox
#
# HIGH:
#     Inbox + Warning
#     Spam -> ZeroGuard Quarantine
#
# CRITICAL:
#     ZeroGuard Quarantine
# ============================================================

@app.get("/emails")
def emails():

    try:

        # ========================================================
        # GET INBOX + SPAM EMAILS
        # ========================================================

        raw_emails = get_latest_emails(
            max_results=10
        )

        analyzed_emails = []

        # ========================================================
        # ANALYZE EACH EMAIL
        # ========================================================

        for email in raw_emails:

            message_id = email.get("id")

            sender = email.get(
                "sender",
                ""
            )

            subject = email.get(
                "subject",
                ""
            )

            body = email.get(
                "body",
                ""
            )

            links = email.get(
                "links",
                []
            )

            mailbox = email.get(
                "mailbox",
                "INBOX"
            )

            # ====================================================
            # ZERO GUARD SECURITY ANALYSIS
            #
            # Rule-based analyzer
            # +
            # Featherless AI
            # ====================================================

            analysis = analyze_email(
                sender,
                subject,
                body,
                links
            )

            email["security"] = analysis

            risk_level = analysis.get(
                "risk_level",
                "LOW"
            )

            # ====================================================
            # DECISION ENGINE
            # ====================================================

            # ----------------------------------------------------
            # CRITICAL
            #
            # Always quarantine CRITICAL emails.
            # ----------------------------------------------------

            if risk_level == "CRITICAL":

                try:

                    quarantine_result = quarantine_email(
                        message_id
                    )

                    email["security"]["quarantine"] = (
                        quarantine_result
                    )

                    email["security"]["quarantined"] = True

                except Exception as e:

                    email["security"]["quarantine"] = {
                        "status": "error",
                        "message": (
                            "Failed to quarantine email"
                        ),
                        "error": str(e)
                    }

                    email["security"]["quarantined"] = False

            # ----------------------------------------------------
            # HIGH
            # ----------------------------------------------------

            elif risk_level == "HIGH":

                if mailbox == "SPAM":

                    try:

                        quarantine_result = quarantine_email(
                            message_id
                        )

                        email["security"]["quarantine"] = (
                            quarantine_result
                        )

                        email["security"]["quarantined"] = True

                    except Exception as e:

                        email["security"]["quarantine"] = {
                            "status": "error",
                            "message": (
                                "Failed to quarantine email"
                            ),
                            "error": str(e)
                        }

                        email["security"]["quarantined"] = False

                else:

                    email["security"]["quarantine"] = {
                        "status": "not_quarantined",
                        "reason": (
                            "Email is HIGH risk. "
                            "It remains in the Inbox "
                            "for user review."
                        )
                    }

                    email["security"]["quarantined"] = False

            # ----------------------------------------------------
            # MEDIUM
            # ----------------------------------------------------

            elif risk_level == "MEDIUM":

                if mailbox == "SPAM":

                    try:

                        move_result = move_to_inbox(
                            message_id
                        )

                        email["security"]["quarantine"] = {
                            "status": "not_quarantined",
                            "reason": (
                                "ZeroGuard analyzed the email "
                                "as MEDIUM risk and moved it "
                                "from Gmail Spam to Inbox."
                            ),
                            "gmail_action": move_result
                        }

                        email["security"]["quarantined"] = False

                        email["mailbox"] = "INBOX"

                    except Exception as e:

                        email["security"]["quarantine"] = {
                            "status": "error",
                            "message": (
                                "Failed to move email "
                                "from Spam to Inbox"
                            ),
                            "error": str(e)
                        }

                        email["security"]["quarantined"] = False

                else:

                    email["security"]["quarantine"] = {
                        "status": "not_quarantined",
                        "reason": (
                            "Email risk level is MEDIUM. "
                            "It remains in the Inbox."
                        )
                    }

                    email["security"]["quarantined"] = False

            # ----------------------------------------------------
            # LOW
            # ----------------------------------------------------

            else:

                if mailbox == "SPAM":

                    try:

                        move_result = move_to_inbox(
                            message_id
                        )

                        email["security"]["quarantine"] = {
                            "status": "not_quarantined",
                            "reason": (
                                "ZeroGuard analyzed the email "
                                "as LOW risk and moved it "
                                "from Gmail Spam to Inbox."
                            ),
                            "gmail_action": move_result
                        }

                        email["security"]["quarantined"] = False

                        email["mailbox"] = "INBOX"

                    except Exception as e:

                        email["security"]["quarantine"] = {
                            "status": "error",
                            "message": (
                                "Failed to move email "
                                "from Spam to Inbox"
                            ),
                            "error": str(e)
                        }

                        email["security"]["quarantined"] = False

                else:

                    email["security"]["quarantine"] = {
                        "status": "not_quarantined",
                        "reason": (
                            "Email risk level is LOW. "
                            "It remains in the Inbox."
                        )
                    }

                    email["security"]["quarantined"] = False

            # ====================================================
            # ADD TO RESPONSE
            # ====================================================

            analyzed_emails.append(
                email
            )

        # ========================================================
        # RETURN RESPONSE
        # ========================================================

        return {
            "status": "success",
            "count": len(analyzed_emails),
            "emails": analyzed_emails
        }

    except Exception as e:

        return {
            "status": "error",
            "error": str(e)
        }


# ============================================================
# MANUAL QUARANTINE
# ============================================================

@app.post("/quarantine/{email_id}")
def quarantine_email_endpoint(
    email_id: str
):

    try:

        result = quarantine_email(
            email_id
        )

        return result

    except Exception as e:

        return {
            "status": "error",
            "error": str(e)
        }


# ============================================================
# GET QUARANTINED EMAILS
# ============================================================

@app.get("/quarantine")
def get_quarantined_emails():

    try:

        service = get_gmail_service()

        # ========================================================
        # FIND ZERO GUARD QUARANTINE LABEL
        # ========================================================

        labels_response = (
            service.users()
            .labels()
            .list(
                userId="me"
            )
            .execute()
        )

        labels = labels_response.get(
            "labels",
            []
        )

        quarantine_label_id = None

        for label in labels:

            if label.get("name") == "ZeroGuard-Quarantine":

                quarantine_label_id = label.get(
                    "id"
                )

                break

        # ========================================================
        # LABEL DOES NOT EXIST
        # ========================================================

        if quarantine_label_id is None:

            return {
                "status": "success",
                "count": 0,
                "emails": []
            }

        # ========================================================
        # GET QUARANTINED EMAILS
        # ========================================================

        messages_response = (
            service.users()
            .messages()
            .list(
                userId="me",
                labelIds=[
                    quarantine_label_id
                ],
                maxResults=50
            )
            .execute()
        )

        messages = messages_response.get(
            "messages",
            []
        )

        quarantined_emails = []

        # ========================================================
        # READ EACH QUARANTINED EMAIL
        # ========================================================

        for message in messages:

            message_id = message["id"]

            msg = (
                service.users()
                .messages()
                .get(
                    userId="me",
                    id=message_id,
                    format="full"
                )
                .execute()
            )

            payload = msg.get(
                "payload",
                {}
            )

            headers = payload.get(
                "headers",
                []
            )

            sender = ""
            subject = ""

            # ----------------------------------------------------
            # Extract sender and subject
            # ----------------------------------------------------

            for header in headers:

                name = header.get(
                    "name",
                    ""
                ).lower()

                value = header.get(
                    "value",
                    ""
                )

                if name == "from":

                    sender = value

                elif name == "subject":

                    subject = value

            # ----------------------------------------------------
            # Extract body
            # ----------------------------------------------------

            body = ""

            def extract_quarantine_body(part):

                nonlocal body

                mime_type = part.get(
                    "mimeType",
                    ""
                )

                data = (
                    part.get(
                        "body",
                        {}
                    ).get(
                        "data"
                    )
                )

                if (
                    mime_type == "text/plain"
                    and data
                ):

                    try:

                        import base64

                        padding = "=" * (
                            -len(data) % 4
                        )

                        decoded = (
                            base64.urlsafe_b64decode(
                                data + padding
                            )
                        )

                        body += decoded.decode(
                            "utf-8",
                            errors="ignore"
                        )

                    except Exception:

                        pass

                for child in part.get(
                    "parts",
                    []
                ):

                    extract_quarantine_body(
                        child
                    )

            extract_quarantine_body(
                payload
            )

            # ----------------------------------------------------
            # Extract links
            # ----------------------------------------------------

            links = re_extract_urls(
                body
            )

            # ----------------------------------------------------
            # Analyze quarantined email
            # ----------------------------------------------------

            security = analyze_email(
                sender,
                subject,
                body,
                links
            )

            # ----------------------------------------------------
            # Mark as quarantined
            # ----------------------------------------------------

            security["quarantined"] = True

            security["quarantine"] = {
                "status": "quarantined",
                "reason": (
                    "Email is stored in "
                    "ZeroGuard quarantine"
                )
            }

            # ====================================================
            # ADD EMAIL
            # ====================================================

            quarantined_emails.append({

                "id": message_id,

                "sender": sender,

                "subject": subject,

                "body": body,

                "links": links,

                "mailbox": "QUARANTINE",

                "security": security

            })

        # ========================================================
        # RETURN QUARANTINED EMAILS
        # ========================================================

        return {

            "status": "success",

            "count": len(
                quarantined_emails
            ),

            "emails": quarantined_emails

        }

    except Exception as e:

        return {

            "status": "error",

            "error": str(e)

        }


# ============================================================
# URL EXTRACTION FOR QUARANTINED EMAILS
# ============================================================

def re_extract_urls(text):

    if not text:
        return []

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        text,
        flags=re.IGNORECASE
    )

    cleaned_urls = []

    for url in urls:

        url = url.rstrip(
            ".,!?;:)"
        )

        if url not in cleaned_urls:

            cleaned_urls.append(
                url
            )

    return cleaned_urls
