import base64
import re

from .gmail_auth import get_gmail_service


def extract_body(payload):
    body = ""

    if "parts" in payload:
        for part in payload["parts"]:

            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data")

                if data:
                    try:
                        body += base64.urlsafe_b64decode(
                            data + "=="
                        ).decode(
                            "utf-8",
                            errors="ignore"
                        )
                    except Exception:
                        pass

            elif "parts" in part:
                body += extract_body(part)

    else:
        if payload.get("mimeType") == "text/plain":
            data = payload.get("body", {}).get("data")

            if data:
                try:
                    body = base64.urlsafe_b64decode(
                        data + "=="
                    ).decode(
                        "utf-8",
                        errors="ignore"
                    )
                except Exception:
                    pass

    return body


def extract_links(text):
    links = re.findall(
        r'https?://[^\s<>"\']+',
        text
    )

    return list(dict.fromkeys(links))


def get_latest_emails(max_results=10):

    service = get_gmail_service()

    # ============================================================
    # GET INBOX EMAILS
    # ============================================================

    inbox_response = (
        service.users()
        .messages()
        .list(
            userId="me",
            labelIds=["INBOX"],
            maxResults=max_results
        )
        .execute()
    )

    inbox_messages = inbox_response.get(
        "messages",
        []
    )

    # ============================================================
    # GET SPAM EMAILS
    # ============================================================

    spam_response = (
        service.users()
        .messages()
        .list(
            userId="me",
            labelIds=["SPAM"],
            maxResults=max_results
        )
        .execute()
    )

    spam_messages = spam_response.get(
        "messages",
        []
    )

    # ============================================================
    # COMBINE INBOX + SPAM
    # ============================================================

    all_messages = {}

    for message in inbox_messages:
        all_messages[message["id"]] = {
            "id": message["id"],
            "mailbox": "INBOX"
        }

    for message in spam_messages:

        if message["id"] not in all_messages:
            all_messages[message["id"]] = {
                "id": message["id"],
                "mailbox": "SPAM"
            }

    messages = list(all_messages.values())

    # Keep the number manageable
    messages = messages[:max_results]

    emails = []

    # ============================================================
    # READ EMAIL DETAILS
    # ============================================================

    for message in messages:

        message_id = message["id"]

        email_data = (
            service.users()
            .messages()
            .get(
                userId="me",
                id=message_id,
                format="full"
            )
            .execute()
        )

        payload = email_data.get(
            "payload",
            {}
        )

        headers = payload.get(
            "headers",
            []
        )

        sender = ""
        subject = ""

        # --------------------------------------------------------
        # Extract headers
        # --------------------------------------------------------

        for header in headers:

            name = header.get(
                "name",
                ""
            ).lower()

            if name == "from":
                sender = header.get(
                    "value",
                    ""
                )

            elif name == "subject":
                subject = header.get(
                    "value",
                    ""
                )

        # --------------------------------------------------------
        # Extract body
        # --------------------------------------------------------

        body = extract_body(payload)

        # --------------------------------------------------------
        # Extract links
        # --------------------------------------------------------

        links = extract_links(body)

        # --------------------------------------------------------
        # Create email object
        # --------------------------------------------------------

        emails.append({
            "id": message_id,
            "sender": sender,
            "subject": subject,
            "body": body,
            "links": links,
            "mailbox": message["mailbox"]
        })

    return emails