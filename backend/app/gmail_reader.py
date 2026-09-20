import base64
import html
import re

from .gmail_auth import get_gmail_service_for_user


def strip_html_tags(html_text: str) -> str:
    """Convert HTML content into readable plaintext."""
    if not html_text:
        return ""

    # Replace block level tags with newlines
    text = re.sub(
        r'<(?:br|p|div|tr|h\d)[\s/>]',
        '\n',
        html_text,
        flags=re.IGNORECASE
    )

    # Strip script and style blocks entirely
    text = re.sub(
        r'<(?:script|style)[\s\S]*?</(?:script|style)>',
        '',
        text,
        flags=re.IGNORECASE
    )

    # Remove remaining HTML tags
    text = re.sub(
        r'<[^>]+>',
        ' ',
        text
    )

    # Unescape HTML entities
    text = html.unescape(text)

    # Normalize whitespace
    text = re.sub(
        r'[ \t]+',
        ' ',
        text
    )

    text = re.sub(
        r'\n\s*\n+',
        '\n\n',
        text
    )

    return text.strip()


def extract_body_parts(payload: dict) -> tuple[str, str]:
    """
    Recursively extract plain text and HTML from payload.
    Returns (plain_text, html_text).
    """

    plain = ""
    html_content = ""

    if "parts" in payload:

        for part in payload["parts"]:

            sub_plain, sub_html = extract_body_parts(
                part
            )

            plain += (
                "\n" + sub_plain
                if sub_plain
                else ""
            )

            html_content += (
                "\n" + sub_html
                if sub_html
                else ""
            )

    else:

        mime_type = payload.get(
            "mimeType",
            ""
        )

        data = payload.get(
            "body",
            {}
        ).get(
            "data"
        )

        if data:

            try:

                # Add padding if needed
                padding = "=" * (
                    -len(data) % 4
                )

                decoded = (
                    base64.urlsafe_b64decode(
                        data + padding
                    )
                    .decode(
                        "utf-8",
                        errors="ignore"
                    )
                )

                if mime_type == "text/plain":

                    plain += decoded

                elif mime_type == "text/html":

                    html_content += decoded

            except Exception:
                pass

    return (
        plain.strip(),
        html_content.strip()
    )


def extract_body(payload: dict) -> str:
    """
    Extract body text, falling back to HTML
    stripping if plain text is empty.
    """

    plain, html_content = extract_body_parts(
        payload
    )

    if plain:
        return plain

    if html_content:
        return strip_html_tags(
            html_content
        )

    return ""


def extract_links_with_details(
    plain_text: str,
    html_content: str
) -> tuple[list[str], list[dict]]:
    """
    Extract URLs and link details
    (href + anchor text) to identify spoofed links.

    Returns:
        (unique_urls, link_details)
    """

    unique_urls = []
    link_details = []

    # ========================================================
    # 1. Extract from HTML anchors if present
    # ========================================================

    if html_content:

        anchor_pattern = re.compile(
            r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
            re.IGNORECASE | re.DOTALL
        )

        for match in anchor_pattern.finditer(
            html_content
        ):

            href = match.group(
                1
            ).strip()

            anchor_html = match.group(
                2
            ).strip()

            anchor_text = strip_html_tags(
                anchor_html
            )

            # Filter valid HTTP(S) links
            if href.lower().startswith(
                (
                    "http://",
                    "https://"
                )
            ):

                clean_href = href.rstrip(
                    ".,!?;:)"
                )

                if clean_href not in unique_urls:

                    unique_urls.append(
                        clean_href
                    )

                link_details.append({
                    "url": clean_href,
                    "anchor_text": anchor_text
                })

    # ========================================================
    # 2. Extract plain text links
    # ========================================================

    raw_text_urls = re.findall(
        r'https?://[^\s<>"\']+',
        plain_text or "",
        flags=re.IGNORECASE
    )

    for url in raw_text_urls:

        clean_url = url.rstrip(
            ".,!?;:)"
        )

        if clean_url not in unique_urls:

            unique_urls.append(
                clean_url
            )

            link_details.append({
                "url": clean_url,
                "anchor_text": ""
            })

    return (
        unique_urls,
        link_details
    )


def extract_links(text: str) -> list[str]:
    """
    Legacy helper for backward compatibility.
    """

    links = re.findall(
        r'https?://[^\s<>"\']+',
        text or "",
        flags=re.IGNORECASE
    )

    cleaned = []

    for link in links:

        c = link.rstrip(
            ".,!?;:)"
        )

        if c not in cleaned:

            cleaned.append(
                c
            )

    return cleaned


# ============================================================
# ATTACHMENT EXTRACTION
# ============================================================

def extract_attachments(
    service,
    message_id: str,
    payload: dict
) -> list[dict]:
    """
    Extract Gmail attachments.

    This function does NOT analyze or quarantine anything.
    It only downloads attachment data and passes it to the
    rest of ZeroGuard.

    Each attachment contains:
        filename
        mime_type
        data
    """

    attachments = []

    def walk_parts(parts):

        for part in parts or []:

            filename = part.get(
                "filename",
                ""
            )

            mime_type = part.get(
                "mimeType",
                ""
            )

            body = part.get(
                "body",
                {}
            )

            attachment_id = body.get(
                "attachmentId"
            )

            # ------------------------------------------------
            # Gmail stores larger attachments separately.
            # ------------------------------------------------

            if filename and attachment_id:

                try:

                    attachment_response = (
                        service.users()
                        .messages()
                        .attachments()
                        .get(
                            userId="me",
                            messageId=message_id,
                            id=attachment_id
                        )
                        .execute()
                    )

                    encoded_data = (
                        attachment_response.get(
                            "data",
                            ""
                        )
                    )

                    if encoded_data:

                        padding = "=" * (
                            -len(encoded_data) % 4
                        )

                        file_data = (
                            base64.urlsafe_b64decode(
                                encoded_data + padding
                            )
                        )

                        attachments.append({
                            "filename": filename,
                            "mime_type": mime_type,
                            "data": file_data
                        })

                except Exception as e:

                    print(
                        "Warning: Failed to download "
                        f"attachment {filename}: {e}"
                    )

            # ------------------------------------------------
            # Some Gmail messages contain nested MIME parts.
            # ------------------------------------------------

            if part.get("parts"):

                walk_parts(
                    part.get(
                        "parts",
                        []
                    )
                )

    walk_parts(
        payload.get(
            "parts",
            []
        )
    )

    return attachments


# ============================================================
# GET LATEST EMAILS
# ============================================================

def get_latest_emails(
    service=None,
    session_token: str | None = None,
    max_results=10
):
    """
    Fetch latest emails from Inbox and Spam.

    Can use an existing service instance or
    resolve from session_token.

    Existing email behavior is preserved.
    Attachments are additionally extracted.
    """

    if service is None:

        service = get_gmail_service_for_user(
            session_token
        )

    # ========================================================
    # GET INBOX EMAILS
    # ========================================================

    inbox_messages = []

    try:

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

        inbox_messages = (
            inbox_response.get(
                "messages",
                []
            )
        )

    except Exception as e:

        print(
            "Warning: Failed to fetch "
            f"inbox messages: {e}"
        )

    # ========================================================
    # GET SPAM EMAILS
    # ========================================================

    spam_messages = []

    try:

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

        spam_messages = (
            spam_response.get(
                "messages",
                []
            )
        )

    except Exception as e:

        print(
            "Warning: Failed to fetch "
            f"spam messages: {e}"
        )

    # ========================================================
    # COMBINE INBOX + SPAM
    # ========================================================

    all_messages = {}

    for message in inbox_messages:

        all_messages[
            message["id"]
        ] = {
            "id": message["id"],
            "mailbox": "INBOX"
        }

    for message in spam_messages:

        if message["id"] not in all_messages:

            all_messages[
                message["id"]
            ] = {
                "id": message["id"],
                "mailbox": "SPAM"
            }

    messages = list(
        all_messages.values()
    )[:max_results]

    emails = []

    # ========================================================
    # READ EMAIL DETAILS
    # ========================================================

    for message in messages:

        message_id = message["id"]

        try:

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

            # =================================================
            # EXISTING BODY EXTRACTION
            # =================================================

            plain_body, html_body = (
                extract_body_parts(
                    payload
                )
            )

            body = (
                plain_body
                if plain_body
                else strip_html_tags(
                    html_body
                )
            )

            # =================================================
            # EXISTING LINK EXTRACTION
            # =================================================

            links, link_details = (
                extract_links_with_details(
                    plain_body,
                    html_body
                )
            )

            # =================================================
            # NEW: ATTACHMENT EXTRACTION
            # =================================================

            attachments = extract_attachments(
                service,
                message_id,
                payload
            )

            # =================================================
            # FINAL EMAIL OBJECT
            # =================================================

            emails.append({
                "id": message_id,
                "sender": sender,
                "subject": subject,
                "body": body,
                "links": links,
                "link_details": link_details,

                # NEW FIELD
                "attachments": attachments,

                "mailbox": message["mailbox"]
            })

        except Exception as e:

            print(
                "Warning: Failed to fetch details "
                f"for email {message_id}: {e}"
            )

            continue

    return emails