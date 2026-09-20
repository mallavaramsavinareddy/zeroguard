import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
from email.utils import parseaddr

from .ai_analyzer import analyze_with_ai, analyze_message_with_ai


# ============================================================
# HELPERS
# ============================================================

def normalize_domain(domain: str) -> str:
    """Normalize a domain for safe comparison."""
    if not domain:
        return ""
    domain = domain.lower().strip()
    domain = domain.rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def get_sender_parts(sender: str) -> tuple[str, str]:
    """Extract display name and email address from sender header."""
    display_name, email_address = parseaddr(sender or "")
    return display_name.strip(), email_address.strip().lower()


def get_domain_from_sender(sender: str) -> str:
    """Extract sender domain."""
    _, email_address = get_sender_parts(sender)
    if "@" not in email_address:
        return ""
    return normalize_domain(email_address.split("@", 1)[1])


def get_link_domain(link: str) -> str:
    """Extract and normalize domain from URL."""
    try:
        parsed = urlparse(link)
        return normalize_domain(parsed.hostname or "")
    except Exception:
        return ""


def extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from email text."""
    if not text:
        return []

    urls = re.findall(
        r"https?://[^\s<>'\"]+",
        text,
        flags=re.IGNORECASE
    )

    cleaned = []

    for url in urls:
        url = url.rstrip(".,!?;:)")

        if url not in cleaned:
            cleaned.append(url)

    return cleaned


def is_trusted_domain(domain: str, trusted_domains: list[str]) -> bool:
    """Check whether domain belongs to a trusted organization."""
    domain = normalize_domain(domain)

    if not domain:
        return False

    return any(
        domain == trusted or domain.endswith("." + trusted)
        for trusted in trusted_domains
    )


def add_reason(reasons: list[str], reason: str):
    """Add a reason only once."""
    if reason and reason not in reasons:
        reasons.append(reason)


# ============================================================
# BRAND CANONICAL MAPPINGS
# ============================================================

BRAND_CANONICAL_DOMAINS = {
    "google": [
        "google.com",
        "youtube.com",
        "gmail.com",
        "googlemail.com"
    ],

    "microsoft": [
        "microsoft.com",
        "live.com",
        "office.com",
        "outlook.com",
        "microsoftonline.com"
    ],

    "apple": [
        "apple.com",
        "icloud.com"
    ],

    "amazon": [
        "amazon.com",
        "aws.amazon.com"
    ],

    "paypal": [
        "paypal.com",
        "paypal-communication.com"
    ],

    "linkedin": [
        "linkedin.com"
    ],

    "github": [
        "github.com"
    ],

    "netflix": [
        "netflix.com"
    ],

    "facebook": [
        "facebook.com",
        "facebookmail.com",
        "meta.com"
    ],

    "instagram": [
        "instagram.com",
        "mail.instagram.com"
    ],

    "twitter": [
        "twitter.com",
        "x.com"
    ],

    "dropbox": [
        "dropbox.com",
        "dropboxmail.com"
    ],

    "adobe": [
        "adobe.com"
    ],

    "slack": [
        "slack.com"
    ],

    "zoom": [
        "zoom.us"
    ],
}


ALL_TRUSTED_DOMAINS = [
    dom
    for sublist in BRAND_CANONICAL_DOMAINS.values()
    for dom in sublist
]


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_email(
    sender,
    subject,
    body,
    links,
    link_details=None
):
    """
    Analyze an email using:

    1. Rule-based security detection
    2. Deceptive/spoofed link analysis
    3. Behavioral suspicion detection
    4. Featherless AI analysis
    5. Safety floors for high-threat patterns
    6. AI threat escalation
    7. Final risk classification

    Risk thresholds:

        0 - 29   -> LOW
        30 - 49  -> MEDIUM
        50 - 69  -> HIGH
        70 - 100 -> CRITICAL
    """

    score = 0
    reasons = []

    sender = sender or ""
    subject = subject or ""
    body = body or ""

    if not isinstance(links, list):
        links = []

    # --------------------------------------------------------
    # Normalize links
    # --------------------------------------------------------

    normalized_links = []

    for link in links:

        if not link:
            continue

        link = str(link).strip()

        if link and link not in normalized_links:
            normalized_links.append(link)

    links = normalized_links

    # Extract URLs from body text
    body_urls = extract_urls_from_text(body)

    for url in body_urls:

        if url not in links:
            links.append(url)

    text = f"{subject} {body}".lower()

    sender_lower = sender.lower()

    display_name, sender_email = get_sender_parts(sender)

    sender_domain = get_domain_from_sender(sender)

    sender_trusted = is_trusted_domain(
        sender_domain,
        ALL_TRUSTED_DOMAINS
    )


    # ============================================================
    # 1. URGENCY / PRESSURE
    # ============================================================

    urgent_words = [
        "urgent",
        "immediately",
        "action required",
        "account will be suspended",
        "verify now",
        "act now",
        "within 24 hours",
        "final warning",
        "last chance",
        "respond immediately",
        "your account is at risk",
        "expires today",
        "expires soon",
        "failure to act",
        "must act",
        "suspended within",
        "unauthorized activity detected",
    ]

    found_urgency = False

    for word in urgent_words:

        if word in text:

            found_urgency = True

            score += 15

            add_reason(
                reasons,
                f"Urgent language detected: '{word}'"
            )

            break


    # ============================================================
    # 2. SENSITIVE INFORMATION REQUESTS
    # ============================================================

    sensitive_words = [
        "password",
        "otp",
        "one-time password",
        "credit card",
        "bank account",
        "security code",
        "login credentials",
        "pin",
        "cvv",
        "debit card",
        "card number",
        "verification code",
        "social security number",
        "ssn",
        "passcode",
    ]

    found_sensitive = False

    for word in sensitive_words:

        if word in text:

            found_sensitive = True

            score += 20

            add_reason(
                reasons,
                f"Sensitive information mentioned: '{word}'"
            )

            break


    # ============================================================
    # 3. PHISHING ACTION PHRASES
    # ============================================================

    phishing_phrases = [
        "verify your account",
        "confirm your identity",
        "update your account",
        "login to your account",
        "log in to your account",
        "click here to verify",
        "click the link",
        "confirm your payment",
        "unlock your account",
        "restore your account",
        "secure your account",
        "verify your identity",
        "validate your account",
        "reactivate your account",
        "your account has been locked",
    ]

    found_phishing_phrase = False

    for phrase in phishing_phrases:

        if phrase in text:

            found_phishing_phrase = True

            score += 15

            add_reason(
                reasons,
                f"Potential phishing phrase detected: '{phrase}'"
            )

            break


    # ============================================================
    # 3B. CREDENTIAL HARVESTING PATTERN
    # ============================================================

    credential_request_words = [
        "password",
        "otp",
        "one-time password",
        "login credentials",
        "security code",
        "verification code",
        "recovery phone",
        "recovery code",
        "passcode",
        "authentication code",
    ]

    verification_words = [
        "verify your account",
        "confirm your identity",
        "update your account",
        "unlock your account",
        "restore your account",
        "verify your identity",
        "validate your account",
    ]

    has_credential_request = any(
        word in text
        for word in credential_request_words
    )

    has_verification_request = any(
        phrase in text
        for phrase in verification_words
    )

    if has_credential_request and has_verification_request:

        score += 30

        add_reason(
            reasons,
            "High-risk credential harvesting pattern: "
            "account verification combined with sensitive "
            "information request"
        )


    # ============================================================
    # 4. SHORTENED URLS
    # ============================================================

    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "rebrand.ly",
        "qr.net",
        "v.gd",
        "clck.ru",
        "rotf.lol",
    ]

    found_shortened_url = False

    for link in links:

        hostname = get_link_domain(link)

        if hostname in shortened_domains:

            found_shortened_url = True

            score += 25

            add_reason(
                reasons,
                f"Shortened URL detected: '{hostname}'"
            )

            break


    # ============================================================
    # 5. IP ADDRESS IN URL
    # ============================================================

    found_ip_url = False

    for link in links:

        try:

            parsed = urlparse(link)

            hostname = parsed.hostname or ""

            if re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                hostname
            ):

                found_ip_url = True

                score += 30

                add_reason(
                    reasons,
                    "URL uses a raw IP address instead of a "
                    f"domain: '{hostname}'"
                )

                break

        except Exception:

            continue


    # ============================================================
    # 6. SUSPICIOUS @ SYMBOL / USERINFO IN URL
    # ============================================================

    for link in links:

        try:

            parsed = urlparse(link)

            if parsed.username or parsed.password:

                score += 25

                add_reason(
                    reasons,
                    "URL contains '@', which can obscure "
                    "the true destination"
                )

                break

        except Exception:

            continue


    # ============================================================
    # 7. INSECURE HTTP CHECK
    # ============================================================

    for link in links:

        try:

            parsed = urlparse(link)

            if parsed.scheme.lower() == "http":

                score += 10

                add_reason(
                    reasons,
                    "Link does not use HTTPS"
                )

                break

        except Exception:

            continue


    # ============================================================
    # 8. DECEPTIVE SPOOFED LINK DETECTION
    # ============================================================

    if link_details:

        for detail in link_details:

            dest_url = detail.get("url", "")

            anchor = detail.get(
                "anchor_text",
                ""
            ).strip()

            if not dest_url or not anchor:
                continue

            dest_domain = get_link_domain(dest_url)

            anchor_match = re.search(
                r'(?:https?://)?'
                r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                anchor
            )

            if anchor_match:

                anchor_domain = normalize_domain(
                    anchor_match.group(1)
                )

                if (
                    anchor_domain
                    and dest_domain
                    and anchor_domain != dest_domain
                ):

                    if not (
                        dest_domain.endswith(
                            "." + anchor_domain
                        )
                        or
                        anchor_domain.endswith(
                            "." + dest_domain
                        )
                    ):

                        score += 35

                        add_reason(
                            reasons,
                            "Deceptive spoofed link: "
                            f"Text displays '{anchor_domain}' "
                            f"but destination opens '{dest_domain}'"
                        )

                        break


    # ============================================================
    # 9. PUNYCODE / IDN HOMOGLYPH DETECTION
    # ============================================================

    if "xn--" in sender_domain:

        score += 25

        add_reason(
            reasons,
            "Sender domain uses Punycode/IDN encoding: "
            f"'{sender_domain}'"
        )

    for link in links:

        ld = get_link_domain(link)

        if "xn--" in ld:

            score += 25

            add_reason(
                reasons,
                "Link uses Punycode/IDN encoding, commonly "
                f"used in lookalike spoofing: '{ld}'"
            )

            break


    # ============================================================
    # 10. EXCESSIVE EXCLAMATION / CAPITALIZATION
    # ============================================================

    if body.count("!") >= 3:

        score += 10

        add_reason(
            reasons,
            "Excessive exclamation marks detected"
        )

    alphabetic_chars = [
        c
        for c in body
        if c.isalpha()
    ]

    if len(alphabetic_chars) >= 20:

        uppercase_chars = [
            c
            for c in body
            if c.isupper()
        ]

        if (
            len(uppercase_chars)
            / len(alphabetic_chars)
        ) >= 0.60:

            score += 5

            add_reason(
                reasons,
                "Excessive capitalization detected"
            )


    # ============================================================
    # 11. SENDER DOMAIN / IMPERSONATION
    # ============================================================

    has_support_identity = False

    if sender_domain:

        if sender_trusted:

            add_reason(
                reasons,
                f"Sender domain appears trusted: "
                f"'{sender_domain}'"
            )

        impersonation_words = [
            "security",
            "support",
            "admin",
            "verify",
            "account",
            "login",
            "billing",
            "service",
            "helpdesk",
            "customer support",
            "customer service",
            "it support"
        ]

        has_support_identity = any(
            word in sender_lower
            for word in impersonation_words
        )

        if has_support_identity and not sender_trusted:

            score += 10

            add_reason(
                reasons,
                "Sender address contains a security-related "
                "impersonation keyword"
            )

        free_email_domains = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "proton.me",
            "protonmail.com"
        ]

        if sender_domain in free_email_domains:

            for brand, valid_domains in BRAND_CANONICAL_DOMAINS.items():

                if (
                    brand in sender_lower
                    or
                    (
                        display_name
                        and brand in display_name.lower()
                    )
                ):

                    score += 25

                    add_reason(
                        reasons,
                        f"Possible impersonation: "
                        f"'{brand.capitalize()}' appears in "
                        "sender identity but email uses "
                        f"free domain '{sender_domain}'"
                    )

                    break


    # ============================================================
    # 12. DISPLAY NAME / BRAND MISMATCH
    # ============================================================

    if display_name and sender_domain:

        display_lower = display_name.lower()

        for brand, valid_domains in BRAND_CANONICAL_DOMAINS.items():

            if brand in display_lower:

                is_legit_brand_domain = any(
                    sender_domain == vd
                    or sender_domain.endswith("." + vd)
                    for vd in valid_domains
                )

                if not is_legit_brand_domain:

                    score += 20

                    add_reason(
                        reasons,
                        f"Display name suggests "
                        f"'{brand.capitalize()}' but sender "
                        f"domain is '{sender_domain}'"
                    )

                break


    # ============================================================
    # 13. SENDER DOMAIN VS LINK DOMAIN
    # ============================================================

    mismatched_link_domain = False

    if sender_domain and links:

        for link in links:

            link_domain = get_link_domain(link)

            if not link_domain:
                continue

            link_trusted = is_trusted_domain(
                link_domain,
                ALL_TRUSTED_DOMAINS
            )

            if sender_trusted and link_trusted:
                continue

            if (
                link_domain == sender_domain
                or link_domain.endswith(
                    "." + sender_domain
                )
                or sender_domain.endswith(
                    "." + link_domain
                )
            ):

                continue

            mismatched_link_domain = True

            score += 15

            add_reason(
                reasons,
                f"Sender domain '{sender_domain}' "
                f"does not match link domain "
                f"'{link_domain}'"
            )

            break


    # ============================================================
    # 14. SUSPICIOUS DOMAIN KEYWORD PATTERNS
    # ============================================================

    suspicious_patterns = [
        r"login-",
        r"verify-",
        r"secure-",
        r"account-",
        r"update-",
        r"signin-",
        r"-login",
        r"-verify",
        r"-secure",
        r"-account",
        r"-update",
        r"password-",
        r"security-"
    ]

    for link in links:

        domain = get_link_domain(link)

        matched = False

        for pattern in suspicious_patterns:

            if re.search(pattern, domain):

                score += 15

                add_reason(
                    reasons,
                    f"Suspicious domain pattern detected: "
                    f"'{domain}'"
                )

                matched = True

                break

        if matched:
            break


    # ============================================================
    # 15. LOOKALIKE DOMAIN DETECTION
    # ============================================================

    lookalike_words = {

        "paypal": [
            "paypa1",
            "pay-pal",
            "paypai"
        ],

        "google": [
            "goog1e",
            "google-login",
            "googleverify",
            "google-secure"
        ],

        "microsoft": [
            "micros0ft",
            "microsoft-login",
            "microsoftverify"
        ],

        "apple": [
            "app1e",
            "apple-login",
            "appleverify"
        ],

        "amazon": [
            "amaz0n",
            "amazon-login",
            "amazonverify"
        ],

        "linkedin": [
            "linkedln",
            "linkedin-login",
            "linkedinverify"
        ],
    }

    lookalike_domain_detected = False

    for link in links:

        domain = get_link_domain(link)

        for _, fake_variations in lookalike_words.items():

            for fake in fake_variations:

                if fake in domain:

                    lookalike_domain_detected = True

                    score += 25

                    add_reason(
                        reasons,
                        "Possible lookalike domain detected: "
                        f"'{domain}'"
                    )

                    break

            if lookalike_domain_detected:
                break

        if lookalike_domain_detected:
            break


    # ============================================================
    # 16. GENERIC DOMAIN SIMILARITY
    # ============================================================

    if links:

        for link in links:

            domain = get_link_domain(link)

            if not domain:
                continue

            for trusted in ALL_TRUSTED_DOMAINS:

                if domain == trusted:
                    continue

                trusted_main = trusted.split(".")[0]

                domain_main = domain.split(".")[0]

                if (
                    len(domain_main) >= 4
                    and len(trusted_main) >= 4
                ):

                    similarity = SequenceMatcher(
                        None,
                        domain_main,
                        trusted_main
                    ).ratio()

                    if (
                        similarity >= 0.80
                        and not is_trusted_domain(
                            domain,
                            ALL_TRUSTED_DOMAINS
                        )
                    ):

                        score += 20

                        add_reason(
                            reasons,
                            "Domain closely resembles "
                            f"trusted domain '{trusted}'"
                        )

                        break


    # ============================================================
    # 17. SUSPICIOUS TLD DETECTION
    # ============================================================

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".buzz",
        ".zip",
        ".mov",
        ".work",
        ".live",
        ".shop",
        ".support",
        ".online",
        ".icu",
        ".rest",
        ".country",
        ".stream",
        ".gq",
        ".cf",
        ".tk",
        ".ml",
        ".ga",
        ".quest",
        ".bond",
        ".cfd"
    ]

    for link in links:

        domain = get_link_domain(link)

        if any(
            domain.endswith(tld)
            for tld in suspicious_tlds
        ):

            score += 15

            add_reason(
                reasons,
                "Suspicious top-level domain detected: "
                f"'{domain}'"
            )

            break


    # ============================================================
    # 18. DEEP SUBDOMAINS & ENCODED URLS
    # ============================================================

    for link in links:

        domain = get_link_domain(link)

        if (
            domain
            and len(domain.split(".")) >= 5
        ):

            score += 10

            add_reason(
                reasons,
                "Unusually deep subdomain structure "
                f"detected: '{domain}'"
            )

            break

    for link in links:

        lower_l = link.lower()

        if any(
            enc in lower_l
            for enc in [
                "%40",
                "%2f",
                "%3d",
                "%3f"
            ]
        ):

            score += 10

            add_reason(
                reasons,
                "URL contains encoded characters that "
                "may obscure its destination"
            )

            break


    # ============================================================
    # 19. DANGEROUS EXECUTABLE MENTIONS
    # ============================================================

    dangerous_file_patterns = [
        r"\.exe\b",
        r"\.scr\b",
        r"\.vbs\b",
        r"\.iso\b",
        r"\.hta\b",
        r"\.bat\b",
        r"\.cmd\b",
        r"\.ps1\b"
    ]

    for pat in dangerous_file_patterns:

        if re.search(pat, text):

            score += 25

            add_reason(
                reasons,
                "Mention of dangerous executable/script "
                "file format detected"
            )

            break


    # ============================================================
    # 20. FINANCIAL / ACCOUNT ACTION COMBINATIONS
    # ============================================================

    financial_words = [
        "payment",
        "invoice",
        "refund",
        "transfer",
        "wire transfer",
        "bank transfer",
        "payment failed",
        "payment required",
        "billing",
        "transaction",
        "money",
        "fee",
        "credit card",
        "debit card"
    ]

    found_financial = any(
        word in text
        for word in financial_words
    )

    account_action_words = [
        "verify",
        "confirm",
        "update",
        "unlock",
        "restore",
        "reactivate",
        "login",
        "log in",
        "reset password",
        "change password",
        "validate"
    ]

    has_account_action = any(
        word in text
        for word in account_action_words
    )

    if found_financial:

        score += 10

        add_reason(
            reasons,
            "Financial or payment-related content detected"
        )

    if (
        found_sensitive
        and links
        and not sender_trusted
    ):

        score += 15

        add_reason(
            reasons,
            "Sensitive information request combined "
            "with an external link"
        )

    if found_urgency and links:

        score += 10

        add_reason(
            reasons,
            "Urgent language combined with an external link"
        )

    if (
        found_financial
        and links
        and not sender_trusted
    ):

        score += 10

        add_reason(
            reasons,
            "Payment-related content combined "
            "with an external link"
        )

    if (
        has_account_action
        and found_urgency
        and links
        and not sender_trusted
    ):

        score += 20

        add_reason(
            reasons,
            "Strong phishing context: account action, "
            "urgency, and external link from an "
            "untrusted sender"
        )

    if (
        has_account_action
        and mismatched_link_domain
    ):

        score += 15

        add_reason(
            reasons,
            "Account-related action requested through "
            "a domain that does not match the sender"
        )

    if (
        has_support_identity
        and links
        and not sender_trusted
    ):

        score += 10

        add_reason(
            reasons,
            "Security/support-style sender directs "
            "the recipient to an external link"
        )


    # ============================================================
    # 21. BEHAVIOR-BASED SUSPICION FLOORS
    # ============================================================

    behavior_floor = 0

    if (
        has_account_action
        and links
        and sender_domain
        and not sender_trusted
    ):

        behavior_floor = max(
            behavior_floor,
            40
        )

        add_reason(
            reasons,
            "Untrusted sender requests an "
            "account-related action through "
            "an external link"
        )

    if (
        found_urgency
        and links
        and sender_domain
        and not sender_trusted
    ):

        behavior_floor = max(
            behavior_floor,
            30
        )

        add_reason(
            reasons,
            "Untrusted sender combines urgency "
            "with an external link"
        )

    if (
        found_financial
        and links
        and sender_domain
        and not sender_trusted
    ):

        behavior_floor = max(
            behavior_floor,
            40
        )

        add_reason(
            reasons,
            "Untrusted sender combines a financial "
            "request with an external link"
        )

    if (
        found_sensitive
        and links
        and sender_domain
        and not sender_trusted
    ):

        behavior_floor = max(
            behavior_floor,
            45
        )

        add_reason(
            reasons,
            "Untrusted sender requests sensitive "
            "information through an external link"
        )

    if (
        has_support_identity
        and links
        and sender_domain
        and not sender_trusted
    ):

        behavior_floor = max(
            behavior_floor,
            35
        )

    if lookalike_domain_detected:

        behavior_floor = max(
            behavior_floor,
            50
        )

    if (
        found_ip_url
        and has_account_action
    ):

        behavior_floor = max(
            behavior_floor,
            70
        )

    if (
        mismatched_link_domain
        and (
            has_account_action
            or found_phishing_phrase
            or found_urgency
        )
        and links
        and sender_domain
        and not sender_trusted
    ):

        behavior_floor = max(
            behavior_floor,
            60
        )

        add_reason(
            reasons,
            "Untrusted sender uses a mismatched "
            "external domain for an account or "
            "verification-related action"
        )


    # ============================================================
    # 22. FEATHERLESS AI ANALYSIS
    # ============================================================

    ai_available = False

    ai_score = 0

    ai_reason = ""

    attacker_intent = "Not determined"

    expected_user_action = "Not determined"

    potential_consequence = "Not determined"

    recommended_defense = "Manual review"

    try:

        ai_result = analyze_with_ai(
            sender=sender,
            subject=subject,
            body=body,
            links=links
        )

        if isinstance(ai_result, dict):

            ai_available = bool(
                ai_result.get(
                    "ai_available",
                    False
                )
            )

            ai_score = int(
                ai_result.get(
                    "risk_score",
                    0
                )
            )

            ai_score = max(
                0,
                min(ai_score, 100)
            )

            ai_reason = str(
                ai_result.get(
                    "reason",
                    ""
                )
                or ""
            )

            attacker_intent = str(
                ai_result.get(
                    "attacker_intent",
                    "Not determined"
                )
                or "Not determined"
            )

            expected_user_action = str(
                ai_result.get(
                    "expected_user_action",
                    "Not determined"
                )
                or "Not determined"
            )

            potential_consequence = str(
                ai_result.get(
                    "potential_consequence",
                    "Not determined"
                )
                or "Not determined"
            )

            recommended_defense = str(
                ai_result.get(
                    "recommended_defense",
                    "Manual review"
                )
                or "Manual review"
            )

    except Exception as e:

        ai_available = False

        add_reason(
            reasons,
            "AI analysis failed; rule-based "
            f"analysis used: {str(e)}"
        )


    # ============================================================
    # 23. COMBINE RULES + AI
    # ============================================================

    rule_score = score

    if ai_available:

        ai_combined_score = int(
            (rule_score * 0.7)
            +
            (ai_score * 0.3)
        )

        # AI cannot reduce deterministic rule score
        combined_score = max(
            ai_combined_score,
            rule_score
        )

    else:

        combined_score = rule_score

        add_reason(
            reasons,
            "AI analysis unavailable; rule-based "
            "analysis used"
        )

    if behavior_floor > combined_score:

        combined_score = behavior_floor

        add_reason(
            reasons,
            "Behavior-based risk floor applied: "
            f"{behavior_floor}"
        )

    if ai_available and ai_reason:

        add_reason(
            reasons,
            f"AI analysis: {ai_reason}"
        )


    # ============================================================
    # 24. AI THREAT ESCALATION FOR HIGH IMPACT ATTACKS
    # ============================================================

    if (
        ai_available
        and links
        and (
            not sender_trusted
            or rule_score >= 20
            or ai_score >= 40
        )
    ):

        ai_intent_l = attacker_intent.lower()

        ai_conseq_l = potential_consequence.lower()

        ai_action_l = expected_user_action.lower()

        ai_def_l = recommended_defense.lower()

        strong_threats = [
            "malware delivery",
            "phishing",
            "credential theft",
            "credential harvesting",
            "account takeover",
            "ransomware",
            "malicious link",
            "social engineering"
        ]

        if (
            any(
                t in ai_intent_l
                for t in strong_threats
            )
            or
            any(
                t in ai_conseq_l
                for t in strong_threats
            )
        ):

            combined_score = max(
                combined_score,
                70
            )

            add_reason(
                reasons,
                "AI identified high-risk threat "
                f"objective: '{attacker_intent}'"
            )

        if (
            "quarantine" in ai_def_l
            and combined_score >= 40
        ):

            combined_score = max(
                combined_score,
                70
            )

            add_reason(
                reasons,
                "AI recommends immediate "
                "quarantine for this message"
            )


    # ============================================================
    # 25. FINAL SAFETY INDICATORS
    # ============================================================

    critical_indicators = 0

    if (
        has_credential_request
        and has_verification_request
    ):

        critical_indicators += 1

    if found_ip_url:

        critical_indicators += 1

    if mismatched_link_domain:

        critical_indicators += 1

    if (
        has_account_action
        and found_urgency
        and links
    ):

        critical_indicators += 1

    if lookalike_domain_detected:

        critical_indicators += 1

    if critical_indicators >= 2:

        combined_score = max(
            combined_score,
            40
        )

        add_reason(
            reasons,
            "Multiple high-risk security "
            "indicators detected"
        )

    if (
        has_credential_request
        and has_verification_request
        and links
    ):

        combined_score = max(
            combined_score,
            60
        )

        add_reason(
            reasons,
            "Credential harvesting with an "
            "external link requires elevated risk"
        )

    if (
        found_ip_url
        and has_account_action
    ):

        combined_score = max(
            combined_score,
            70
        )

        add_reason(
            reasons,
            "IP-based URL combined with account "
            "action is highly dangerous"
        )

    if (
        lookalike_domain_detected
        and (
            has_credential_request
            or has_account_action
        )
    ):

        combined_score = max(
            combined_score,
            70
        )

        add_reason(
            reasons,
            "Lookalike domain combined with "
            "account or credential activity"
        )


    # ============================================================
    # 26. FINAL SCORE
    # ============================================================

    score = max(
        0,
        min(
            int(combined_score),
            100
        )
    )


    # ============================================================
    # 27. FINAL RISK LEVEL
    # ============================================================
    #
    # NEW THRESHOLDS
    #
    # 70 - 100 = CRITICAL
    # 50 - 69  = HIGH
    # 30 - 49  = MEDIUM
    # 0  - 29  = LOW
    #
    # ============================================================

    if score >= 70:

        risk_level = "CRITICAL"

    elif score >= 50:

        risk_level = "HIGH"

    elif score >= 30:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # ============================================================
    # 28. FINAL DEFENSE DECISION
    # ============================================================
    #
    # IMPORTANT:
    # AI recommendation must NOT override the final
    # security risk level.
    #
    # HIGH / CRITICAL -> QUARANTINE
    # MEDIUM           -> WARN
    # LOW              -> ALLOW
    #
    # ============================================================

    if risk_level == "CRITICAL":

        final_recommended_defense = "Quarantine email"

    elif risk_level == "HIGH":

        final_recommended_defense = "Quarantine email"

    elif risk_level == "MEDIUM":

        final_recommended_defense = "Warn user"

    else:

        final_recommended_defense = "Allow email"


    # ============================================================
    # 29. RETURN FINAL RESULT
    # ============================================================

    return {

        "risk_score": score,

        "risk_level": risk_level,

        "reasons": reasons,

        "intent": {

            "attacker_intent": attacker_intent,

            "expected_user_action": expected_user_action,

            "potential_consequence": potential_consequence,

            # Use final security decision instead of
            # blindly trusting AI recommendation.
            "recommended_defense": final_recommended_defense,
        },

        "ai_analysis": {

            "available": ai_available,

            "score": ai_score,

            "reason": ai_reason,
        }
    }


# ============================================================
# MANUAL MESSAGE / URL PHISHING ANALYZER
# ============================================================

def analyze_message(
    message: str = "",
    url: str = ""
) -> dict:
    """
    Analyze a manually submitted message and/or URL (from SMS, WhatsApp,
    LinkedIn, Instagram, or direct message) for phishing indicators.

    Reuses existing ZeroGuard security analysis rules, canonical brand
    mappings, homoglyph detection, URL heuristics, and AI analyzer.

    Severity Scale:
        0 - 19   -> SAFE
        20 - 39  -> LOW
        40 - 69  -> SUSPICIOUS
        70 - 89  -> DANGEROUS
        90 - 100 -> CRITICAL
    """
    message = (message or "").strip()
    url = (url or "").strip()

    score = 0
    reasons = []
    detected_urls = []

    # --------------------------------------------------------
    # 1. URL EXTRACTION & NORMALIZATION
    # --------------------------------------------------------
    raw_urls = extract_urls_from_text(message)

    # Also detect bare domain-style links in message (e.g. paypa1.com/login, bit.ly/xyz)
    bare_matches = re.findall(
        r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>"\']*)?',
        message,
        flags=re.IGNORECASE
    )
    for m in bare_matches:
        cleaned_m = m.rstrip(".,!?;:)")
        if cleaned_m and cleaned_m not in raw_urls:
            raw_urls.append(cleaned_m)

    if url and url not in raw_urls:
        raw_urls.append(url)

    for item in raw_urls:
        item = item.strip().rstrip(".,!?;:)")
        if not item:
            continue
        if item not in detected_urls:
            detected_urls.append(item)

    # Normalized URLs with scheme for safe parsing
    normalized_parse_links = []
    for u in detected_urls:
        if not re.match(r"^https?://", u, flags=re.IGNORECASE):
            normalized_parse_links.append(f"https://{u}")
        else:
            normalized_parse_links.append(u)

    text_lower = message.lower()

    # --------------------------------------------------------
    # 2. URGENCY & THREATENING LANGUAGE
    # --------------------------------------------------------
    urgent_words = [
        "urgent",
        "immediately",
        "action required",
        "account will be suspended",
        "account suspended",
        "account locked",
        "verify now",
        "act now",
        "within 24 hours",
        "within 12 hours",
        "final warning",
        "last chance",
        "respond immediately",
        "your account is at risk",
        "expires today",
        "expires soon",
        "failure to act",
        "must act",
        "suspended within",
        "unauthorized activity detected",
        "deactivated soon",
        "termination notice",
        "time sensitive"
    ]

    found_urgency = False
    for word in urgent_words:
        if word in text_lower:
            found_urgency = True
            score += 15
            add_reason(reasons, f"Urgent/threatening language detected: '{word}'")
            break

    # --------------------------------------------------------
    # 3. SENSITIVE INFORMATION REQUESTS
    # --------------------------------------------------------
    sensitive_words = [
        "password",
        "otp",
        "one-time password",
        "credit card",
        "debit card",
        "bank account",
        "security code",
        "login credentials",
        "pin",
        "cvv",
        "verification code",
        "social security number",
        "ssn",
        "passcode",
        "atm pin",
        "secret code",
        "auth code"
    ]

    found_sensitive = False
    for word in sensitive_words:
        if word in text_lower:
            found_sensitive = True
            score += 20
            add_reason(reasons, f"Requests or mentions sensitive data: '{word}'")
            break

    # --------------------------------------------------------
    # 4. PHISHING ACTION PHRASES
    # --------------------------------------------------------
    phishing_phrases = [
        "verify your account",
        "confirm your identity",
        "update your account",
        "login to your account",
        "log in to your account",
        "click here to verify",
        "click the link",
        "click here",
        "tap here",
        "confirm your payment",
        "unlock your account",
        "restore your account",
        "secure your account",
        "validate your account",
        "reactivate your account",
        "claim your prize",
        "claim your reward",
        "claim here",
        "share your code",
        "send your code",
        "send the code",
        "send otp",
        "send your otp",
        "share otp",
        "share your otp",
        "provide otp",
        "enter your otp",
        "share the 6-digit",
        "download attachment",
        "install the app"
    ]

    found_action = False
    for phrase in phishing_phrases:
        if phrase in text_lower:
            found_action = True
            score += 15
            add_reason(reasons, f"Phishing action phrase detected: '{phrase}'")
            break

    # --------------------------------------------------------
    # 5. CREDENTIAL HARVESTING COMBINATIONS
    # --------------------------------------------------------
    if found_sensitive and found_action:
        score += 25
        add_reason(
            reasons,
            "High-risk credential harvesting pattern: sensitive information requested alongside an account action"
        )

    if found_sensitive and found_urgency:
        score += 15
        add_reason(
            reasons,
            "Urgent language combined with request for sensitive credentials/OTP"
        )

    # --------------------------------------------------------
    # 6. SOCIAL ENGINEERING / COMMON SCAM LURES
    # --------------------------------------------------------
    # Smishing: WhatsApp / SMS 6-digit code takeover
    if ("6-digit" in text_lower or "six digit" in text_lower or "whatsapp code" in text_lower) and (
        "sent" in text_lower or "send" in text_lower or "forward" in text_lower or "share" in text_lower
    ):
        score += 30
        add_reason(
            reasons,
            "Smishing pattern: Requesting a 6-digit verification code commonly used in account takeover scams"
        )

    # Package delivery scam lures
    delivery_keywords = [
        "package delivery",
        "parcel",
        "unpaid postage",
        "customs fee",
        "delivery address",
        "reschedule delivery",
        "failed delivery attempt",
        "usps",
        "dhl",
        "fedex",
        "ups"
    ]
    has_delivery = any(k in text_lower for k in delivery_keywords)
    if has_delivery and (detected_urls or found_urgency):
        score += 20
        add_reason(reasons, "Package delivery notice combined with link or urgency (common smishing lure)")

    # Job / Lottery / Crypto scams
    scam_lures = [
        "part-time job",
        "earn $",
        "earn daily",
        "work from home",
        "lottery winner",
        "won $",
        "crypto investment",
        "bitcoin bonus",
        "giveaway winner",
        "free gift card"
    ]
    for lure in scam_lures:
        if lure in text_lower:
            score += 20
            add_reason(reasons, f"Potential social-engineering lure detected: '{lure}'")
            break

    # --------------------------------------------------------
    # 7. DANGEROUS FILE / EXECUTABLE EXTENSIONS
    # --------------------------------------------------------
    dangerous_file_patterns = [
        r"\.exe\b",
        r"\.scr\b",
        r"\.vbs\b",
        r"\.iso\b",
        r"\.hta\b",
        r"\.bat\b",
        r"\.cmd\b",
        r"\.ps1\b",
        r"\.apk\b"
    ]
    for pat in dangerous_file_patterns:
        if re.search(pat, text_lower):
            score += 25
            add_reason(reasons, "Reference to executable or script file format detected")
            break

    # --------------------------------------------------------
    # 8. URL-BASED SECURITY HEURISTICS (SAFE STATIC ANALYSIS)
    # --------------------------------------------------------
    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "rebrand.ly",
        "qr.net",
        "v.gd",
        "clck.ru",
        "rotf.lol"
    ]

    suspicious_patterns = [
        r"login-",
        r"verify-",
        r"secure-",
        r"account-",
        r"update-",
        r"signin-",
        r"-login",
        r"-verify",
        r"-secure",
        r"-account",
        r"-update",
        r"password-",
        r"security-"
    ]

    lookalike_words = {
        "paypal": ["paypa1", "pay-pal", "paypai"],
        "google": ["goog1e", "google-login", "googleverify", "google-secure"],
        "microsoft": ["micros0ft", "microsoft-login", "microsoftverify"],
        "apple": ["app1e", "apple-login", "appleverify"],
        "amazon": ["amaz0n", "amazon-login", "amazonverify"],
        "linkedin": ["linkedln", "linkedin-login", "linkedinverify"],
        "whatsapp": ["whatsap", "whats-app", "wa-verify"],
        "instagram": ["instagrarn", "insta-login", "instagram-verify"],
        "netflix": ["netflx", "netflix-verify", "netflix-update"]
    }

    suspicious_tlds = [
        ".xyz", ".top", ".click", ".buzz", ".zip", ".mov", ".work",
        ".live", ".shop", ".support", ".online", ".icu", ".rest",
        ".country", ".stream", ".gq", ".cf", ".tk", ".ml", ".ga",
        ".quest", ".bond", ".cfd"
    ]

    lookalike_detected = False
    found_ip_url = False
    found_suspicious_domain_pattern = False
    brand_impersonation_mismatch = False

    for link in normalized_parse_links:
        try:
            parsed = urlparse(link)
            domain = normalize_domain(parsed.hostname or "")

            if not domain:
                continue

            # Shortened URL
            if domain in shortened_domains:
                score += 25
                add_reason(reasons, f"Shortened URL detected: '{domain}' (obscures actual destination)")

            # Raw IP Address
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain):
                found_ip_url = True
                score += 35
                add_reason(reasons, f"URL uses raw IP address instead of domain name: '{domain}'")

            # Insecure HTTP
            if parsed.scheme.lower() == "http":
                score += 10
                add_reason(reasons, f"Link '{domain}' does not use HTTPS encryption")

            # Suspicious @ userinfo in URL
            if parsed.username or parsed.password or "@" in parsed.netloc:
                score += 25
                add_reason(reasons, "URL contains '@' symbol which can conceal the true destination")

            # Punycode / IDN Homoglyph
            if "xn--" in domain:
                score += 30
                add_reason(reasons, f"Link uses Punycode/IDN encoding commonly seen in spoofing: '{domain}'")

            # Suspicious domain keywords
            for pat in suspicious_patterns:
                if re.search(pat, domain):
                    found_suspicious_domain_pattern = True
                    score += 20
                    add_reason(reasons, f"Suspicious keyword pattern detected in domain: '{domain}'")
                    break

            # Lookalike domain detection
            for brand, fakes in lookalike_words.items():
                for fake in fakes:
                    if fake in domain:
                        lookalike_detected = True
                        score += 30
                        add_reason(reasons, f"Possible lookalike domain targeting {brand.capitalize()}: '{domain}'")
                        break
                if lookalike_detected:
                    break

            # Generic domain similarity to trusted brands
            for trusted in ALL_TRUSTED_DOMAINS:
                if domain == trusted or domain.endswith("." + trusted):
                    continue
                trusted_main = trusted.split(".")[0]
                domain_main = domain.split(".")[0]
                if len(domain_main) >= 4 and len(trusted_main) >= 4:
                    similarity = SequenceMatcher(None, domain_main, trusted_main).ratio()
                    if similarity >= 0.80 and not is_trusted_domain(domain, ALL_TRUSTED_DOMAINS):
                        score += 25
                        add_reason(reasons, f"Domain '{domain}' closely resembles trusted brand '{trusted}'")
                        break

            # Suspicious TLD
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                score += 20
                add_reason(reasons, f"Suspicious top-level domain detected: '{domain}'")

            # Deep subdomains
            if len(domain.split(".")) >= 5:
                score += 15
                add_reason(reasons, f"Unusually deep subdomain structure: '{domain}'")

            # Encoded URL characters
            if any(enc in link.lower() for enc in ["%40", "%2f", "%3d", "%3f"]):
                score += 10
                add_reason(reasons, "URL contains encoded characters that may conceal destination")

            # Brand name mentioned in message vs link mismatch
            for brand, canonical_list in BRAND_CANONICAL_DOMAINS.items():
                if brand in text_lower:
                    is_legit = is_trusted_domain(domain, canonical_list)
                    if not is_legit and domain not in shortened_domains:
                        brand_impersonation_mismatch = True
                        score += 30
                        add_reason(
                            reasons,
                            f"Possible impersonation: Message refers to '{brand.capitalize()}' but contains link to unrelated domain '{domain}'"
                        )
                        break

            # If link is legitimate trusted brand domain
            if is_trusted_domain(domain, ALL_TRUSTED_DOMAINS) and score == 0:
                add_reason(reasons, f"Domain belongs to recognized organization: '{domain}'")

        except Exception:
            continue

    # --------------------------------------------------------
    # 9. BEHAVIORAL RISK FLOORS
    # --------------------------------------------------------
    behavior_floor = 0

    if found_sensitive and detected_urls:
        behavior_floor = max(behavior_floor, 45)
        add_reason(reasons, "Sensitive request combined with external URL requires heightened risk")

    if found_urgency and detected_urls:
        behavior_floor = max(behavior_floor, 40)

    if found_sensitive and found_urgency:
        behavior_floor = max(behavior_floor, 45)

    if brand_impersonation_mismatch:
        behavior_floor = max(behavior_floor, 70)

    if lookalike_detected:
        behavior_floor = max(behavior_floor, 65)

    if found_ip_url:
        behavior_floor = max(behavior_floor, 70)

    if found_sensitive and found_action and detected_urls:
        behavior_floor = max(behavior_floor, 75)

    rule_score = max(score, behavior_floor)

    # --------------------------------------------------------
    # 10. FEATHERLESS AI MESSAGE ANALYSIS
    # --------------------------------------------------------
    ai_available = False
    ai_score = 0
    ai_recommendation = ""

    try:
        ai_res = analyze_message_with_ai(
            message=message,
            links=detected_urls
        )
        if isinstance(ai_res, dict) and ai_res.get("ai_available"):
            ai_available = True
            ai_score = max(0, min(100, int(ai_res.get("risk_score", 0))))
            ai_reasons = ai_res.get("reasons", [])
            ai_recommendation = ai_res.get("recommendation", "")

            for r in ai_reasons:
                add_reason(reasons, f"AI Analysis: {r}")

    except Exception as e:
        ai_available = False
        print("AI message analysis exception:", e)

    # --------------------------------------------------------
    # 11. COMBINE RULE & AI SCORES
    # --------------------------------------------------------
    if ai_available:
        combined_score = int((rule_score * 0.65) + (ai_score * 0.35))
        # Deterministic security rules act as a floor
        final_score = max(combined_score, rule_score, behavior_floor)

        if ai_score >= 70 and detected_urls:
            final_score = max(final_score, 70)
    else:
        final_score = rule_score
        if not reasons:
            add_reason(reasons, "Standard heuristic analysis completed; AI analysis was unavailable")

    final_score = max(0, min(int(final_score), 100))

    # --------------------------------------------------------
    # 12. SEVERITY MAPPING
    # --------------------------------------------------------
    # 0-19   = SAFE
    # 20-39  = LOW
    # 40-69  = SUSPICIOUS
    # 70-89  = DANGEROUS
    # 90-100 = CRITICAL
    if final_score >= 90:
        severity = "CRITICAL"
    elif final_score >= 70:
        severity = "DANGEROUS"
    elif final_score >= 40:
        severity = "SUSPICIOUS"
    elif final_score >= 20:
        severity = "LOW"
    else:
        severity = "SAFE"

    # Default reason if clean
    if not reasons and severity == "SAFE":
        reasons.append("No suspicious phishing indicators, deceptive links, or social engineering detected.")

    # --------------------------------------------------------
    # 13. ACTIONABLE RECOMMENDATION
    # --------------------------------------------------------
    if ai_recommendation and len(ai_recommendation) > 10:
        recommendation = ai_recommendation
    elif severity == "CRITICAL":
        recommendation = "Do not click any links or enter credentials. This message appears to be a direct credential or financial theft attempt. Block the sender immediately."
    elif severity == "DANGEROUS":
        recommendation = "Do not click the link or provide sensitive information until verified through an independent, official channel."
    elif severity == "SUSPICIOUS":
        recommendation = "Exercise caution. Confirm the sender's identity through an official channel before interacting or clicking links."
    elif severity == "LOW":
        recommendation = "Low risk detected. Always exercise basic caution when receiving unsolicited messages or links."
    else:
        recommendation = "This message appears safe. Always stay vigilant with unfamiliar requests."

    return {
        "risk_score": final_score,
        "severity": severity,
        "reasons": reasons,
        "detected_urls": detected_urls,
        "recommendation": recommendation,
        "ai_analysis": {
            "available": ai_available,
            "score": ai_score
        }
    }