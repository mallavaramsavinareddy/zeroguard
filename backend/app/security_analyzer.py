import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
from email.utils import parseaddr

from .ai_analyzer import analyze_with_ai


# ============================================================
# HELPERS
# ============================================================

def normalize_domain(domain):
    """Normalize a domain for comparison."""

    if not domain:
        return ""

    domain = domain.lower().strip()
    domain = domain.rstrip(".")

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def get_sender_parts(sender):
    """
    Extract display name and email address from sender.
    """

    display_name, email_address = parseaddr(sender)

    return (
        display_name.strip(),
        email_address.strip().lower()
    )


def get_domain_from_sender(sender):
    """
    Extract sender domain.
    """

    _, email_address = get_sender_parts(sender)

    if "@" not in email_address:
        return ""

    return normalize_domain(
        email_address.split("@", 1)[1]
    )


def get_link_domain(link):
    """
    Extract and normalize domain from URL.
    """

    try:
        parsed = urlparse(link)

        return normalize_domain(
            parsed.hostname or ""
        )

    except Exception:
        return ""


def extract_urls_from_text(text):
    """
    Extract URLs from email text.
    """

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


def is_trusted_domain(domain, trusted_domains):
    """
    Check whether domain belongs to a trusted organization.
    """

    domain = normalize_domain(domain)

    if not domain:
        return False

    return any(
        domain == trusted
        or domain.endswith("." + trusted)
        for trusted in trusted_domains
    )


def add_reason(reasons, reason):
    """
    Add a reason only once.
    """

    if reason and reason not in reasons:
        reasons.append(reason)


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze_email(sender, subject, body, links):
    """
    Analyze an email using:

    1. Rule-based security detection
    2. Behavioral suspicion detection
    3. Featherless AI analysis
    4. Safety floors for strong phishing indicators
    5. AI threat escalation for strong AI conclusions
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

    # --------------------------------------------------------
    # Extract URLs from body too
    # --------------------------------------------------------

    body_urls = extract_urls_from_text(body)

    for url in body_urls:
        if url not in links:
            links.append(url)

    # --------------------------------------------------------
    # Basic text
    # --------------------------------------------------------

    text = f"{subject} {body}".lower()

    sender_lower = sender.lower()

    display_name, sender_email = get_sender_parts(sender)

    sender_domain = get_domain_from_sender(sender)

    # ============================================================
    # TRUSTED DOMAINS
    # ============================================================

    trusted_domains = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "linkedin.com",
        "github.com",
    ]

    sender_trusted = is_trusted_domain(
        sender_domain,
        trusted_domains
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
    # 3B. CREDENTIAL HARVESTING
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

    if (
        has_credential_request
        and has_verification_request
    ):
        score += 30

        add_reason(
            reasons,
            "High-risk credential harvesting pattern: "
            "account verification combined with sensitive information request"
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
    ]

    found_shortened_url = False

    for link in links:

        hostname = get_link_domain(link)

        if hostname in shortened_domains:

            found_shortened_url = True

            score += 25

            add_reason(
                reasons,
                "Shortened URL detected"
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
                    "URL uses an IP address instead of a domain"
                )

                break

        except Exception:
            continue

    # ============================================================
    # 6. SUSPICIOUS @ SYMBOL / USERINFO
    # ============================================================

    for link in links:

        try:
            parsed = urlparse(link)

            if parsed.username or parsed.password:

                score += 25

                add_reason(
                    reasons,
                    "URL contains '@', which can hide the real destination"
                )

                break

        except Exception:
            continue

    # ============================================================
    # 7. HTTP CHECK
    # ============================================================

    found_http = False

    for link in links:

        try:
            parsed = urlparse(link)

            if parsed.scheme.lower() == "http":

                found_http = True

                score += 10

                add_reason(
                    reasons,
                    "Link does not use HTTPS"
                )

                break

        except Exception:
            continue

    # ============================================================
    # 8. EXCESSIVE EXCLAMATION MARKS
    # ============================================================

    if body.count("!") >= 3:

        score += 10

        add_reason(
            reasons,
            "Excessive exclamation marks detected"
        )

    # ============================================================
    # 9. EXCESSIVE CAPITALIZATION
    # ============================================================

    alphabetic_chars = [
        char
        for char in body
        if char.isalpha()
    ]

    if len(alphabetic_chars) >= 20:

        uppercase_chars = [
            char
            for char in body
            if char.isupper()
        ]

        uppercase_ratio = (
            len(uppercase_chars)
            / len(alphabetic_chars)
        )

        if uppercase_ratio >= 0.60:

            score += 5

            add_reason(
                reasons,
                "Excessive capitalization detected"
            )

    # ============================================================
    # 10. SENDER DOMAIN / IMPERSONATION
    # ============================================================

    has_support_identity = False

    if sender_domain:

        if sender_trusted:

            add_reason(
                reasons,
                f"Sender domain appears trusted: '{sender_domain}'"
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
            "it support",
        ]

        has_support_identity = any(
            word in sender_lower
            for word in impersonation_words
        )

        if (
            has_support_identity
            and not sender_trusted
        ):

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
            "protonmail.com",
        ]

        company_names = [
            "google",
            "microsoft",
            "apple",
            "amazon",
            "paypal",
            "linkedin",
            "github",
            "bank",
            "netflix",
            "instagram",
            "facebook",
        ]

        if sender_domain in free_email_domains:

            for company in company_names:

                if company in sender_lower:

                    score += 20

                    add_reason(
                        reasons,
                        f"Possible impersonation: '{company}' appears "
                        f"in sender name but email uses "
                        f"'{sender_domain}'"
                    )

                    break

    # ============================================================
    # 11. DISPLAY NAME / DOMAIN MISMATCH
    # ============================================================

    if display_name and sender_domain:

        company_names = [
            "google",
            "microsoft",
            "apple",
            "amazon",
            "paypal",
            "linkedin",
            "github",
            "netflix",
            "instagram",
            "facebook",
            "bank",
        ]

        display_lower = display_name.lower()

        for company in company_names:

            if company in display_lower:

                company_domain = None

                for trusted in trusted_domains:

                    if company in trusted:
                        company_domain = trusted
                        break

                if company_domain:

                    if not is_trusted_domain(
                        sender_domain,
                        [company_domain]
                    ):

                        score += 15

                        add_reason(
                            reasons,
                            f"Display name suggests '{company}' "
                            f"but sender domain is '{sender_domain}'"
                        )

                elif sender_domain not in trusted_domains:

                    score += 15

                    add_reason(
                        reasons,
                        f"Display name suggests '{company}' "
                        f"but sender domain is '{sender_domain}'"
                    )

                break

    # ============================================================
    # 12. SENDER DOMAIN VS LINK DOMAIN
    # ============================================================

    mismatched_link_domain = False

    if sender_domain and links:

        for link in links:

            link_domain = get_link_domain(link)

            if not link_domain:
                continue

            link_trusted = is_trusted_domain(
                link_domain,
                trusted_domains
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
                f"Sender domain '{sender_domain}' does not match "
                f"link domain '{link_domain}'"
            )

            break

    # ============================================================
    # 13. SUSPICIOUS DOMAIN PATTERNS
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
        r"security-",
    ]

    for link in links:

        domain = get_link_domain(link)

        for pattern in suspicious_patterns:

            if re.search(pattern, domain):

                score += 15

                add_reason(
                    reasons,
                    f"Suspicious domain pattern detected: '{domain}'"
                )

                break

        else:
            continue

        break

    # ============================================================
    # 14. LOOKALIKE DOMAIN DETECTION
    # ============================================================

    lookalike_words = {
        "paypal": [
            "paypa1",
            "pay-pal",
            "paypai",
        ],
        "google": [
            "goog1e",
            "google-login",
            "googleverify",
            "google-secure",
        ],
        "microsoft": [
            "micros0ft",
            "microsoft-login",
            "microsoftverify",
        ],
        "apple": [
            "app1e",
            "apple-login",
            "appleverify",
        ],
        "amazon": [
            "amaz0n",
            "amazon-login",
            "amazonverify",
        ],
        "linkedin": [
            "linkedln",
            "linkedin-login",
            "linkedinverify",
        ],
    }

    lookalike_domain_detected = False

    for link in links:

        domain = get_link_domain(link)

        for company, fake_variations in lookalike_words.items():

            for fake in fake_variations:

                if fake in domain:

                    lookalike_domain_detected = True

                    score += 25

                    add_reason(
                        reasons,
                        f"Possible lookalike domain detected: '{domain}'"
                    )

                    break

            if lookalike_domain_detected:
                break

        if lookalike_domain_detected:
            break

    # ============================================================
    # 15. GENERIC DOMAIN SIMILARITY
    # ============================================================

    if links:

        for link in links:

            domain = get_link_domain(link)

            if not domain:
                continue

            for trusted in trusted_domains:

                if domain == trusted:
                    continue

                similarity = SequenceMatcher(
                    None,
                    domain.split(".")[0],
                    trusted.split(".")[0]
                ).ratio()

                if (
                    similarity >= 0.80
                    and not is_trusted_domain(
                        domain,
                        trusted_domains
                    )
                ):

                    score += 20

                    add_reason(
                        reasons,
                        f"Domain closely resembles trusted domain "
                        f"'{trusted}'"
                    )

                    break

    # ============================================================
    # 16. SUSPICIOUS TLD
    # ============================================================

    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".buzz",
        ".zip",
        ".work",
        ".live",
        ".shop",
        ".support",
        ".online",
    ]

    for link in links:

        domain = get_link_domain(link)

        if any(
            domain.endswith(tld)
            for tld in suspicious_tlds
        ):

            score += 10

            add_reason(
                reasons,
                f"Suspicious top-level domain detected: '{domain}'"
            )

            break

    # ============================================================
    # 17. DEEP SUBDOMAINS
    # ============================================================

    for link in links:

        domain = get_link_domain(link)

        if domain:

            parts = domain.split(".")

            if len(parts) >= 5:

                score += 10

                add_reason(
                    reasons,
                    f"Unusually deep subdomain structure detected: '{domain}'"
                )

                break

    # ============================================================
    # 18. ENCODED URL
    # ============================================================

    for link in links:

        if (
            "%40" in link.lower()
            or "%2f" in link.lower()
            or "%3d" in link.lower()
            or "%3f" in link.lower()
        ):

            score += 10

            add_reason(
                reasons,
                "URL contains encoded characters that may obscure its destination"
            )

            break

    # ============================================================
    # 19. TOO MANY LINKS
    # ============================================================

    if len(links) >= 5:

        score += 10

        add_reason(
            reasons,
            "Email contains an unusually high number of links"
        )

    # ============================================================
    # 20. FINANCIAL / PAYMENT REQUEST
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
        "debit card",
    ]

    found_financial = any(
        word in text
        for word in financial_words
    )

    if found_financial:

        score += 10

        add_reason(
            reasons,
            "Financial or payment-related content detected"
        )

    # ============================================================
    # 21. ACCOUNT ACTION
    # ============================================================

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
        "validate",
    ]

    has_account_action = any(
        word in text
        for word in account_action_words
    )

    # ============================================================
    # 22. SENSITIVE REQUEST + EXTERNAL LINK
    # ============================================================

    if (
        found_sensitive
        and links
        and not sender_trusted
    ):

        score += 15

        add_reason(
            reasons,
            "Sensitive information request combined with "
            "an external link"
        )

    # ============================================================
    # 23. URGENCY + LINK
    # ============================================================

    if (
        found_urgency
        and links
    ):

        score += 10

        add_reason(
            reasons,
            "Urgent language combined with an external link"
        )

    # ============================================================
    # 24. PAYMENT + LINK
    # ============================================================

    if (
        found_financial
        and links
        and not sender_trusted
    ):

        score += 10

        add_reason(
            reasons,
            "Payment-related content combined with an external link"
        )

    # ============================================================
    # 25. STRONG CONTEXTUAL PHISHING
    # ============================================================

    strong_phishing_context = (
        has_account_action
        and found_urgency
        and links
        and not sender_trusted
    )

    if strong_phishing_context:

        score += 20

        add_reason(
            reasons,
            "Strong phishing context: account action, urgency, "
            "and external link from an untrusted sender"
        )

    # ============================================================
    # 26. ACCOUNT ACTION + DOMAIN MISMATCH
    # ============================================================

    if (
        has_account_action
        and mismatched_link_domain
    ):

        score += 10

        add_reason(
            reasons,
            "Account-related action requested through a "
            "domain that does not match the sender"
        )

    # ============================================================
    # 27. SUPPORT IDENTITY + LINK
    # ============================================================

    if (
        has_support_identity
        and links
        and not sender_trusted
    ):

        score += 10

        add_reason(
            reasons,
            "Security/support-style sender directs the "
            "recipient to an external link"
        )

    # ============================================================
    # 28. HIGH-RISK ACCOUNT PHISHING
    # ============================================================

    if (
        has_credential_request
        and has_verification_request
        and links
        and not sender_trusted
    ):

        score += 20

        add_reason(
            reasons,
            "High-risk account phishing pattern detected"
        )

    # ============================================================
    # 29. BEHAVIOR-BASED SUSPICION FLOOR
    # ============================================================

    behavior_floor = 0

    # Untrusted sender + account action + external link
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
            "Untrusted sender requests an account-related "
            "action through an external link"
        )

    # Untrusted sender + urgency + external link
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
            "Untrusted sender combines urgency with "
            "an external link"
        )

    # Financial request + external link
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
            "Untrusted sender combines a financial request "
            "with an external link"
        )

    # Sensitive information + external link
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
            "Untrusted sender requests sensitive information "
            "through an external link"
        )

    # Security/support identity + external link
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

        add_reason(
            reasons,
            "Security/support-style sender directs the "
            "recipient to an external link"
        )

    # Lookalike domain is inherently suspicious
    if lookalike_domain_detected:

        behavior_floor = max(
            behavior_floor,
            50
        )

    # IP address + account action
    if (
        found_ip_url
        and has_account_action
    ):

        behavior_floor = max(
            behavior_floor,
            70
        )

    # ============================================================
    # NEW FIX 1:
    # SENDER/LINK MISMATCH + PHISHING/ACCOUNT BEHAVIOR
    # ============================================================

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
            "Untrusted sender uses a mismatched external domain "
            "for an account or verification-related action"
        )

    # ============================================================
    # 30. FEATHERLESS AI ANALYSIS
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

        if not isinstance(
            ai_result,
            dict
        ):
            ai_result = {}

        ai_available = bool(
            ai_result.get(
                "ai_available",
                False
            )
        )

        try:
            ai_score = int(
                ai_result.get(
                    "risk_score",
                    0
                )
            )
        except (
            ValueError,
            TypeError
        ):
            ai_score = 0

        ai_score = max(
            0,
            min(
                ai_score,
                100
            )
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
        ai_score = 0

        ai_reason = ""

        attacker_intent = "Not determined"
        expected_user_action = "Not determined"
        potential_consequence = "Not determined"
        recommended_defense = "Manual review"

        add_reason(
            reasons,
            f"AI analysis failed; rule-based analysis used: {str(e)}"
        )

    # ============================================================
    # 31. COMBINE RULES + AI
    # ============================================================

    rule_score = score

    if ai_available:

        ai_combined_score = int(
            (rule_score * 0.7)
            + (ai_score * 0.3)
        )

        # AI is NOT allowed to reduce deterministic
        # rule-based security score.
        combined_score = max(
            ai_combined_score,
            rule_score
        )

    else:

        combined_score = rule_score

        add_reason(
            reasons,
            "AI analysis unavailable; rule-based analysis used"
        )

    # ============================================================
    # 32. APPLY BEHAVIOR FLOOR
    # ============================================================

    if behavior_floor > combined_score:

        combined_score = behavior_floor

        add_reason(
            reasons,
            f"Behavior-based risk floor applied: {behavior_floor}"
        )

    # ============================================================
    # 33. AI EXPLANATION
    # ============================================================

    if ai_available and ai_reason:

        add_reason(
            reasons,
            f"AI analysis: {ai_reason}"
        )

    # ============================================================
    # NEW FIX 2:
    # DOMAIN MISMATCH + PHISHING/ACCOUNT BEHAVIOR
    # ============================================================

    if (
        mismatched_link_domain
        and (
            has_account_action
            or found_phishing_phrase
        )
    ):

        combined_score = max(
            combined_score,
            60
        )

        add_reason(
            reasons,
            "Domain mismatch combined with phishing or "
            "account-related activity"
        )

    # ============================================================
    # NEW FIX 3:
    # STRONG AI THREAT + EXTERNAL LINK
    #
    # This fixes cases where AI correctly identifies a
    # dangerous email but gives a low numerical score.
    #
    # Examples:
    # - Malware Delivery + link
    # - Phishing + link
    # - Credential Theft + link
    # - Account Takeover + link
    # - AI recommends Quarantine
    # ============================================================

    if ai_available and links:

        ai_intent_lower = attacker_intent.lower().strip()
        ai_action_lower = expected_user_action.lower().strip()
        ai_consequence_lower = potential_consequence.lower().strip()
        ai_defense_lower = recommended_defense.lower().strip()

        strong_ai_intents = [
            "malware delivery",
            "phishing",
            "credential theft",
            "credential harvesting",
            "account takeover",
            "ransomware",
            "malicious link",
            "social engineering",
        ]

        strong_ai_consequences = [
            "malware infection",
            "account takeover",
            "credential theft",
            "credential compromise",
            "data theft",
            "financial loss",
            "identity theft",
            "system compromise",
        ]

        strong_ai_actions = [
            "click a verification link",
            "click the link",
            "click a malicious link",
            "enter credentials",
            "provide credentials",
            "enter your password",
            "enter sensitive information",
            "download",
            "open the attachment",
        ]

        ai_threat_detected = any(
            threat in ai_intent_lower
            for threat in strong_ai_intents
        )

        ai_consequence_detected = any(
            consequence in ai_consequence_lower
            for consequence in strong_ai_consequences
        )

        ai_action_detected = any(
            action in ai_action_lower
            for action in strong_ai_actions
        )

        ai_quarantine_detected = (
            "quarantine" in ai_defense_lower
        )

        # Strong AI intent + external link
        if ai_threat_detected:

            combined_score = max(
                combined_score,
                70
            )

            add_reason(
                reasons,
                "AI identified a high-risk threat type "
                f"('{attacker_intent}') associated with an external link"
            )

        # AI consequence indicates serious compromise
        if ai_consequence_detected:

            combined_score = max(
                combined_score,
                70
            )

            add_reason(
                reasons,
                "AI identified a potentially severe security consequence: "
                f"'{potential_consequence}'"
            )

        # Dangerous user action predicted by AI
        if (
            ai_action_detected
            and (
                ai_threat_detected
                or ai_consequence_detected
            )
        ):

            combined_score = max(
                combined_score,
                70
            )

            add_reason(
                reasons,
                "AI predicts a dangerous user action involving "
                "the external link"
            )

        # AI itself recommends quarantine
        if (
            ai_quarantine_detected
            and (
                ai_threat_detected
                or ai_consequence_detected
            )
        ):

            combined_score = max(
                combined_score,
                70
            )

            add_reason(
                reasons,
                "AI recommends quarantining the email due to "
                "its detected threat behavior"
            )

    # ============================================================
    # 34. FINAL SAFETY INDICATORS
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

    # Multiple strong indicators -> HIGH minimum
    if critical_indicators >= 2:

        combined_score = max(
            combined_score,
            40
        )

        add_reason(
            reasons,
            "Multiple high-risk security indicators detected"
        )

    # Credential harvesting + verification + link
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
            "Credential harvesting with an external link requires elevated risk"
        )

    # IP address + account action
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
            "IP-based URL combined with account action is highly dangerous"
        )

    # Lookalike + credential/account phishing
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
            "Lookalike domain combined with account or credential activity"
        )

    # ============================================================
    # 35. FINAL SCORE
    # ============================================================

    score = max(
        0,
        min(
            int(combined_score),
            100
        )
    )

    # ============================================================
    # 36. RISK LEVEL
    # ============================================================

    if score >= 70:

        risk_level = "CRITICAL"

    elif score >= 40:

        risk_level = "HIGH"

    elif score >= 20:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # ============================================================
    # RESULT
    # ============================================================

    return {
        "risk_score": score,

        "risk_level": risk_level,

        "reasons": reasons,

        "intent": {
            "attacker_intent": attacker_intent,
            "expected_user_action": expected_user_action,
            "potential_consequence": potential_consequence,
            "recommended_defense": recommended_defense,
        },

        "ai_analysis": {
            "available": ai_available,
            "score": ai_score,
            "reason": ai_reason,
        }
    }

