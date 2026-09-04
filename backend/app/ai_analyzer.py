import os
import json

from dotenv import load_dotenv
from openai import OpenAI


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

api_key = os.getenv("FEATHERLESS_API_KEY")
model = os.getenv("FEATHERLESS_MODEL")


client = OpenAI(
    base_url="https://api.featherless.ai/v1",
    api_key=api_key,
)


# ============================================================
# AI EMAIL ANALYZER
# ============================================================

def analyze_with_ai(sender, subject, body, links):
    """
    Uses Featherless AI to analyze an email for:

    - Phishing
    - Social engineering
    - Impersonation
    - Credential theft
    - Financial fraud
    - Malware delivery
    - Business Email Compromise
    - Attacker intent
    - Expected victim action
    - Potential consequence
    - Recommended defense
    """

    prompt = f"""
You are an expert cybersecurity email threat analyst.

Analyze the following email carefully.

Your job is not only to determine whether the email is dangerous,
but also to understand the ATTACK CHAIN:

1. What does the attacker want?
2. What action does the attacker want the victim to perform?
3. What could happen if the victim performs that action?
4. What defense should be recommended?

--------------------------------------------------
EMAIL INFORMATION
--------------------------------------------------

Sender:
{sender}

Subject:
{subject}

Email Body:
{body}

Links:
{links}

--------------------------------------------------
ANALYSIS AREAS
--------------------------------------------------

Look for:

1. Phishing
2. Social engineering
3. Impersonation
4. Credential theft
5. Password or OTP harvesting
6. Account takeover
7. Financial fraud
8. Payment scams
9. Gift card scams
10. Business Email Compromise
11. Malware delivery
12. Data theft
13. Suspicious links
14. Urgency and pressure
15. Requests for sensitive information
16. Fake account verification
17. Fake security alerts
18. Fake invoices or payment requests

--------------------------------------------------
ATTACKER INTENT
--------------------------------------------------

Choose the most likely attacker objective.

Examples:

- Credential Theft
- Account Takeover
- Financial Fraud
- Payment Fraud
- Business Email Compromise
- Identity Impersonation
- Data Theft
- Malware Delivery
- Social Engineering
- Scam
- No Malicious Intent

--------------------------------------------------
EXPECTED USER ACTION
--------------------------------------------------

Determine what the attacker wants the victim to do.

Examples:

- Click a verification link
- Enter username and password
- Enter an OTP
- Transfer money
- Make a payment
- Open an attachment
- Download a file
- Reply with sensitive information
- Call a phone number
- Share confidential information
- No risky action expected

--------------------------------------------------
POTENTIAL CONSEQUENCE
--------------------------------------------------

Determine the likely consequence.

Examples:

- Account takeover
- Financial loss
- Credential theft
- Data exposure
- Malware infection
- Identity theft
- Unauthorized transaction
- Business compromise
- No significant security consequence

--------------------------------------------------
RECOMMENDED DEFENSE
--------------------------------------------------

Choose one:

- Quarantine
- Block and alert
- Manual review
- Warn user
- Allow email

--------------------------------------------------
OUTPUT
--------------------------------------------------

Return ONLY valid JSON.

Use exactly this structure:

{{
    "risk_score": 0,
    "risk_level": "LOW",
    "reason": "Short explanation of why the email is dangerous or safe.",
    "attacker_intent": "Credential Theft",
    "expected_user_action": "Click a verification link and enter credentials",
    "potential_consequence": "Account takeover",
    "recommended_defense": "Quarantine"
}}

Risk levels:

0-19 = LOW
20-39 = MEDIUM
40-69 = HIGH
70-100 = CRITICAL

Important:

- Do not include markdown.
- Do not include text outside JSON.
- Keep the reason concise.
- Base the analysis on the actual email content.
- Do not assume an email is malicious just because it contains a link.
- Look for combinations of signals.
"""


    # ========================================================
    # CALL FEATHERLESS AI
    # ========================================================

    try:

        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=400,
            temperature=0
        )

        result = response.choices[0].message.content.strip()


        # ====================================================
        # REMOVE MARKDOWN CODE FENCES
        # ====================================================

        result = result.replace("```json", "")
        result = result.replace("```", "")
        result = result.strip()


        # ====================================================
        # PARSE JSON
        # ====================================================

        data = json.loads(result)


        # ====================================================
        # VALIDATE SCORE
        # ====================================================

        score = int(data.get("risk_score", 0))

        score = max(0, min(100, score))


        # ====================================================
        # CALCULATE RISK LEVEL
        # ====================================================

        if score >= 70:
            level = "CRITICAL"

        elif score >= 40:
            level = "HIGH"

        elif score >= 20:
            level = "MEDIUM"

        else:
            level = "LOW"


        # ====================================================
        # GET INTENT DATA
        # ====================================================

        attacker_intent = data.get(
            "attacker_intent",
            "Not determined"
        )

        expected_user_action = data.get(
            "expected_user_action",
            "Not determined"
        )

        potential_consequence = data.get(
            "potential_consequence",
            "Not determined"
        )

        recommended_defense = data.get(
            "recommended_defense",
            "Manual review"
        )

        reason = data.get(
            "reason",
            "AI analysis completed"
        )


        # ====================================================
        # RETURN RESULT
        # ====================================================

        return {
            "risk_score": score,
            "risk_level": level,
            "reason": reason,

            "attacker_intent": attacker_intent,
            "expected_user_action": expected_user_action,
            "potential_consequence": potential_consequence,
            "recommended_defense": recommended_defense,

            "ai_available": True
        }


    # ========================================================
    # AI FAILURE
    # ========================================================

    except Exception as e:

        print("AI Analyzer Error:", e)


        # IMPORTANT:
        # Do NOT return LOW here.
        #
        # Returning LOW when AI fails could make a dangerous
        # email appear safe.
        #
        # The rule-based ZeroGuard analyzer will continue
        # analyzing the email.

        return {
            "risk_score": 0,
            "risk_level": "UNAVAILABLE",
            "reason": "AI analysis unavailable",

            "attacker_intent": "AI analysis unavailable",
            "expected_user_action": "Unknown",
            "potential_consequence": "Unknown",
            "recommended_defense": "Use rule-based analysis",

            "ai_available": False
        }