"""Fixed "what to do next" advice, one block per verdict.

Copied word for word from PROJECT_BRIEF.md section 4. This text is never
written or changed by AI. Check it against official sources (NCSC, Report
Fraud, Stop! Think Fraud) before publishing.
"""

ADVICE = {
    "likely_scam": (
        "This message has strong signs of a scam. Don't click any links, reply, "
        "or call numbers in the message.\n"
        "- Text message: forward it to 7726 (free).\n"
        "- Email: forward it to report@phishing.gov.uk.\n"
        "- If you've already clicked, paid or shared details: call your bank "
        "straight away on 159, or the number on the back of your card. Then "
        "report it to Report Fraud at reportfraud.police.uk or 0300 123 2040 "
        "(England, Wales and Northern Ireland). In Scotland, call Police "
        "Scotland on 101."
    ),
    "be_careful": (
        "This message has some warning signs. Don't use any links or numbers in "
        "it. If it claims to be from an organisation, contact them using details "
        "you already trust, like their official website, app, or the number on "
        "your card or a bill. If it claims to be from family, call them on the "
        "number you already have for them."
    ),
    "no_strong_signs": (
        "We didn't find strong warning signs, but no tool can be sure a message "
        "is genuine. If it asks you to pay, log in or share details, check with "
        "the organisation directly using contact details you already trust."
    ),
}


def advice_for(verdict: str) -> str:
    """Return the fixed advice for a verdict. Unknown verdicts get 'be careful'."""
    return ADVICE.get(verdict, ADVICE["be_careful"])
