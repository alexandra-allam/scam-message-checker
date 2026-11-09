"""Rule-based backstop (build plan step 4, brief section 3 rule 3).

Simple keyword and pattern checks that run after the AI. They can only make
the verdict MORE cautious, never less:
  - a "strong" pattern raises the verdict to at least likely_scam
  - a "caution" pattern raises the verdict to at least be_careful
If the classifier returned an error, the final verdict is be_careful, so an
error can never look like "no strong warning signs".

The reasons are fixed plain-English text, never written by AI.
"""

from __future__ import annotations

import re

from advice import advice_for

# Lower number = less cautious. The backstop only ever moves up this scale.
CAUTION_ORDER = {"no_strong_signs": 0, "be_careful": 1, "likely_scam": 2}

STRONG = "likely_scam"
CAUTION = "be_careful"

_LINK = re.compile(
    r"(https?://|www\.)\S+"
    r"|\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|co\.uk|uk|net|org|info|top|help|co|xyz|online|site|io|me)\b(/\S*)?",
    re.IGNORECASE,
)
_FEE = re.compile(
    r"\b(pay|paying|payment|fee|fees|charge|postage)\b|£\s?\d|€\s?\d|\b\d+[.,]\d{2}\s?(eur|gbp|usd)\b",
    re.IGNORECASE,
)
_NEVER = re.compile(r"\b(never|will not|won't)\b", re.IGNORECASE)
_SENTENCES = re.compile(r"[^.!?\n]+")

_GIFT_CARD_REQUEST = "It asks for gift cards or gift card codes."
_GIFT_CARD_MENTION = "It mentions gift cards."

# (pattern, level, plain-English reason)
_PHRASES = [
    (re.compile(r"\bsafe account\b", re.I), STRONG,
     "It mentions moving money to a \"safe account\". Banks never ask you to do this."),
    (re.compile(r"\b(keep (it|this) (between us|quiet|to yourself)|(do not|don't|dont) (tell|discuss|mention)\b)", re.I), STRONG,
     "It asks you to keep it secret or not to tell anyone."),
    (re.compile(r"\b(buy|send|get|purchase)\b[^.!?\n]*\bgift ?cards?\b|\bgift ?cards?\b[^.!?\n]*\bcodes?\b", re.I), STRONG,
     _GIFT_CARD_REQUEST),
    (re.compile(r"\bgift ?cards?\b", re.I), CAUTION,
     _GIFT_CARD_MENTION),
    (re.compile(r"\bnew (phone )?number\b", re.I), CAUTION,
     "Someone says they have a new number."),
    (re.compile(r"\b(crypto|cryptocurrency|bitcoin|btc)\b", re.I), CAUTION,
     "It mentions crypto or bitcoin."),
]


def _negated(match_sentence: str) -> bool:
    """True for warnings like 'we will never ask you to move money to a safe account'."""
    return bool(_NEVER.search(match_sentence))


def check_message(message: str) -> list[tuple[str, str]]:
    """Return a list of (level, reason) for every pattern found in the message."""
    hits: list[tuple[str, str]] = []
    sentences = _SENTENCES.findall(message or "")
    for pattern, level, reason in _PHRASES:
        matching = [s for s in sentences if pattern.search(s)]
        if not matching:
            continue
        # A sentence like "we will never ask you to ..." is a warning, not a request.
        if all(_negated(s) for s in matching):
            continue
        hits.append((level, reason))
    if _LINK.search(message or "") and _FEE.search(message or ""):
        hits.append((CAUTION, "It has a link and mentions a payment, fee or sum of money."))
    # If it asks for gift cards, "mentions gift cards" adds nothing
    if any(r == _GIFT_CARD_REQUEST for _, r in hits):
        hits = [(l, r) for l, r in hits if r != _GIFT_CARD_MENTION]
    # One reason per text, keeping the most cautious level
    seen: dict[str, str] = {}
    for level, reason in hits:
        if reason not in seen or CAUTION_ORDER[level] > CAUTION_ORDER[seen[reason]]:
            seen[reason] = level
    return [(level, reason) for reason, level in seen.items()]


def apply_backstop(message: str, ai_result: dict) -> dict:
    """Combine the AI result with the backstop. Returns the final result:

    verdict, signs, explanations, impersonating  - final values shown to the user
    ai_verdict        - what the AI said (None if it errored)
    error             - the classifier error, if any
    fallback_from_error - True if the AI errored and be_careful was used instead
    backstop_changed  - True if the backstop raised the verdict
    backstop_reasons  - fixed plain-English reasons for any patterns found
    advice            - fixed advice text for the final verdict
    """
    ai_verdict = ai_result.get("verdict")
    error = ai_result.get("error")
    hits = check_message(message)
    reasons = [reason for _, reason in hits]

    if error or ai_verdict not in CAUTION_ORDER:
        verdict = CAUTION
        fallback = True
    else:
        verdict = ai_verdict
        fallback = False

    floor = max((CAUTION_ORDER[level] for level, _ in hits), default=0)
    changed = False
    if floor > CAUTION_ORDER[verdict]:
        verdict = next(v for v, n in CAUTION_ORDER.items() if n == floor)
        changed = True

    return {
        "verdict": verdict,
        "signs": ai_result.get("signs") or [],
        "explanations": ai_result.get("explanations") or [],
        "impersonating": ai_result.get("impersonating"),
        "ai_verdict": ai_verdict,
        "error": error,
        "fallback_from_error": fallback,
        "backstop_changed": changed,
        "backstop_reasons": reasons,
        "advice": advice_for(verdict),
    }
