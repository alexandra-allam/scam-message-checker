"""Scam Message Checker: Streamlit page (build plan step 5).

Run locally:   streamlit run app.py
Messages are never stored or logged. Only a count of checks per day is kept,
in memory, to protect the API credit.
"""

import html
import os
import re
import threading
from datetime import datetime
from zoneinfo import ZoneInfo

import streamlit as st

from advice import ADVICE
from backstop import apply_backstop
from classifier import SIGNS

MAX_CHARS = 2000
DAILY_LIMIT = 50
REPO_URL = "https://github.com/alexandra-allam/scam-message-checker"

CHANNELS = {"Text message": "sms", "Email": "email", "WhatsApp": "whatsapp", "Other": "other"}

VERDICT_LABELS = {
    "likely_scam": "Likely scam",
    "be_careful": "Be careful",
    "no_strong_signs": "No strong warning signs",
}

# Plain, high-contrast colours (text, background, border). No green: we never imply "safe".
VERDICT_COLOURS = {
    "likely_scam": ("#7a0000", "#fde8e8", "#b00000"),
    "be_careful": ("#5c3a00", "#fff4d6", "#b36b00"),
    "no_strong_signs": ("#0b2a5b", "#e8eef8", "#1f4e99"),
}

st.set_page_config(page_title="Scam Message Checker", page_icon="🔍", layout="centered")

st.markdown(
    """
<style>
html, body, [class*="css"], .stMarkdown, p, li, label, textarea, input, select, button {
    font-size: 21px !important; line-height: 1.55 !important;
}
h1 { font-size: 40px !important; }
h2, h3 { font-size: 28px !important; }
textarea { color: #111 !important; }
.stButton button { font-size: 24px !important; padding: 0.6em 1.6em !important; font-weight: 700; }
.note { background: #f2f2f2; border-left: 6px solid #333; padding: 0.8em 1em; margin: 0.5em 0 1em; color: #111; }
.card { border: 4px solid; border-radius: 10px; padding: 1.2em 1.4em; margin: 1em 0; }
.verdict { font-size: 40px; font-weight: 800; margin: 0 0 0.3em; }
.footer { font-size: 17px !important; color: #333; border-top: 1px solid #999; margin-top: 2.5em; padding-top: 0.8em; }
.footer p, .footer a { font-size: 17px !important; }
</style>
""",
    unsafe_allow_html=True,
)


# ---- API key: st.secrets when deployed, .env locally ------------------------

def _load_api_key():
    try:
        if "ANTHROPIC_API_KEY" in st.secrets:
            os.environ["ANTHROPIC_API_KEY"] = st.secrets["ANTHROPIC_API_KEY"]
    except Exception:
        pass  # no secrets file locally: classifier falls back to .env


_load_api_key()


# ---- Daily cap for the whole app (in memory, shared by all visitors) --------

@st.cache_resource
def _usage():
    return {"date": None, "count": 0, "lock": threading.Lock()}


def take_a_check() -> bool:
    """Count one check. Returns False if today's limit has been reached."""
    usage = _usage()
    today = datetime.now(ZoneInfo("Europe/London")).date()
    with usage["lock"]:
        if usage["date"] != today:
            usage["date"], usage["count"] = today, 0
        if usage["count"] >= DAILY_LIMIT:
            return False
        usage["count"] += 1
        return True


# ---- Checking ---------------------------------------------------------------

def check(message: str, channel: str, sender: str) -> dict:
    """Classifier + backstop. Any failure becomes 'be careful', never an error."""
    try:
        from classifier import classify

        ai = classify(message, channel, sender or None)
    except Exception:
        ai = {"verdict": None, "signs": [], "explanations": [], "impersonating": None,
              "error": "failed"}
    try:
        return apply_backstop(message, ai)
    except Exception:
        return {"verdict": "be_careful", "signs": [], "explanations": [],
                "fallback_from_error": True, "backstop_changed": False,
                "backstop_reasons": [], "advice": ADVICE["be_careful"]}


_SAFE_WORD = re.compile(r"\bsafe\b(?!\s+account)", re.IGNORECASE)


def sign_lines(result: dict) -> list[tuple[str, str]]:
    """(heading, explanation) pairs to show. Headings are the fixed labels."""
    lines = []
    for code, why in zip(result.get("signs", []), result.get("explanations", [])):
        label = SIGNS.get(code)
        if not label:
            continue
        # Never show the word "safe" (except the phrase "safe account")
        if _SAFE_WORD.search(why or ""):
            why = ""
        lines.append((label, why))
    return lines


def show_result(result: dict):
    verdict = result["verdict"]
    text, bg, border = VERDICT_COLOURS[verdict]
    parts = [f'<div class="card" style="color:{text}; background:{bg}; border-color:{border};">',
             f'<p class="verdict">{VERDICT_LABELS[verdict]}</p>']

    lines = sign_lines(result)
    if result.get("fallback_from_error"):
        parts.append("<p>We couldn't finish checking this message, so treat it with care.</p>")
    if lines:
        parts.append("<p><strong>Warning signs we found:</strong></p><ul>")
        for label, why in lines:
            item = f"<strong>{html.escape(label, quote=False)}</strong>"
            if why:
                item += f"<br>{html.escape(why, quote=False)}"
            parts.append(f"<li>{item}</li>")
        parts.append("</ul>")
    if result.get("backstop_changed") and result.get("backstop_reasons"):
        parts.append("<p><strong>Also:</strong></p><ul>")
        parts += [f"<li>{html.escape(r, quote=False)}</li>" for r in result["backstop_reasons"]]
        parts.append("</ul>")
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)

    st.subheader("What to do next")
    st.markdown(ADVICE[verdict])


# ---- Page -------------------------------------------------------------------

st.title("Scam Message Checker")
st.markdown(
    "Not sure about a text, email or WhatsApp message? Paste it below. "
    "We'll look for warning signs of a scam and tell you what to do next."
)
st.markdown(
    '<div class="note"><strong>Before you paste:</strong> please remove names, addresses '
    "and account numbers. We don't keep your message.</div>",
    unsafe_allow_html=True,
)

with st.form("check"):
    message = st.text_area("The message", height=200, max_chars=MAX_CHARS,
                           placeholder="Paste the message here")
    where = st.selectbox("Where did it come from?", list(CHANNELS))
    sender = st.text_input("Who is it from? (optional)",
                           placeholder="For example: Royal Mail, a phone number, or a name")
    submitted = st.form_submit_button("Check this message")

if submitted:
    if not message.strip():
        st.markdown("Please paste a message into the box first.")
    elif len(message) > MAX_CHARS:
        st.markdown(f"That message is too long. Please paste up to {MAX_CHARS:,} characters.")
    elif not take_a_check():
        st.markdown(
            "**The checker has reached its limit for today.** Please try again tomorrow. "
            "In the meantime, here's what to do if you're unsure:"
        )
        st.markdown(ADVICE["be_careful"])
    else:
        with st.spinner("Checking..."):
            result = check(message, CHANNELS[where], sender.strip()[:200])
        show_result(result)

st.markdown(
    f'<div class="footer"><p>This is a personal portfolio project, not an official service. '
    f"It can't be sure whether a message is genuine. "
    f'<a href="{REPO_URL}" target="_blank">See the code on GitHub</a>.</p></div>',
    unsafe_allow_html=True,
)
