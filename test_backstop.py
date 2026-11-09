"""Simulated backstop tests: no API calls, fake AI answers.

Run with:  python test_backstop.py
"""

from advice import ADVICE
from backstop import apply_backstop


def fake_ai(verdict, error=None):
    return {"verdict": verdict, "signs": [], "explanations": [],
            "impersonating": "none" if verdict else None, "error": error}


SAFE_ACCOUNT = ("We have detected suspicious activity on your account. To protect your money "
                "we have set up a temporary safe account. Please transfer your balance today.")


def test_overrides_fake_no_strong_signs_on_safe_account():
    out = apply_backstop(SAFE_ACCOUNT, fake_ai("no_strong_signs"))
    assert out["ai_verdict"] == "no_strong_signs"
    assert out["verdict"] == "likely_scam"
    assert out["backstop_changed"] is True
    assert any("safe account" in r for r in out["backstop_reasons"])
    assert out["advice"] == ADVICE["likely_scam"]


def test_error_becomes_be_careful_never_no_strong_signs():
    out = apply_backstop("Your parcel will be delivered today.", fake_ai(None, error="invalid output"))
    assert out["verdict"] == "be_careful"
    assert out["fallback_from_error"] is True
    assert out["advice"] == ADVICE["be_careful"]


def test_error_plus_strong_pattern_becomes_likely_scam():
    out = apply_backstop(SAFE_ACCOUNT, fake_ai(None, error="api: network error"))
    assert out["verdict"] == "likely_scam"


def test_never_less_cautious():
    out = apply_backstop("Your Ocado delivery slot is 18:00-19:00.", fake_ai("likely_scam"))
    assert out["verdict"] == "likely_scam"
    assert out["backstop_changed"] is False


def test_caution_pattern_raises_only_to_be_careful():
    msg = "Royal Mail: pay £1.45 to rebook delivery: royalmail-redeliver-uk.com/pay"
    assert apply_backstop(msg, fake_ai("no_strong_signs"))["verdict"] == "be_careful"
    out = apply_backstop(msg, fake_ai("be_careful"))
    assert out["verdict"] == "be_careful" and out["backstop_changed"] is False


def test_bank_warning_is_not_a_trigger():
    msg = "Barclays: we will never ask you to move money to a safe account."
    out = apply_backstop(msg, fake_ai("no_strong_signs"))
    assert out["verdict"] == "no_strong_signs"
    assert out["backstop_changed"] is False


if __name__ == "__main__":
    tests = [(n, f) for n, f in globals().items() if n.startswith("test_")]
    for name, fn in tests:
        fn()
        print(f"PASS  {name}")
    print(f"\nAll {len(tests)} backstop tests passed.")
