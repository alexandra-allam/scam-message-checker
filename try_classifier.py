"""Hand test (build plan step 1): run 5 test messages once and print the results."""

import csv

from advice import advice_for
from classifier import classify

PICKS = ["T01", "T07", "T27", "T37", "T43"]


def main():
    with open("test-messages.csv", newline="", encoding="utf-8") as f:
        rows = {r["id"]: r for r in csv.DictReader(f)}

    for test_id in PICKS:
        row = rows[test_id]
        result = classify(row["message"], row["channel"] or None, row["sender_shown"] or None)
        print("=" * 70)
        print(f"{test_id}  ({row['type']}, expected {row['expected_verdict']})")
        print(f"Message: {row['message']}")
        print("-" * 70)
        if result["error"]:
            print(f"ERROR: {result['error']}")
            continue
        print(f"Verdict:       {result['verdict']}")
        print(f"Impersonating: {result['impersonating']}")
        for sign, why in zip(result["signs"], result["explanations"]):
            print(f"  - {sign}: {why}")
        print(f"Advice (fixed text):\n{advice_for(result['verdict'])}")


if __name__ == "__main__":
    main()
