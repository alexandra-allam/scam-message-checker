"""Evaluation (build plan step 2).

Runs every message in test-messages.csv 3 times through the classifier,
saves results/run-YYYY-MM-DD-HHMM.csv, appends a line to results/run-log.csv,
and prints the section 5 summary table.

Usage:
    python evaluate.py --note "first version"
"""

import argparse
import csv
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from classifier import EFFORT, MODEL, classify

RUNS = 3
WORKERS = 5
TEST_FILE = "test-messages.csv"
RESULTS_DIR = "results"
RUN_LOG = os.path.join(RESULTS_DIR, "run-log.csv")


def is_scam_like(row):
    """Should never be rated no_strong_signs."""
    return row["type"] != "genuine" and row["expected_verdict"] in ("likely_scam", "be_careful")


def is_genuine_like(row):
    """Should never be rated likely_scam."""
    return row["type"] == "genuine" or row["expected_verdict"] == "no_strong_signs"


def run_one(row):
    result = classify(row["message"], row["channel"] or None, row["sender_shown"] or None)
    return result["verdict"] or "error", result["error"]


def output_path(now):
    base = os.path.join(RESULTS_DIR, f"run-{now:%Y-%m-%d-%H%M}")
    path, n = base + ".csv", 2
    while os.path.exists(path):
        path, n = f"{base}-{n}.csv", n + 1
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--note", required=True, help='What changed before this run, e.g. "first version"')
    args = parser.parse_args()

    with open(TEST_FILE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    jobs = [(row, run) for row in rows for run in range(RUNS)]
    print(f"Running {len(rows)} messages x {RUNS} runs = {len(jobs)} calls on {MODEL} (effort {EFFORT})...")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        outputs = list(pool.map(lambda job: run_one(job[0]), jobs))

    verdicts = {}  # id -> [verdict per run]
    error_msgs = []
    for (row, _), (verdict, err) in zip(jobs, outputs):
        verdicts.setdefault(row["id"], []).append(verdict)
        if err:
            error_msgs.append(f"{row['id']}: {err}")

    # ---- per-message results ----
    results = []
    for row in rows:
        v = verdicts[row["id"]]
        results.append({
            "id": row["id"],
            "type": row["type"],
            "expected_verdict": row["expected_verdict"],
            **{f"run{i + 1}": v[i] for i in range(RUNS)},
            "missed_scam": is_scam_like(row) and "no_strong_signs" in v,
            "no_answer_on_scam": is_scam_like(row) and "error" in v,
            "false_alarm": is_genuine_like(row) and "likely_scam" in v,
            "consistent": len(set(v)) == 1,
            "errors": v.count("error"),
        })

    os.makedirs(RESULTS_DIR, exist_ok=True)
    now = datetime.now()
    path = output_path(now)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)

    # ---- metrics (section 5) ----
    by_id = {r["id"]: r for r in rows}
    total_runs = len(jobs)
    all_runs = [(r["id"], v) for r in results for v in (r[f"run{i + 1}"] for i in range(RUNS))]

    missed_ids = [r["id"] for r in results if r["missed_scam"]]
    missed_runs = sum(1 for i, v in all_runs if is_scam_like(by_id[i]) and v == "no_strong_signs")
    false_ids = [r["id"] for r in results if r["false_alarm"]]
    false_runs = sum(1 for i, v in all_runs if is_genuine_like(by_id[i]) and v == "likely_scam")
    exact_runs = sum(1 for i, v in all_runs if v == by_id[i]["expected_verdict"])
    changed_ids = [r["id"] for r in results if not r["consistent"]]
    injection_runs = [(i, v) for i, v in all_runs if by_id[i]["type"] == "injection"]
    # An error is not the AI being tricked, so it is counted separately.
    injection_fail = [(i, v) for i, v in injection_runs if v not in ("likely_scam", "error")]
    injection_errors = [(i, v) for i, v in injection_runs if v == "error"]
    no_answer_ids = [r["id"] for r in results if r["no_answer_on_scam"]]
    no_answer_runs = sum(1 for i, v in all_runs if is_scam_like(by_id[i]) and v == "error")
    error_count = sum(r["errors"] for r in results)

    exact_pct = 100 * exact_runs / total_runs
    changed_pct = 100 * len(changed_ids) / len(results)

    def ids(lst):
        return ", ".join(lst) if lst else "-"

    table = [
        ("Missed scams (target 0)", f"{len(missed_ids)} messages, {missed_runs} runs", ids(missed_ids)),
        ("No answer on a scam (target 0)", f"{len(no_answer_ids)} messages, {no_answer_runs} runs", ids(no_answer_ids)),
        ("False alarms", f"{len(false_ids)} messages, {false_runs} runs", ids(false_ids)),
        ("Exact match", f"{exact_runs}/{total_runs} runs ({exact_pct:.0f}%)", ""),
        ("Consistency: changed", f"{len(changed_ids)}/{len(results)} messages ({changed_pct:.0f}%)", ids(changed_ids)),
        ("Injection: verdict changed (target 0)", f"{len(injection_fail)}/{len(injection_runs)} runs",
         ids(sorted({i for i, _ in injection_fail}))),
        ("Injection: errors (no answer)", f"{len(injection_errors)}/{len(injection_runs)} runs",
         ids(sorted({i for i, _ in injection_errors}))),
        ("Errors", f"{error_count}/{total_runs} runs", ""),
    ]
    w1 = max(len(t[0]) for t in table)
    w2 = max(len(t[1]) for t in table)
    print()
    print(f"{'Metric':<{w1}}  {'Result':<{w2}}  Messages")
    print(f"{'-' * w1}  {'-' * w2}  --------")
    for name, value, detail in table:
        print(f"{name:<{w1}}  {value:<{w2}}  {detail}")
    if error_msgs:
        print("\nErrors:")
        for m in error_msgs:
            print(f"  {m}")
    print(f"\nSaved {path}")

    # ---- run log ----
    log_row = {
        "timestamp": now.strftime("%Y-%m-%d %H:%M"),
        "file": os.path.basename(path),
        "note": args.note,
        "model": MODEL,
        "effort": EFFORT,
        "missed_scam_messages": len(missed_ids),
        "missed_scam_runs": missed_runs,
        "no_answer_on_scam_messages": len(no_answer_ids),
        "no_answer_on_scam_runs": no_answer_runs,
        "false_alarm_messages": len(false_ids),
        "false_alarm_runs": false_runs,
        "exact_match_pct": f"{exact_pct:.1f}",
        "changed_across_runs_pct": f"{changed_pct:.1f}",
        "injection_failures": len(injection_fail),
        "injection_errors": len(injection_errors),
        "errors": error_count,
    }
    # Read earlier runs so new metric columns can be added without misaligning old rows
    # (old rows get blanks for columns that didn't exist yet).
    old_rows, fieldnames = [], list(log_row)
    if os.path.exists(RUN_LOG):
        with open(RUN_LOG, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            old_rows = list(reader)
            old_fields = reader.fieldnames or []
        fieldnames = old_fields + [k for k in log_row if k not in old_fields]
    with open(RUN_LOG, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, restval="")
        writer.writeheader()
        writer.writerows(old_rows + [log_row])
    print(f"Logged in {RUN_LOG}: \"{args.note}\"")


if __name__ == "__main__":
    main()
