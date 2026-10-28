"""What does the dashboard's "Uncertain" label do on the test split? (descriptive, nothing is tuned)

The rule (dash_common.verdict) is fixed in advance: a scan is Uncertain when the selected model's score is within
0.40-0.60, or when the three models disagree about which side of 0.5 the file is. It changes no score and no model,
and the official test metrics in outputs/metrics.csv are untouched. This script only reports, per selected model,
how many test files the rule sets aside and how many of that model's mistakes it catches.
Run from the project root:  python src/evaluate_triage.py     (writes outputs/triage_check.md)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dash_common as dc  # noqa: E402


def main():
    y, scores = dc.test_scores()  # saved models on the held-out test split (same predictions as outputs/metrics.csv)
    names = list(scores)
    rows = []
    for primary in names:
        err = unc_err = unc_ok = dec_err = dec = 0
        for i in range(len(y)):
            label, _ = dc.verdict({n: float(scores[n][i]) for n in names}, primary)
            wrong = (scores[primary][i] >= 0.5) != bool(y[i])
            if label == dc.LABEL_UNC:
                unc_err += wrong
                unc_ok += not wrong
            else:
                dec += 1
                dec_err += wrong
            err += wrong
        unc = unc_err + unc_ok
        rows.append((primary, len(y), err, unc, unc_err, dec, dec_err))
    md = ["# Effect of the Uncertain label on the test split (1,042 files)", "",
          "Descriptive only: the rule was fixed before measuring (score within 0.40-0.60, or the three models disagree) and "
          "no model, score or official metric changes. 'Errors' are the selected model's mistakes at the usual 0.5 "
          "threshold (false alarms plus misses).", "",
          "| Selected model | Errors | Files marked Uncertain | Errors among those | Errors caught | Decided files | Errors among decided | Error rate when decided |",
          "|---|---|---|---|---|---|---|---|"]
    for p, n, err, unc, ue, dec, de in rows:
        md.append(f"| {p} | {err} | {unc} ({unc / n:.1%}) | {ue} | {ue / max(err, 1):.0%} | {dec} | {de} | "
                  f"{de / max(dec, 1):.2%} (was {err / n:.2%}) |")
    text = "\n".join(md)
    (Path(__file__).resolve().parent.parent / "outputs" / "triage_check.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
