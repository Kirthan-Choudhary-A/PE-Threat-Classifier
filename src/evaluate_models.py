"""Final evaluation of LR / DT / RF on the TEST split (the only stage that opens it). No tuning, no retraining."""
import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve, ConfusionMatrixDisplay)

SEED = 42  # no randomness is used here; kept for the project convention
CAT = "packer_type"
NAMES = ["logistic_regression", "decision_tree", "random_forest"]

# same feature list / X construction as src/train_models.py
feats = []
for line in open("outputs/selected_features.txt", encoding="utf-8"):
    line = line.strip()
    if not line and feats:
        break
    if line and not line.startswith("#"):
        feats.append(line)
assert len(feats) == 58, len(feats)
num = [c for c in feats if c != CAT]

X_test = pd.read_csv("data/X_test.csv")[feats]
X_test[num] = X_test[num].apply(pd.to_numeric)
y_test = pd.read_csv("data/y_test.csv")["class"].to_numpy()
y_train = pd.read_csv("data/y_train.csv")["class"].to_numpy()
cv = pd.read_csv("outputs/cv_results.csv").set_index("model")
best = cv["cv_f1_mean"].idxmax()  # chosen by CV F1, never by test score
print(f"test n={len(y_test)}, malware={int(y_test.sum())}, best by CV F1: {best}")


def row(name, y_pred, score):
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    return {"model": name,
            "precision": precision_score(y_test, y_pred, zero_division=0),
            "recall": recall_score(y_test, y_pred, zero_division=0),
            "f1": f1_score(y_test, y_pred, zero_division=0),
            "fpr": fp / (fp + tn), "roc_auc": roc_auc_score(y_test, score),
            "TN": tn, "FP": fp, "FN": fn, "TP": tp, "accuracy": accuracy_score(y_test, y_pred)}


rows, scores, models = [], {}, {}
for n in NAMES:
    m = joblib.load(f"models/{n}.joblib")
    models[n] = m
    s = m.predict_proba(X_test)[:, 1]
    scores[n] = s
    rows.append(row(n, m.predict(X_test), s))
    ConfusionMatrixDisplay(confusion_matrix(y_test, m.predict(X_test), labels=[0, 1]),
                           display_labels=["benign", "malware"]).plot(cmap="Blues", values_format="d")
    plt.title(f"Confusion matrix (test): {n}")
    plt.tight_layout(); plt.savefig(f"outputs/confusion_matrix_{n}.png", dpi=150); plt.close()

# majority-class baseline (majority class of the TRAIN labels)
maj = int(np.bincount(y_train).argmax())
rows.append(row("majority_baseline", np.full(len(y_test), maj), np.full(len(y_test), float(maj))))
df = pd.DataFrame(rows)
df.to_csv("outputs/metrics.csv", index=False)
print(df.to_string(index=False))

# combined ROC
plt.figure(figsize=(6, 5))
for n in NAMES:
    fpr, tpr, _ = roc_curve(y_test, scores[n])
    plt.plot(fpr, tpr, label=f"{n} (AUC={df.set_index('model').loc[n, 'roc_auc']:.4f})")
plt.plot([0, 1], [0, 1], "k--", label="chance")
plt.xlabel("False positive rate"); plt.ylabel("True positive rate"); plt.title("ROC curves (test split)")
plt.legend(loc="lower right"); plt.tight_layout(); plt.savefig("outputs/roc_curves.png", dpi=150); plt.close()

# comparison bar chart
d = df[df.model.isin(NAMES)].set_index("model")[["precision", "recall", "f1", "fpr"]]
ax = d.plot.bar(figsize=(8, 5), rot=15)
ax.set_title("Test-split metrics per model"); ax.set_ylim(0, 1.05)
plt.tight_layout(); plt.savefig("outputs/model_comparison.png", dpi=150); plt.close()

# top-15 feature importance for the best-by-CV model
fnames = open("outputs/model_feature_names.txt", encoding="utf-8").read().split("\n")
fnames = [f for f in fnames if f]
clf = models[best].named_steps["clf"]
if best == "logistic_regression":
    imp, lab = np.abs(clf.coef_[0]), "|coefficient| (scaled features)"
else:
    imp, lab = clf.feature_importances_, "feature importance (impurity-based)"
assert len(imp) == len(fnames) == 94, (len(imp), len(fnames))
top = pd.Series(imp, index=fnames).nlargest(15)[::-1]
plt.figure(figsize=(8, 6)); top.plot.barh()
plt.xlabel(lab); plt.title(f"Top 15 features: {best}"); plt.tight_layout()
plt.savefig("outputs/feature_importance_best_model.png", dpi=150); plt.close()
print("top15:", list(top[::-1].round(4).items()))

# summary text
m = df.set_index("model")
L = [f"Best model (chosen by cross-validated F1 on train, not by test score): {best}",
     f"  CV F1 = {cv.loc[best, 'cv_f1_mean']:.4f} +/- {cv.loc[best, 'cv_f1_std']:.4f}; "
     f"test F1 = {m.loc[best, 'f1']:.4f}; test FPR = {m.loc[best, 'fpr']:.4f}; test ROC-AUC = {m.loc[best, 'roc_auc']:.4f}",
     "", f"Test split: n={len(y_test)} ({int(y_test.sum())} malware, {int((y_test == 0).sum())} benign).",
     "", "F1 by stage (train = mean over CV training folds at the chosen params; CV = 5-fold mean on train; test = held-out):",
     f"{'model':22s}{'train':>9s}{'CV':>9s}{'test':>9s}{'test-CV':>10s}"]
for n in NAMES:
    L.append(f"{n:22s}{cv.loc[n, 'train_f1_mean']:9.4f}{cv.loc[n, 'cv_f1_mean']:9.4f}{m.loc[n, 'f1']:9.4f}"
             f"{m.loc[n, 'f1'] - cv.loc[n, 'cv_f1_mean']:+10.4f}")
L += ["", "Test metrics (precision / recall / F1 / FPR / ROC-AUC | TN FP FN TP | accuracy):"]
for n in m.index:
    r = m.loc[n]
    L.append(f"  {n:20s}{r.precision:.4f} / {r.recall:.4f} / {r.f1:.4f} / {r.fpr:.4f} / {r.roc_auc:.4f} | "
             f"{int(r.TN)} {int(r.FP)} {int(r.FN)} {int(r.TP)} | {r.accuracy:.4f}")
L += ["", "Cost of false positives:",
      "A false positive is a benign file flagged as malware. In deployment this means blocked or quarantined legitimate software,",
      "lost user trust, analyst time spent triaging alerts, and eventually alert fatigue that makes real detections get ignored.",
      "A false negative lets malware through, which is usually costlier per event, but FPR matters because benign files vastly",
      "outnumber malware in real traffic: even a small FPR becomes many false alarms. Here the dataset is near-balanced, so the",
      f"test FPR below is NOT what a real deployment would see. Test FPR: " +
      ", ".join(f"{n} {int(m.loc[n, 'FP'])} FP of {int(m.loc[n, 'FP'] + m.loc[n, 'TN'])} benign ({m.loc[n, 'fpr']:.4f})" for n in NAMES) + ".",
      "", "Limitations:",
      "- Single 80/20 split with one test set (about 1,000 files); test metrics carry sampling noise, and one extra error moves them noticeably.",
      "- ClaMP is a research dataset with a roughly balanced class ratio; real-world prevalence of malware is much lower, so precision/FPR here are optimistic.",
      "- Static PE-header features only: packed/obfuscated or header-forged files and adversarial samples are not tested.",
      "- Benign and malware samples may come from different collection sources, so models may learn dataset artefacts (e.g. header/compiler fields) rather than maliciousness.",
      "- Hyperparameters were tuned by CV on train only; the test split was opened once for this evaluation and not used for any choice.",
      "- Feature importances (impurity-based / coefficient magnitude) describe model behaviour, not causal malicious traits; correlated features split importance.",
      "- The majority-class baseline predicts the train-majority class for every file and has ROC-AUC 0.5 by construction."]
open("outputs/evaluation_summary.txt", "w", encoding="utf-8").write("\n".join(L) + "\n")
print("\n".join(L))
