"""How much do the models lean on FH_char12 (most likely the DLL flag)? CV on the TRAIN split only.

1. Trivial rule "malware iff FH_char12 == 0" scored on train.
2. Repeated 5x3 CV with FH_char12 removed (tuned hyperparameters unchanged).
3. Out-of-fold performance split by FH_char12 (DLL-like vs EXE-like files).
Test files are never opened. Run from the project root:  python src/dll_shortcut_cv.py"""
import json

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import RepeatedStratifiedKFold, StratifiedKFold, cross_val_predict, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

SEED, CAT, FLAG = 42, "packer_type", "FH_char12"

feats = []
for line in open("outputs/selected_features.txt", encoding="utf-8"):
    line = line.strip()
    if not line and feats:
        break
    if line and not line.startswith("#"):
        feats.append(line)
X = pd.read_csv("data/X_train.csv")[feats]
X[[c for c in feats if c != CAT]] = X[[c for c in feats if c != CAT]].apply(pd.to_numeric)
y = pd.read_csv("data/y_train.csv")["class"].to_numpy()
best = json.load(open("outputs/cv_best_params.json"))


def build(name, cols):
    num = [c for c in cols if c != CAT]
    pre = ColumnTransformer([("num", StandardScaler() if name == "logistic_regression" else "passthrough", num),
                             ("cat", OneHotEncoder(handle_unknown="ignore"), [CAT])])
    clf = {"logistic_regression": LogisticRegression(max_iter=5000, random_state=SEED),
           "decision_tree": DecisionTreeClassifier(random_state=SEED),
           "random_forest": RandomForestClassifier(random_state=SEED, n_jobs=-1)}[name]
    return Pipeline([("pre", pre), ("clf", clf)]).set_params(**best[name])


# 1. trivial rule
rule = (X[FLAG] == 0).astype(int).to_numpy()
print(f"{FLAG}=1 share: benign {X[FLAG][y == 0].mean():.3f}, malware {X[FLAG][y == 1].mean():.3f}")
print(f"Rule 'malware iff {FLAG}==0' on train: accuracy {(rule == y).mean():.4f}, F1 {f1_score(y, rule):.4f}")

# 2. CV with the flag removed
cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=3, random_state=SEED)
rows = []
for name in best:
    for label, cols in [("all_58", feats), (f"no_{FLAG}", [c for c in feats if c != FLAG])]:
        r = cross_validate(build(name, cols), X[cols], y, cv=cv, scoring={"f1": "f1", "recall": "recall"})
        rows.append({"model": name, "feature_set": label, "n_cols": len(cols),
                     "cv_f1_mean": r["test_f1"].mean(), "cv_f1_std": r["test_f1"].std(),
                     "cv_recall_mean": r["test_recall"].mean()})
        print(name, label, f"F1={r['test_f1'].mean():.4f}+/-{r['test_f1'].std():.4f}", flush=True)
pd.DataFrame(rows).to_csv("outputs/dll_shortcut_cv.csv", index=False)

# 3. out-of-fold performance by group
oof_cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
rows = []
for name in best:
    pred = cross_val_predict(build(name, feats), X, y, cv=oof_cv)
    for gname, mask in [("FH_char12=1 (DLL-like)", X[FLAG].to_numpy() == 1),
                        ("FH_char12=0 (EXE-like)", X[FLAG].to_numpy() == 0)]:
        yt, yp = y[mask], pred[mask]
        tn, fp = ((yt == 0) & (yp == 0)).sum(), ((yt == 0) & (yp == 1)).sum()
        rows.append({"model": name, "group": gname, "n": int(mask.sum()), "n_malware": int(yt.sum()),
                     "n_benign": int((yt == 0).sum()), "accuracy": (yt == yp).mean(),
                     "recall": recall_score(yt, yp, zero_division=0) if yt.sum() else np.nan,
                     "fpr": fp / (fp + tn) if (fp + tn) else np.nan,
                     "missed_malware": int(((yt == 1) & (yp == 0)).sum())})
g = pd.DataFrame(rows)
g.to_csv("outputs/dll_shortcut_subgroups.csv", index=False)
print(g.round(4).to_string(index=False))
