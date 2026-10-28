"""Supplementary: how much do test metrics vary with the random split?

Re-splits the whole cleaned dataset (train + test rows, 5,207) 20 times with stratified 80/20 splits and
evaluates each model with the hyperparameters already chosen by CV. Nothing is re-tuned.
Caveat: those hyperparameters were chosen on the original train split, whose rows appear in the test part of
other splits, so these numbers are a variance estimate, slightly optimistic, NOT a replacement for the single
held-out evaluation. Run from the project root:  python src/repeated_splits.py"""
import json

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

SEED, CAT, N_SPLITS = 42, "packer_type", 20

feats = []
for line in open("outputs/selected_features.txt", encoding="utf-8"):
    line = line.strip()
    if not line and feats:
        break
    if line and not line.startswith("#"):
        feats.append(line)
X = pd.concat([pd.read_csv(f"data/X_{s}.csv")[feats] for s in ("train", "test")], ignore_index=True)
X[[c for c in feats if c != CAT]] = X[[c for c in feats if c != CAT]].apply(pd.to_numeric)
y = pd.concat([pd.read_csv(f"data/y_{s}.csv")["class"] for s in ("train", "test")], ignore_index=True)
assert len(X) == len(y) == 5207
best = json.load(open("outputs/cv_best_params.json"))
num = [c for c in feats if c != CAT]


def build(name):
    pre = ColumnTransformer([("num", StandardScaler() if name == "logistic_regression" else "passthrough", num),
                             ("cat", OneHotEncoder(handle_unknown="ignore"), [CAT])])
    clf = {"logistic_regression": LogisticRegression(max_iter=5000, random_state=SEED),
           "decision_tree": DecisionTreeClassifier(random_state=SEED),
           "random_forest": RandomForestClassifier(random_state=SEED, n_jobs=-1)}[name]
    return Pipeline([("pre", pre), ("clf", clf)]).set_params(**best[name])


rows = []
for i in range(N_SPLITS):
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=100 + i, stratify=y)
    for name in best:
        m = build(name).fit(Xtr, ytr)
        pred, score = m.predict(Xte), m.predict_proba(Xte)[:, 1]
        tn, fp, fn, tp = confusion_matrix(yte, pred).ravel()
        rows.append({"split": i, "model": name, "precision": precision_score(yte, pred),
                     "recall": recall_score(yte, pred), "f1": f1_score(yte, pred), "fpr": fp / (fp + tn),
                     "roc_auc": roc_auc_score(yte, score), "fp": fp, "fn": fn})
    print("split", i, flush=True)
df = pd.DataFrame(rows)
df.to_csv("outputs/repeated_splits.csv", index=False)
summ = df.groupby("model")[["precision", "recall", "f1", "fpr", "roc_auc"]].agg(["mean", "std", "min", "max"])
summ.columns = [f"{a}_{b}" for a, b in summ.columns]
summ.to_csv("outputs/repeated_splits_summary.csv")
print(summ[[c for c in summ.columns if c.startswith(("f1", "fpr"))]].round(4).to_string())
