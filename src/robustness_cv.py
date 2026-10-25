"""Robustness check, CV on the TRAIN split only (test files are never opened).

1. Repeated 5x3 stratified CV of each tuned model on feature sets with the suspected
   dataset-artefact columns removed (hyperparameters stay those tuned on all 58 features).
2. Logistic Regression with a wider C grid (it picked the top of the original grid).
"""
import json
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import RepeatedStratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier

SEED = 42
CAT = "packer_type"

feats = []
for line in open("outputs/selected_features.txt", encoding="utf-8"):
    line = line.strip()
    if not line and feats:
        break
    if line and not line.startswith("#"):
        feats.append(line)
assert len(feats) == 58, len(feats)

X = pd.read_csv("data/X_train.csv")[feats]
y = pd.read_csv("data/y_train.csv")["class"]
X[[c for c in feats if c != CAT]] = X[[c for c in feats if c != CAT]].apply(pd.to_numeric)
assert len(X) == len(y) == 4165

best = json.load(open("outputs/cv_best_params.json"))
cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=3, random_state=SEED)
scoring = {"f1": "f1", "roc_auc": "roc_auc"}

SETS = {
    "all_58": [],
    "no_fileinfo": ["fileinfo"],
    "no_CheckSum": ["CheckSum"],
    "no_fileinfo_CheckSum": ["fileinfo", "CheckSum"],
    "no_fileinfo_CheckSum_filesize": ["fileinfo", "CheckSum", "filesize"],
}


def build(name, cols, **params):
    num = [c for c in cols if c != CAT]
    scale = name == "logistic_regression"
    pre = ColumnTransformer([("num", StandardScaler() if scale else "passthrough", num),
                             ("cat", OneHotEncoder(handle_unknown="ignore"), [CAT])])
    clf = {"logistic_regression": LogisticRegression(max_iter=5000, random_state=SEED),
           "decision_tree": DecisionTreeClassifier(random_state=SEED),
           "random_forest": RandomForestClassifier(random_state=SEED, n_jobs=-1)}[name]
    return Pipeline([("pre", pre), ("clf", clf)]).set_params(**params)


def run(name, cols, **params):
    r = cross_validate(build(name, cols, **params), X[cols], y, cv=cv, scoring=scoring)
    return {m: (r[f"test_{m}"].mean(), r[f"test_{m}"].std()) for m in scoring}


rows = []
for model in best:
    for label, drop in SETS.items():
        cols = [c for c in feats if c not in drop]
        s = run(model, cols, **best[model])
        rows.append({"model": model, "feature_set": label, "n_cols": len(cols),
                     "cv_f1_mean": s["f1"][0], "cv_f1_std": s["f1"][1],
                     "cv_roc_auc_mean": s["roc_auc"][0], "cv_roc_auc_std": s["roc_auc"][1]})
        print(model, label, f"F1={s['f1'][0]:.4f}+/-{s['f1'][1]:.4f}", flush=True)
pd.DataFrame(rows).to_csv("outputs/robustness_cv.csv", index=False)

rows = []
for C in [1, 10, 100, 1000, 10000, 100000]:
    s = run("logistic_regression", feats, clf__C=C)
    rows.append({"C": C, "cv_f1_mean": s["f1"][0], "cv_f1_std": s["f1"][1],
                 "cv_roc_auc_mean": s["roc_auc"][0], "cv_roc_auc_std": s["roc_auc"][1]})
    print("LR C =", C, f"F1={s['f1'][0]:.4f}+/-{s['f1'][1]:.4f}", flush=True)
pd.DataFrame(rows).to_csv("outputs/lr_C_extended_cv.csv", index=False)
