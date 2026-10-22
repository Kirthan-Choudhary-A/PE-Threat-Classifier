"""Train LR / DT / RF with GridSearchCV on the TRAIN split only. Test files are never opened."""
import json
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold
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
num = [c for c in feats if c != CAT]
X[num] = X[num].apply(pd.to_numeric)  # fails loudly if any other text column sneaks in
assert len(X) == len(y) == 4165


def pre(scale):
    return ColumnTransformer(
        [("num", StandardScaler() if scale else "passthrough", num),
         ("cat", OneHotEncoder(handle_unknown="ignore"), [CAT])])


models = {
    "logistic_regression": (
        Pipeline([("pre", pre(True)), ("clf", LogisticRegression(max_iter=5000, random_state=SEED))]),
        {"clf__C": [0.01, 0.1, 1, 10, 100]}),
    "decision_tree": (
        Pipeline([("pre", pre(False)), ("clf", DecisionTreeClassifier(random_state=SEED))]),
        {"clf__max_depth": [3, 5, 8, 12, None], "clf__min_samples_leaf": [1, 2, 5, 10],
         "clf__criterion": ["gini", "entropy"]}),
    "random_forest": (
        Pipeline([("pre", pre(False)), ("clf", RandomForestClassifier(random_state=SEED, n_jobs=-1))]),
        {"clf__n_estimators": [100, 300], "clf__max_depth": [None, 10, 20],
         "clf__min_samples_leaf": [1, 2, 4], "clf__max_features": ["sqrt", "log2"]}),
}

cv = StratifiedKFold(5, shuffle=True, random_state=SEED)
metrics = ["f1", "roc_auc", "precision", "recall"]
rows, best_params = [], {}
for name, (pipe, grid) in models.items():
    t = time.time()
    gs = GridSearchCV(pipe, grid, cv=cv, scoring={m: m for m in metrics}, refit="f1",
                      return_train_score=True)
    gs.fit(X, y)
    r, i = gs.cv_results_, gs.best_index_
    row = {"model": name, "best_params": json.dumps(gs.best_params_, default=str),
           "train_f1_mean": r["mean_train_f1"][i], "n_candidates": len(r["params"]),
           "fit_seconds": round(time.time() - t, 1)}
    for m in metrics:
        row[f"cv_{m}_mean"], row[f"cv_{m}_std"] = r[f"mean_test_{m}"][i], r[f"std_test_{m}"][i]
    row["f1_train_minus_cv_gap"] = row["train_f1_mean"] - row["cv_f1_mean"]
    rows.append(row)
    best_params[name] = gs.best_params_
    joblib.dump(gs.best_estimator_, f"models/{name}.joblib")
    if name == "logistic_regression":  # all three share identical post-encoding column order
        names = [n.split("__", 1)[1] for n in gs.best_estimator_.named_steps["pre"].get_feature_names_out()]
        open("outputs/model_feature_names.txt", "w", encoding="utf-8").write("\n".join(names) + "\n")
    print(f"done {name} in {row['fit_seconds']}s", flush=True)

df = pd.DataFrame(rows)
df.to_csv("outputs/cv_results.csv", index=False)
json.dump(best_params, open("outputs/cv_best_params.json", "w"), indent=2, default=str)

show = df[["model"]].copy()
for m in metrics:
    show[m] = df[f"cv_{m}_mean"].map("{:.4f}".format) + " +/- " + df[f"cv_{m}_std"].map("{:.4f}".format)
show["train_f1"] = df["train_f1_mean"].map("{:.4f}".format)
show["gap"] = df["f1_train_minus_cv_gap"].map("{:.4f}".format)
print(show.to_string(index=False))
print(df[["model", "best_params"]].to_string(index=False))
