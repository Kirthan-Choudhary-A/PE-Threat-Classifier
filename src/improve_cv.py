"""Can the models be improved? CV-only search on the TRAIN split (test files are never opened).

Candidates are tuned with 5-fold CV (seed 7), then compared to the current tuned Random Forest on repeated 5x3 CV
with different fold seeds (43), so the comparison is not on the folds used for tuning.
Run from the project root:  python src/improve_cv.py   (about 10 minutes)"""
import json
import time

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier, VotingClassifier
from sklearn.metrics import make_scorer
from sklearn.model_selection import GridSearchCV, RepeatedStratifiedKFold, StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

SEED, CAT = 42, "packer_type"

feats = []
for line in open("outputs/selected_features.txt", encoding="utf-8"):
    line = line.strip()
    if not line and feats:
        break
    if line and not line.startswith("#"):
        feats.append(line)
X = pd.read_csv("data/X_train.csv")[feats]
num = [c for c in feats if c != CAT]
X[num] = X[num].apply(pd.to_numeric)
y = pd.read_csv("data/y_train.csv")["class"].to_numpy()
best = json.load(open("outputs/cv_best_params.json"))


def pipe(clf):
    pre = ColumnTransformer([("num", "passthrough", num),
                             ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), [CAT])])
    return Pipeline([("pre", pre), ("clf", clf)])


def fpr(yt, yp):
    fp = ((yt == 0) & (yp == 1)).sum()
    return fp / max(1, (yt == 0).sum())


tune_cv = StratifiedKFold(5, shuffle=True, random_state=7)
eval_cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=3, random_state=SEED + 1)
scoring = {"f1": "f1", "roc_auc": "roc_auc", "recall": "recall", "fpr": make_scorer(fpr)}

rf_now = pipe(RandomForestClassifier(random_state=SEED, n_jobs=-1)).set_params(**best["random_forest"])
searches = {
    "rf_wider": (pipe(RandomForestClassifier(n_estimators=500, random_state=SEED, n_jobs=-1)),
                 {"clf__max_features": ["sqrt", 0.2, 0.35], "clf__criterion": ["gini", "entropy"],
                  "clf__class_weight": [None, "balanced_subsample"], "clf__min_samples_leaf": [1, 2]}),
    "extra_trees": (pipe(ExtraTreesClassifier(random_state=SEED, n_jobs=-1)),
                    {"clf__n_estimators": [300, 600], "clf__max_features": ["sqrt", 0.3, 0.5],
                     "clf__min_samples_leaf": [1, 2]}),
    "hist_gradient_boosting": (pipe(HistGradientBoostingClassifier(max_iter=300, random_state=SEED)),
                               {"clf__learning_rate": [0.05, 0.1, 0.2], "clf__max_leaf_nodes": [15, 31, 63],
                                "clf__l2_regularization": [0.0, 1.0]}),
}
fitted, rows = {"rf_current": rf_now}, []
for name, (p, grid) in searches.items():
    t = time.time()
    gs = GridSearchCV(p, grid, cv=tune_cv, scoring="f1", n_jobs=1).fit(X, y)
    fitted[name] = gs.best_estimator_
    print(f"{name}: tuned in {time.time() - t:.0f}s, best {gs.best_params_}, inner CV F1 {gs.best_score_:.4f}", flush=True)
    rows.append({"model": name, "best_params": json.dumps(gs.best_params_, default=str)})

# soft-voting ensemble of the tuned tree models
ens = VotingClassifier([(n, fitted[n]) for n in ("rf_current", "extra_trees", "hist_gradient_boosting")], voting="soft")
fitted["voting_ensemble"] = ens

params = {r["model"]: r["best_params"] for r in rows}
res = []
for name, est in fitted.items():
    t = time.time()
    r = cross_validate(est, X, y, cv=eval_cv, scoring=scoring)
    res.append({"model": name, "cv_f1_mean": r["test_f1"].mean(), "cv_f1_std": r["test_f1"].std(),
                "cv_roc_auc_mean": r["test_roc_auc"].mean(), "cv_recall_mean": r["test_recall"].mean(),
                "cv_fpr_mean": r["test_fpr"].mean(), "cv_fpr_std": r["test_fpr"].std(),
                "best_params": params.get(name, json.dumps(best["random_forest"]))})
    print(f"{name}: F1 {res[-1]['cv_f1_mean']:.4f} +/- {res[-1]['cv_f1_std']:.4f}, "
          f"FPR {res[-1]['cv_fpr_mean']:.4f}, AUC {res[-1]['cv_roc_auc_mean']:.4f} ({time.time() - t:.0f}s)", flush=True)
out = pd.DataFrame(res)
out.to_csv("outputs/improve_cv.csv", index=False)
print(out.drop(columns="best_params").round(4).to_string(index=False))
