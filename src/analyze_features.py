"""Stage 3: feature analysis on TRAIN ONLY (data/X_train.csv, y_train.csv). Seed 42.
Never reads X_test/y_test. Writes outputs/feature_*.csv, feature_analysis.txt, feature_importance.png,
selected_features.txt."""
import io
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier

SEED = 42
ROOT = Path(__file__).resolve().parent.parent
D, O = ROOT / "data", ROOT / "outputs"
log = io.StringIO()
def p(*a):
    print(*a); print(*a, file=log)

X = pd.read_csv(D / "X_train.csv")
y = pd.read_csv(D / "y_train.csv")["class"]
p(f"Train: {X.shape}, malware={int(y.sum())}, benign={int((1 - y).sum())}")
cv = StratifiedKFold(5, shuffle=True, random_state=SEED)

# ---- 1. themes -------------------------------------------------------------
def theme(c):
    if c.startswith("e_"): return "DOS header"
    if c.startswith("FH_char") or c in ("NumberOfSections", "CreationYear"): return "File header"
    if c.startswith("OH_DLLchar"): return "Optional hdr: DLL characteristics"
    if c in ("sus_sections", "non_sus_sections"): return "Sections (suspicious count)"
    if c in ("packer", "packer_type"): return "Packer"
    if c in ("E_text", "E_data", "E_file"): return "Entropy"
    if c in ("filesize", "fileinfo"): return "File-level"
    if c.startswith("SizeOfStack") or c.startswith("SizeOfHeap"): return "Optional hdr: stack/heap"
    if "Version" in c: return "Optional hdr: versions"
    return "Optional hdr: other (sizes/addresses/alignment)"
themes = pd.Series({c: theme(c) for c in X.columns})
p("\n== 1. Themes =="); [p(f"{t} ({len(g)}): {', '.join(g.index)}") for t, g in themes.groupby(themes)]

# ---- 2. constant / duplicate / correlated ----------------------------------
num = [c for c in X.columns if c != "packer_type"]
const = [c for c in X.columns if X[c].nunique() == 1]
nonconst = [c for c in num if c not in const]
dups = []  # identical-valued columns (keep first)
for i, a in enumerate(nonconst):
    for b in nonconst[i + 1:]:
        if X[a].equals(X[b]): dups.append((a, b))
TH = 0.95
corr = X[nonconst].corr()  # Pearson
pairs = [(a, b, corr.loc[a, b]) for i, a in enumerate(nonconst) for b in nonconst[i + 1:] if abs(corr.loc[a, b]) > TH]
p(f"\n== 2. Constant / duplicate / correlated ==\nConstant ({len(const)}): {const}")
p(f"Exact duplicate numeric columns: {dups if dups else 'none'}")
p(f"Pearson |r| > {TH} pairs (non-constant numeric; packer_type excluded): {len(pairs)}")
for a, b, r in sorted(pairs, key=lambda t: -abs(t[2])): p(f"  {a} ~ {b}: r={r:.4f}")
pd.DataFrame(pairs, columns=["a", "b", "pearson_r"]).to_csv(O / "feature_correlated_pairs.csv", index=False)
# also report a looser band for context
loose = [(a, b, corr.loc[a, b]) for i, a in enumerate(nonconst) for b in nonconst[i + 1:] if 0.8 < abs(corr.loc[a, b]) <= TH]
p(f"Pairs with 0.8 < |r| <= {TH}: {len(loose)}")
for a, b, r in sorted(loose, key=lambda t: -abs(t[2])): p(f"  {a} ~ {b}: r={r:.4f}")

# ---- 3. single-feature separators -----------------------------------------
# raw AUC (direction-free) and 5-fold CV AUC/accuracy of a depth-3 tree on that single feature
def single(cols, name):
    Xs = X[cols]
    if "packer_type" in cols:
        Xs = pd.get_dummies(Xs, columns=["packer_type"]).astype(float)  # deterministic encoding, no fitting on labels
    pr = cross_val_predict(DecisionTreeClassifier(max_depth=3, random_state=SEED), Xs, y, cv=cv, method="predict_proba")[:, 1]
    auc_raw = np.nan if name == "packer_type" else max(roc_auc_score(y, X[name]), 1 - roc_auc_score(y, X[name]))
    return dict(feature=name, raw_auc=auc_raw, tree3_cv_auc=roc_auc_score(y, pr), tree3_cv_acc=((pr > .5) == y).mean())
sf = pd.DataFrame([single([c], c) for c in X.columns if c not in const]).sort_values("tree3_cv_auc", ascending=False)
sf.to_csv(O / "feature_single_auc.csv", index=False)
p("\n== 3. Single-feature separators (train, 5-fold CV, depth-3 tree; raw_auc = max(AUC,1-AUC)) ==")
p(sf.head(15).round(4).to_string(index=False))
p("Specifically:"); p(sf[sf.feature.isin(["fileinfo", "packer", "packer_type", "sus_sections", "non_sus_sections", "CreationYear", "E_text", "E_data", "E_file", "filesize"])].round(4).to_string(index=False))
p("Class rate by packer (1=packed):", X.groupby("packer").apply(lambda g: (len(g), round(y[g.index].mean(), 4)), include_groups=False).to_dict())
p("Malware rate by CreationYear:", X.groupby("CreationYear").apply(lambda g: (len(g), round(y[g.index].mean(), 4)), include_groups=False).to_dict())
p("Mean per class fileinfo:", X.groupby(y)["fileinfo"].mean().round(4).to_dict())

# ---- 4. importance ---------------------------------------------------------
cands = [c for c in X.columns if c not in const]
def make_rf(cols):
    ohe = ColumnTransformer([("oh", OneHotEncoder(handle_unknown="ignore", sparse_output=False), ["packer_type"] if "packer_type" in cols else [])],
                            remainder="passthrough", verbose_feature_names_out=False)
    return Pipeline([("t", ohe), ("rf", RandomForestClassifier(300, random_state=SEED, n_jobs=-1))])
# impurity: fit on full train, sum packer_type dummies back into one feature
m = make_rf(cands).fit(X[cands], y)
names = m["t"].get_feature_names_out()
imp = pd.Series(m["rf"].feature_importances_, index=names)
imp_agg = imp.groupby(lambda n: "packer_type" if n.startswith("packer_type_") else n).sum()
# permutation importance on held-out folds (original columns permuted; ROC-AUC drop)
perm = pd.DataFrame(index=cands)
for k, (tr, va) in enumerate(cv.split(X, y)):
    mk = make_rf(cands).fit(X.iloc[tr][cands], y.iloc[tr])
    r = permutation_importance(mk, X.iloc[va][cands], y.iloc[va], scoring="roc_auc", n_repeats=5, random_state=SEED, n_jobs=-1)
    perm[k] = r.importances_mean
imp_df = pd.DataFrame({"theme": themes[cands], "rf_impurity": imp_agg.reindex(cands), "perm_auc_drop_mean": perm.mean(axis=1), "perm_auc_drop_std_across_folds": perm.std(axis=1)})
imp_df = imp_df.sort_values("rf_impurity", ascending=False)
imp_df.to_csv(O / "feature_importance.csv")
p("\n== 4. Importance (RF 300 trees, seed 42; permutation = held-out ROC-AUC drop, 5 folds x 5 repeats) ==")
p(imp_df.head(20).round(4).to_string())
fig, ax = plt.subplots(1, 2, figsize=(14, 7))
t = imp_df.head(20)[::-1]; ax[0].barh(t.index, t.rf_impurity); ax[0].set_title("RF impurity importance (top 20, train)")
t = imp_df.sort_values("perm_auc_drop_mean", ascending=False).head(20)[::-1]
ax[1].barh(t.index, t.perm_auc_drop_mean, xerr=t.perm_auc_drop_std_across_folds); ax[1].set_title("Permutation importance: held-out ROC-AUC drop (train CV)")
plt.tight_layout(); plt.savefig(O / "feature_importance.png", dpi=130); plt.close()

# ---- 5. ablation CV on TRAIN only (to inform the design; test untouched) ---
SUSP = ["fileinfo", "packer", "packer_type", "sus_sections", "non_sus_sections", "CreationYear"]
sets = {"A_all_nonconstant": cands,
        "B_no_suspected_separators": [c for c in cands if c not in SUSP],
        "C_no_fileinfo": [c for c in cands if c != "fileinfo"],
        "D_no_packer_cols": [c for c in cands if c not in ("packer", "packer_type")],
        "E_no_sus_sections_cols": [c for c in cands if c not in ("sus_sections", "non_sus_sections")]}
rows = []
for k, cols in sets.items():
    for mname, est in (("RF", make_rf(cols)), ("DT", Pipeline([("t", ColumnTransformer([("oh", OneHotEncoder(handle_unknown="ignore", sparse_output=False), ["packer_type"] if "packer_type" in cols else [])], remainder="passthrough")),
                                                           ("dt", DecisionTreeClassifier(random_state=SEED))]))):
        s = cross_validate(est, X[cols], y, cv=cv, scoring=["roc_auc", "f1", "precision", "recall"])
        rows.append(dict(feature_set=k, n_cols=len(cols), model=mname, **{m_: round(s[f"test_{m_}"].mean(), 4) for m_ in ("roc_auc", "f1", "precision", "recall")}))
ab = pd.DataFrame(rows); ab.to_csv(O / "feature_ablation_cv_train.csv", index=False)
p("\n== 5. Ablation (5-fold CV on TRAIN only, default hyperparameters) =="); p(ab.to_string(index=False))

# ---- 6. extras + recommendation ---------------------------------------------
p("\n== 6. Extras ==")
p("Spearman / fraction-equal for the |r|>0.95 pairs (Pearson on heavy-tailed cols is outlier-driven):")
for a, b, r in pairs:
    p(f"  {a} ~ {b}: pearson={r:.4f} spearman={X[a].corr(X[b], method='spearman'):.4f} equal_frac={(X[a] == X[b]).mean():.4f}")
p("packer==1 iff packer_type!='NoPacker':", bool(((X.packer == 1) == (X.packer_type != "NoPacker")).all()))
p("Max e_cp / e_cparhdr / SizeOfCode (outlier-driven correlation):", X[["e_cp", "e_cparhdr", "SizeOfCode"]].max().to_dict())
DROP = {c: "constant in train (single value)" for c in const}
DROP["FH_char10"] = "exact duplicate of FH_char9"
DROP["FH_char14"] = "near-duplicate of FH_char6 (differs in 1 of 4165 rows, r=0.9978)"
keep = [c for c in X.columns if c not in DROP]
lines = [f"# Recommended feature set (train-only analysis). {len(keep)} columns kept of {X.shape[1]}; packer_type to be one-hot encoded (fit on train).", *keep, "",
         "# Proposed drops (one reason each)"] + [f"DROP {c}: {r}" for c, r in DROP.items()] + ["",
         "# Flagged but KEPT",
         "FH_char3: r=0.97 with FH_char2 (98.5% equal); keep, harmless for trees, mildly collinear for LR",
         "e_cp, e_cparhdr, SizeOfCode, SizeOfInitializedData: Pearson>0.99 is driven by a few extreme rows; Spearman is low, so NOT redundant",
         "packer: equals (packer_type != NoPacker); redundant with packer_type but kept (use packer_type one-hot, optionally drop packer for LR)",
         "fileinfo, packer*, sus_sections, CreationYear, E_*: no single-feature near-perfect separation found; kept in main set, tested in ablation B",
         "",
         "# Ablation (same split, CV on train; test only at final evaluation)",
         "A: all kept features   B: A minus [fileinfo, packer, packer_type, sus_sections, non_sus_sections, CreationYear]"]
(O / "selected_features.txt").write_text("\n".join(lines), encoding="utf-8")
p("Kept:", len(keep), "Dropped:", len(DROP))

(O / "feature_analysis.txt").write_text(log.getvalue(), encoding="utf-8")
