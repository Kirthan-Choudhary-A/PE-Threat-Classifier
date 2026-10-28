import altair as alt
import pandas as pd
import streamlit as st
from sklearn.metrics import auc, average_precision_score, precision_recall_curve, roc_curve

from dash_common import MODELS, OUT, importances, metrics_table, test_scores

M = metrics_table()
key = {n: f for n, f in MODELS.items()}
st.title("Model Performance")
st.caption("Dataset: ClaMP Integrated, cleaned to 5,207 samples. Stratified 80/20 split (seed 42): 4,165 train / "
           "1,042 test. Hyperparameters tuned with 5-fold CV on train only; the test split was evaluated once and "
           "the best model was chosen by CV F1.")

cols = st.columns(3)
for col, (name, k) in zip(cols, key.items()):
    r = M.loc[k]
    with col.container(border=True):
        st.markdown(f"**{name}**" + ("  · best by CV" if k == "random_forest" else ""))
        st.markdown(f"## F1 {r['f1']:.4f}")
        st.markdown(f"Precision {r['precision']:.4f} · Recall {r['recall']:.4f}  \n"
                    f"False-positive rate **{r['fpr']:.4f}** · ROC-AUC {r['roc_auc']:.4f}  \n"
                    f"Accuracy {r['accuracy']:.4f}")
base = M.loc["majority_baseline"]
st.caption(f"Majority-class baseline for reference: F1 {base['f1']:.4f}, accuracy {base['accuracy']:.4f}, "
           f"ROC-AUC {base['roc_auc']:.4f}.")

g1, g2 = st.columns(2)
long = (M.loc[list(key.values()), ["precision", "recall", "f1", "fpr"]].reset_index()
        .melt("model", var_name="metric", value_name="value"))
long["model"] = long["model"].map({v: k for k, v in key.items()})
long["metric"] = long["metric"].map({"precision": "Precision", "recall": "Recall", "f1": "F1", "fpr": "FPR"})
with g1.container(border=True):
    st.markdown("**Precision, recall, F1 and FPR**")
    st.altair_chart(alt.Chart(long).mark_bar().encode(
        x=alt.X("metric:N", title=None, sort=["Precision", "Recall", "F1", "FPR"], axis=alt.Axis(labelAngle=0)),
        xOffset="model:N", y=alt.Y("value:Q", title=None),
        color=alt.Color("model:N", title=None, legend=alt.Legend(orient="bottom"))).properties(height=300),
        width="stretch")

y, sc = test_scores()
roc, pr, areas = [], [], {}
for name, k in key.items():
    s = sc[name]
    fpr, tpr, _ = roc_curve(y, s)
    roc.append(pd.DataFrame({"fpr": fpr, "tpr": tpr, "model": name}))
    p, r_, _ = precision_recall_curve(y, s)
    pr.append(pd.DataFrame({"recall": r_, "precision": p, "model": name}))
    areas[name] = (auc(fpr, tpr), average_precision_score(y, s))
with g2.container(border=True):
    st.markdown("**ROC and precision-recall curves**")
    which = st.radio("Curve", ["ROC", "Precision-recall"], horizontal=True, label_visibility="collapsed")
    if which == "ROC":
        d, x, yy = pd.concat(roc), "fpr", "tpr"
    else:
        d, x, yy = pd.concat(pr), "recall", "precision"
    st.altair_chart(alt.Chart(d).mark_line().encode(
        x=alt.X(f"{x}:Q", title=x.upper() if x == "fpr" else "Recall"),
        y=alt.Y(f"{yy}:Q", title=yy.upper() if yy == "tpr" else "Precision"),
        color=alt.Color("model:N", title=None, legend=alt.Legend(orient="bottom"))).properties(height=260),
        width="stretch")
    st.caption(("ROC-AUC: " if which == "ROC" else "Average precision: ")
               + " · ".join(f"{n} {v[0 if which == 'ROC' else 1]:.4f}" for n, v in areas.items()))
    st.caption("Curves are recomputed from the saved models on the same test split (read-only, no tuning).")

st.markdown("**Confusion matrices (test split, malware = positive class)**")
cm_cols = st.columns(3)
for col, (name, k) in zip(cm_cols, key.items()):
    r = M.loc[k]
    cm = pd.DataFrame([("Benign", "Benign", int(r["TN"])), ("Benign", "Malicious", int(r["FP"])),
                       ("Malicious", "Benign", int(r["FN"])), ("Malicious", "Malicious", int(r["TP"]))],
                      columns=["Actual", "Predicted", "n"])
    base_c = alt.Chart(cm).encode(x=alt.X("Predicted:N", sort=["Benign", "Malicious"], axis=alt.Axis(labelAngle=0)),
                                  y=alt.Y("Actual:N", sort=["Benign", "Malicious"]))
    ch = base_c.mark_rect().encode(color=alt.Color("n:Q", legend=None, scale=alt.Scale(scheme="blues"))) + \
        base_c.mark_text(fontSize=18).encode(text="n:Q", color=alt.condition(alt.datum.n > 250, alt.value("white"),
                                                                              alt.value("#0b1220")))
    with col.container(border=True):
        st.markdown(f"**{name}**")
        st.altair_chart(ch.properties(height=200), width="stretch")
        st.caption(f"FPR = {int(r['FP'])} / ({int(r['FP'])} + {int(r['TN'])}) = {r['fpr']:.4f}")

with st.container(border=True):
    pick = st.selectbox("Feature importance for", list(key), index=2)
    imp = importances(pick).head(15).reset_index()
    imp.columns = ["feature", "importance"]
    st.altair_chart(alt.Chart(imp).mark_bar().encode(
        x=alt.X("importance:Q", title="|coefficient| (scaled)" if pick == "Logistic Regression" else "Impurity importance"),
        y=alt.Y("feature:N", sort="-x", title=None, axis=alt.Axis(labelLimit=260)), color=alt.value("#22d3ee")).properties(height=380), width="stretch")
    st.caption("Importance describes what the model uses, not what makes a file malicious. "
               "Correlated features share importance.")

with st.expander("Cross-validation vs test, and robustness check"):
    cv = pd.read_csv(OUT / "cv_results.csv").set_index("model")
    cmp_ = pd.DataFrame({"CV F1 (train)": cv["cv_f1_mean"], "Test F1": M.loc[cv.index, "f1"]}).round(4)
    st.dataframe(cmp_, width="stretch")
    st.markdown("Repeated 5x3 CV on train with suspect columns removed (`outputs/robustness_cv.csv`):")
    st.dataframe(pd.read_csv(OUT / "robustness_cv.csv").round(4), hide_index=True, width="stretch")

with st.expander("DLL-like flag check (FH_char12, train-split CV)"):
    st.markdown("`FH_char12` is the top Random Forest feature and is most likely the DLL flag. "
                "CV F1 with and without it, then out-of-fold performance by group "
                "(`src/dll_shortcut_cv.py`, train split only):")
    st.dataframe(pd.read_csv(OUT / "dll_shortcut_cv.csv").round(4), hide_index=True, width="stretch")
    st.dataframe(pd.read_csv(OUT / "dll_shortcut_subgroups.csv").round(4), hide_index=True, width="stretch")
    st.caption("False-positive rates are several times higher on EXE-like files than on DLL-like files, and the "
               "DLL-like group has only 39 malware samples, so its recall is noisy.")

with st.expander("Variation across 20 random splits (supplementary)"):
    st.markdown("All 5,207 cleaned samples re-split 20 times (stratified 80/20) with the already-chosen "
                "hyperparameters (`src/repeated_splits.py`). A variance estimate, slightly optimistic, "
                "not a replacement for the single held-out evaluation above.")
    sm = pd.read_csv(OUT / "repeated_splits_summary.csv").set_index("model")
    st.dataframe(sm[["f1_mean", "f1_std", "f1_min", "f1_max", "fpr_mean", "fpr_std", "fpr_min", "fpr_max",
                     "roc_auc_mean"]].round(4), width="stretch")
