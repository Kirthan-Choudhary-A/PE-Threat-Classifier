"""Demo UI. Run from anywhere:  streamlit run src/app.py
Shows the saved results and lets you run the trained models on rows from the test split.
Those rows were already scored once in evaluation, so this is an illustration, not a new evaluation."""
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs"
CAT = "packer_type"
MODELS = {"Logistic Regression": "logistic_regression", "Decision Tree": "decision_tree",
          "Random Forest": "random_forest"}
EDITABLE = ["E_file", "E_text", "E_data", "filesize", "NumberOfSections", "CheckSum", "fileinfo"]

st.set_page_config(page_title="PE malware classifier", layout="wide")


@st.cache_resource
def load():
    feats = []
    for line in open(OUT / "selected_features.txt", encoding="utf-8"):
        line = line.strip()
        if not line and feats:
            break
        if line and not line.startswith("#"):
            feats.append(line)
    X = pd.read_csv(ROOT / "data/X_test.csv")[feats]
    y = pd.read_csv(ROOT / "data/y_test.csv")["class"]
    X[[c for c in feats if c != CAT]] = X[[c for c in feats if c != CAT]].apply(pd.to_numeric)
    models = {n: joblib.load(ROOT / f"models/{f}.joblib") for n, f in MODELS.items()}
    return feats, X, y, models


feats, X_test, y_test, models = load()

st.title("Static PE-header malware classifier")
st.caption("ML classification of Windows executables from PE-header features only. "
           "No file is ever executed: the dataset is a table of pre-extracted header values (ClaMP).")

tab_res, tab_live = st.tabs(["Results", "Live prediction"])

with tab_res:
    m = pd.read_csv(OUT / "metrics.csv").set_index("model")
    st.subheader("Test-split metrics (1,042 files, evaluated once)")
    st.dataframe(m.style.format({c: "{:.4f}" for c in ["precision", "recall", "f1", "fpr", "roc_auc", "accuracy"]}),
                 width="stretch")
    st.caption("FPR = FP / (FP + TN): benign files wrongly flagged as malware. "
               "Majority baseline = always predict malware.")
    c1, c2 = st.columns(2)
    c1.image(str(OUT / "model_comparison.png"), caption="Model comparison")
    c2.image(str(OUT / "roc_curves.png"), caption="ROC curves")
    c3, c4, c5 = st.columns(3)
    for col, n in zip((c3, c4, c5), MODELS.values()):
        col.image(str(OUT / f"confusion_matrix_{n}.png"), caption=n.replace("_", " ").title())
    st.image(str(OUT / "feature_importance_best_model.png"), caption="Random Forest: top 15 features")
    with st.expander("Limitations"):
        st.markdown("- Old, near 50/50 dataset: scores will not carry over to real traffic.\n"
                    "- Header features only; import counts are not in the dataset.\n"
                    "- Benign/malware files may come from different sources (collection artefacts).\n"
                    "- One 80/20 split, no significance test.")

with tab_live:
    st.write("Pick a file from the held-out test split, optionally edit some header values, "
             "and see what each model says.")
    left, right = st.columns([1, 2])
    mode = left.radio("Row", ["Random", "By index"], horizontal=True)
    if mode == "Random":
        if "idx" not in st.session_state or left.button("Pick another random file"):
            st.session_state.idx = int(pd.Series(range(len(X_test))).sample(1).iloc[0])
        idx = st.session_state.idx
    else:
        idx = int(left.number_input("Test row index", 0, len(X_test) - 1, 0))
    row = X_test.iloc[[idx]].copy()
    left.markdown(f"**Test row {idx}** &nbsp; actual label: "
                  f"**{'malware' if y_test.iloc[idx] == 1 else 'benign'}**")
    left.caption(f"packer_type: {row[CAT].iloc[0]}")

    with left.expander("Edit header values (what-if)"):
        for c in EDITABLE:
            v = float(row[c].iloc[0])
            row[c] = st.number_input(c, value=v, key=f"{c}_{idx}", format="%.4f" if c.startswith("E_") else "%.0f")

    cols = right.columns(3)
    for col, (name, model) in zip(cols, models.items()):
        p = float(model.predict_proba(row)[0, 1])
        label = "MALWARE" if p >= 0.5 else "BENIGN"
        col.metric(name, label, f"{p:.1%} malware probability", delta_color="off")
        col.progress(p)
    right.caption("Edited values change the prediction because the models see them directly. "
                  "Random Forest is the best model on the test split.")
    with right.expander("All 58 feature values for this row"):
        st.dataframe(row.T.astype(str).rename(columns={row.index[0]: "value"}), width="stretch")
