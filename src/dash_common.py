"""Shared loaders, scan database and report rendering for the dashboard (src/app.py + src/views/).

Everything shown comes from saved project outputs or from scans made in the app.
Nothing here executes or parses an executable: scans work on feature rows only."""
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "outputs"
DB = ROOT / "data" / "scans.db"
CAT = "packer_type"
MODELS = {"Logistic Regression": "logistic_regression", "Decision Tree": "decision_tree",
          "Random Forest": "random_forest"}
LABEL_MAL, LABEL_BEN = "Potentially malicious", "Predicted benign"
COLORS = {LABEL_MAL: "#ef4444", LABEL_BEN: "#22c55e", "Total": "#22d3ee"}
DEMO_ROWS = [0, 3, 1, 29, 19]  # real test-split rows: clear malware, clear benign, packed, one FP, one FN


def label_for(score):
    return LABEL_MAL if score >= 0.5 else LABEL_BEN


@st.cache_resource
def load_models():
    return {n: joblib.load(ROOT / f"models/{f}.joblib") for n, f in MODELS.items()}


@st.cache_data
def load_data():
    """Returns (feature names, DataFrame of all 5,207 cleaned rows with 'class' and 'split')."""
    feats = []
    for line in open(OUT / "selected_features.txt", encoding="utf-8"):
        line = line.strip()
        if not line and feats:
            break
        if line and not line.startswith("#"):
            feats.append(line)
    parts = []
    for split in ("train", "test"):
        X = pd.read_csv(ROOT / f"data/X_{split}.csv")[feats]
        X["class"] = pd.read_csv(ROOT / f"data/y_{split}.csv")["class"].to_numpy()
        X["split"] = split
        parts.append(X)
    df = pd.concat(parts, ignore_index=True)
    num = [c for c in feats if c != CAT]
    df[num] = df[num].apply(pd.to_numeric)
    return feats, df


def test_rows():
    return load_data()[1].query("split == 'test'").reset_index(drop=True)


def predict_all(X):
    feats = load_data()[0]
    return {n: m.predict_proba(X[feats])[:, 1] for n, m in load_models().items()}


@st.cache_data
def test_scores():
    t = test_rows()
    return t["class"].to_numpy(), predict_all(t)


@st.cache_data
def importances(model_name):
    names = open(OUT / "model_feature_names.txt", encoding="utf-8").read().split()
    clf = load_models()[model_name].named_steps["clf"]
    imp = np.abs(clf.coef_[0]) if hasattr(clf, "coef_") else clf.feature_importances_
    return pd.Series(imp, index=names).sort_values(ascending=False)


@st.cache_data
def metrics_table():
    return pd.read_csv(OUT / "metrics.csv").set_index("model")


# ---- scan history (SQLite) -------------------------------------------------
def _con():
    DB.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, sha256 TEXT, source TEXT, model TEXT,
        score REAL, label TEXT, scores_json TEXT, features_json TEXT, created_at TEXT)""")
    return con


def list_scans():
    with closing(_con()) as con:
        return pd.read_sql("SELECT * FROM scans ORDER BY id DESC", con)


def clear_scans():
    with closing(_con()) as con, con:
        con.execute("DELETE FROM scans")


def record_scans(X, names, source, model):
    """Score every row with all three models, store one scan per row. Returns the new ids."""
    scores = predict_all(X)
    ids = []
    with closing(_con()) as con, con:
        for i, name in enumerate(names):
            feats = json.loads(X.iloc[[i]].to_json(orient="records"))[0]
            sha = hashlib.sha256(json.dumps(feats, sort_keys=True).encode()).hexdigest()
            s = float(scores[model][i])
            cur = con.execute(
                "INSERT INTO scans(name,sha256,source,model,score,label,scores_json,features_json,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (name, sha, source, model, s, label_for(s),
                 json.dumps({n: float(v[i]) for n, v in scores.items()}), json.dumps(feats),
                 datetime.now().isoformat(timespec="seconds")))
            ids.append(cur.lastrowid)
    return ids


def validate_features(raw, max_rows=50):
    """Check an uploaded feature table. Returns (X with the 58 feature columns, None) or (None, error message)."""
    feats = load_data()[0]
    num = [c for c in feats if c != CAT]
    missing = [c for c in feats if c not in raw.columns]
    if missing:
        return None, f"Missing {len(missing)} required column(s): {', '.join(missing[:8])}{' ...' if len(missing) > 8 else ''}"
    if not 1 <= len(raw) <= max_rows:
        return None, f"CSV must have 1 to {max_rows} rows (has {len(raw)})."
    X = raw[feats].copy()
    X[num] = X[num].apply(pd.to_numeric, errors="coerce")
    bad = [c for c in num if X[c].isna().any()]
    if bad:
        return None, f"Non-numeric or empty values in: {', '.join(bad[:8])}"
    return X, None


def get_scan(scan_id):
    with closing(_con()) as con:
        r = pd.read_sql("SELECT * FROM scans WHERE id = ?", con, params=(int(scan_id),))
    return r.iloc[0] if len(r) else None


# ---- report ---------------------------------------------------------------
def top_features(n=10):
    feats = load_data()[0]
    return [f for f in importances("Random Forest").index if f in feats][:n]


def feature_table(feats_dict, n=10):
    df = load_data()[1]
    med = df.groupby("class")[[c for c in df.columns if c not in (CAT, "class", "split")]].median()
    rows = []
    for f in top_features(n):
        rows.append({"Feature": f, "This file": feats_dict[f], "Benign median": med.loc[0, f],
                     "Malware median": med.loc[1, f]})
    return pd.DataFrame(rows)


def report_markdown(rec, ft):
    s = json.loads(rec["scores_json"])
    lines = [f"# Analysis report: {rec['name']}", "",
             f"- Feature-vector SHA-256: `{rec['sha256']}`", f"- Source: {rec['source']}",
             f"- Scanned: {rec['created_at']}", f"- Model: {rec['model']}",
             f"- **Prediction: {rec['label']}** (model score {rec['score']:.3f})", "",
             "Machine-learning predictions are uncertain. This result does not confirm malicious behaviour.", "",
             "## All models", "", "| Model | Score | Prediction |", "|---|---|---|"]
    lines += [f"| {n} | {v:.3f} | {label_for(v)} |" for n, v in s.items()]
    lines += ["", "## Top features vs dataset medians", "", "| " + " | ".join(ft.columns) + " |",
              "|" + "---|" * len(ft.columns)]
    lines += ["| " + " | ".join(str(v) for v in r) + " |" for r in ft.itertuples(index=False)]
    lines += ["", "Scores are raw model scores, not calibrated probabilities."]
    return "\n".join(lines)


def render_report(rec):
    s = json.loads(rec["scores_json"])
    feats_dict = json.loads(rec["features_json"])
    mal = rec["label"] == LABEL_MAL
    with st.container(border=True):
        st.caption("FILE ANALYSIS REPORT")
        st.subheader(rec["name"])
        st.caption(f"Feature-vector SHA-256: `{rec['sha256']}`  \nSource: {rec['source']}  |  "
                   f"Scanned: {rec['created_at']}")
        st.markdown(f"#### {'🔴' if mal else '🟢'} :{'red' if mal else 'green'}[{rec['label'].upper()}]")
        st.markdown(f"**Model:** {rec['model']} &nbsp;|&nbsp; **Model score:** {rec['score']:.3f}")
        st.progress(float(rec["score"]))
        st.warning("Machine-learning predictions are uncertain. This result does not confirm malicious behaviour. "
                   "The score is a raw model score (for Random Forest, the average vote of its trees), "
                   "not a calibrated probability.", icon="⚠️")
    c1, c2 = st.columns([1, 2])
    with c1.container(border=True):
        st.markdown("**All three models**")
        for n, v in s.items():
            st.markdown(f"{'🔴' if v >= .5 else '🟢'} {n}: **{v:.3f}** — {label_for(v)}")
    ft = feature_table(feats_dict)
    with c2.container(border=True):
        st.markdown("**Top Random Forest features vs the dataset**")
        st.dataframe(ft, hide_index=True, width="stretch")
        st.caption(f"Packer: `{feats_dict.get(CAT)}`. Unusual values are clues that need context, "
                   "not proof of malicious behaviour.")
    with st.expander("All 58 feature values"):
        st.dataframe(pd.DataFrame({"value": {k: str(v) for k, v in feats_dict.items()}}), width="stretch")
    st.download_button("Download report (Markdown)", report_markdown(rec, ft),
                       file_name=f"report_{rec['id']}.md", mime="text/markdown")
