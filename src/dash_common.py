"""Shared loaders, scan database and report rendering for the dashboard (src/app.py + src/views/).

Everything shown comes from saved project outputs or from scans made in the app.
Nothing here executes or parses an executable: scans work on feature rows only."""
import hashlib
import json
import os
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
DB = Path(os.environ.get("STATICSCAN_DB", ROOT / "data" / "scans.db"))  # override for screenshots/tests
CAT = "packer_type"
MODELS = {"Logistic Regression": "logistic_regression", "Decision Tree": "decision_tree",
          "Random Forest": "random_forest"}
LABEL_MAL, LABEL_BEN, LABEL_UNC = "Potentially malicious", "Predicted benign", "Uncertain"
COLORS = {LABEL_MAL: "#ef4444", LABEL_BEN: "#22c55e", LABEL_UNC: "#f59e0b", "Total": "#22d3ee"}
BORDER = (0.4, 0.6)  # a score this close to the 0.5 line is too close to call (fixed in advance, not tuned)
DEMO_ROWS = [0, 3, 1, 29, 19]  # real test-split rows: clear malware, clear benign, packed, one FP, one FN


def label_for(score):
    return LABEL_MAL if score >= 0.5 else LABEL_BEN


def verdict(scores, primary):
    """(label, reason) for one scan. scores: {model name: score}; primary: the model the user selected.
    Uncertain when the selected model's score is within BORDER of 0.5, or when the three models do not agree on
    which side of 0.5 the file is. The models and their scores are unchanged; this only decides what to show."""
    s, why = scores[primary], []
    if BORDER[0] <= s <= BORDER[1]:
        why.append(f"{primary} score {s:.2f} is close to the 0.5 line")
    mal = [m for m, v in scores.items() if v >= 0.5]
    ben = [m for m, v in scores.items() if v < 0.5]
    if mal and ben:
        why.append(f"models disagree (malicious: {', '.join(mal)}; benign: {', '.join(ben)})")
    if why:
        return LABEL_UNC, "; ".join(why)
    return label_for(s), ""


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
    if "extra_json" not in [r[1] for r in con.execute("PRAGMA table_info(scans)")]:
        con.execute("ALTER TABLE scans ADD COLUMN extra_json TEXT")  # PE info for real-file scans
    return con


def _apply_verdict(df):
    """Recompute label and reason from the stored scores, so every scan (older ones too) follows the current rule."""
    out = [verdict(json.loads(r.scores_json), r.model) for r in df.itertuples()]
    df = df.copy()
    df["label"] = [o[0] for o in out]
    df["reason"] = [o[1] for o in out]
    return df


def list_scans():
    with closing(_con()) as con:
        return _apply_verdict(pd.read_sql("SELECT * FROM scans ORDER BY id DESC", con))


def clear_scans():
    with closing(_con()) as con, con:
        con.execute("DELETE FROM scans")


def record_scans(X, names, source, model, sha_list=None, extra_list=None):
    """Score every row with all three models, store one scan per row. Returns the new ids."""
    scores = predict_all(X)
    ids = []
    with closing(_con()) as con, con:
        for i, name in enumerate(names):
            feats = json.loads(X.iloc[[i]].to_json(orient="records"))[0]
            sha = sha_list[i] if sha_list else hashlib.sha256(json.dumps(feats, sort_keys=True).encode()).hexdigest()
            extra = json.dumps(extra_list[i]) if extra_list else None
            s = float(scores[model][i])
            label, _ = verdict({n: float(v[i]) for n, v in scores.items()}, model)
            cur = con.execute(
                "INSERT INTO scans(name,sha256,source,model,score,label,scores_json,features_json,created_at,extra_json)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (name, sha, source, model, s, label,
                 json.dumps({n: float(v[i]) for n, v in scores.items()}), json.dumps(feats),
                 datetime.now().isoformat(timespec="seconds"), extra))
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
    return _apply_verdict(r).iloc[0] if len(r) else None


def ood_notes(f, info):
    """Warnings when an uploaded file looks unlike the ClaMP training samples."""
    feats, df = load_data()
    benign = df[df["class"] == 0]
    notes, reported = [], set()
    share = float(df["FH_char7"].mean())
    if info["pe_format"] == "PE32+":
        notes.append(f"64-bit (PE32+) image, but {share:.1%} of ClaMP samples carry the 32-bit machine flag.")
    for col, label in [("MajorLinkerVersion", "linker version"), ("MajorOperatingSystemVersion", "OS version"),
                       ("MajorSubsystemVersion", "subsystem version")]:
        if f[col] > benign[col].max():
            reported.add(col)
            notes.append(f"{label} {f[col]} is above the maximum seen in benign ClaMP samples ({int(benign[col].max())}).")
    num = [c for c in feats if c != CAT]
    out = [c for c in num if c not in reported and not df[c].min() <= f[c] <= df[c].max()]
    if out:
        notes.append(f"{len(out)} feature value(s) outside the training range: {', '.join(out[:6])}.")
    return notes


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
             f"- **Prediction: {rec['label']}** (model score {rec['score']:.3f})",
             *([f"- Why uncertain: {rec['reason']}"] if rec.get("reason") else []), "",
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
    extra = json.loads(rec["extra_json"]) if isinstance(rec.get("extra_json"), str) else None
    real = bool(extra)
    with st.container(border=True):
        st.caption("FILE ANALYSIS REPORT")
        st.subheader(rec["name"])
        st.caption(f"{'File' if real else 'Feature-vector'} SHA-256: `{rec['sha256']}`  \nSource: {rec['source']}  |  "
                   f"Scanned: {rec['created_at']}")
        icon, colour = {LABEL_MAL: ("🔴", "red"), LABEL_BEN: ("🟢", "green")}.get(rec["label"], ("🟠", "orange"))
        st.markdown(f"#### {icon} :{colour}[{rec['label'].upper()}]")
        if rec.get("reason"):
            st.caption(f"Why: {rec['reason']}. Treat this as unknown rather than a verdict.")
        st.markdown(f"**Model:** {rec['model']} &nbsp;|&nbsp; **Model score:** {rec['score']:.3f}")
        st.progress(float(rec["score"]))
        st.warning("Machine-learning predictions are uncertain. This result does not confirm malicious behaviour. "
                   "The score is a raw model score (for Random Forest, the average vote of its trees), "
                   "not a calibrated probability.", icon="⚠️")
    if real:
        if extra["ood"]:
            st.warning("**Outside the training data** (the verdict is less reliable):\n\n"
                       + "\n".join(f"- {n}" for n in extra["ood"]), icon="🧭")
        st.info("Approximate features: only part of the 58 features can be read exactly from a real file. "
                "The verdict is indicative only. See the provenance table below.", icon="ℹ️")
        i = extra["info"]
        with st.container(border=True):
            st.markdown("**PE file information** (read statically; not all of it is a model feature)")
            a, b, c, d_, e_ = st.columns(5)
            a.metric("Format", i["pe_format"] + (" DLL" if i["is_dll"] else ""))
            b.metric("File size", f"{i['file_size'] / 1024:,.0f} KB")
            c.metric("Sections", len(i["sections"]))
            d_.metric("Imported DLLs", i["imported_dlls"])
            e_.metric("Imported functions", i["imported_functions"])
            st.dataframe(pd.DataFrame(i["sections"]).rename(columns={
                "name": "Section", "virtual_size": "Virtual size", "raw_size": "Raw size", "entropy": "Entropy",
                "flags": "Flags"}), hide_index=True, width="stretch")
            st.caption("High entropy or unusual permissions are clues that need context, not proof of malware.")
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
    with st.expander("All 58 feature values" + (" and where each came from" if real else "")):
        tbl = pd.DataFrame({"value": {k: str(v) for k, v in feats_dict.items()}})
        if real:
            tbl["origin"] = pd.Series(extra["provenance"])
            st.caption("extracted = raw header value or entropy; inferred = flag bit order inferred from the dataset; "
                       "best guess = derived 0/1 flag whose ClaMP definition is unknown; default = not checked.")
        st.dataframe(tbl, width="stretch")
    st.download_button("Download report (Markdown)", report_markdown(rec, ft),
                       file_name=f"report_{rec['id']}.md", mime="text/markdown")
