import json

import pandas as pd
import streamlit as st

from dash_common import LABEL_BEN, LABEL_MAL, MODELS, clear_scans, get_scan, list_scans, render_report, top_features

PAGE = 25
st.title("Scan History")
scans = list_scans()
if scans.empty:
    st.info("No scans yet. Use **Scan File** to analyze a feature row.")
    st.stop()

c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
q = c1.text_input("Search file name or SHA-256", placeholder="e.g. testsplit_row_0 or 9f86d0...")
pred = c2.selectbox("Prediction", ["All", LABEL_MAL, LABEL_BEN])
mod = c3.selectbox("Model", ["All", *MODELS])
order = c4.selectbox("Sort", ["Newest first", "Oldest first"])

f = scans
if q:
    f = f[f["name"].str.contains(q, case=False, regex=False) | f["sha256"].str.contains(q, case=False, regex=False)]
if pred != "All":
    f = f[f["label"] == pred]
if mod != "All":
    f = f[f["model"] == mod]
if order == "Oldest first":
    f = f.iloc[::-1]

pages = max(1, -(-len(f) // PAGE))
page = st.number_input(f"Page (of {pages}) — {len(f)} scan(s)", 1, pages, 1)
cur = f.iloc[(page - 1) * PAGE: page * PAGE]
view = pd.DataFrame({"ID": cur["id"], "File": cur["name"], "Feature-vector SHA-256": cur["sha256"].str[:16] + "…",
                     "Prediction": cur["label"], "Model": cur["model"], "Score": cur["score"].round(3),
                     "Analyzed": cur["created_at"]})
ev = st.dataframe(view, hide_index=True, width="stretch", on_select="rerun", selection_mode="multi-row")
st.caption("Select one row to open its report, or exactly two rows to compare them.")
st.download_button("Export filtered metadata (CSV)",
                   f[["id", "name", "sha256", "source", "model", "score", "label", "created_at"]].to_csv(index=False),
                   "scan_history.csv", "text/csv")

sel = [int(cur["id"].iloc[i]) for i in ev.selection.rows]
st.divider()
if len(sel) == 2:
    a, b = get_scan(sel[0]), get_scan(sel[1])
    st.subheader("Side-by-side comparison")
    fa, fb = json.loads(a["features_json"]), json.loads(b["features_json"])
    rows = [("Prediction", a["label"], b["label"]), ("Model", a["model"], b["model"]),
            ("Score", f"{a['score']:.3f}", f"{b['score']:.3f}")]
    rows += [(k, fa[k], fb[k]) for k in ["NumberOfSections", "filesize", "E_file", "packer_type", *top_features(6)]
             if k in fa]
    st.dataframe(pd.DataFrame(rows, columns=["", f"#{a['id']} {a['name']}", f"#{b['id']} {b['name']}"]).astype(str),
                 hide_index=True, width="stretch")
    st.caption("Similar features do not imply the two files belong to the same malware family.")
elif len(sel) == 1 or "view_id" in st.session_state:
    rid = sel[0] if sel else st.session_state["view_id"]
    rec = get_scan(rid)
    if rec is not None:
        render_report(rec)

with st.expander("Danger zone"):
    if st.checkbox("I want to delete all scan history") and st.button("Delete all scans"):
        clear_scans()
        st.session_state.pop("view_id", None)
        st.session_state.pop("last_scan_ids", None)
        st.rerun()
