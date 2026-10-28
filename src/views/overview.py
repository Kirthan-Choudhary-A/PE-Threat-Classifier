from datetime import datetime, timedelta

import altair as alt
import pandas as pd
import streamlit as st

from dash_common import COLORS, DEMO_ROWS, MODELS, LABEL_BEN, LABEL_MAL, LABEL_UNC, list_scans, metrics_table, record_scans, test_rows

model = st.session_state.get("active_model", "Random Forest")
scans = list_scans()

head, btn = st.columns([4, 1], vertical_alignment="bottom")
head.title("Malware Intelligence Center")
head.caption("Analyze feature rows of Windows executables with static analysis and machine learning.")
btn.page_link("views/scan_file.py", label="Analyze New File", icon=":material/upload_file:")
last = scans["created_at"].iloc[0] if len(scans) else "no scans yet"
st.caption(f"Last analysis: {last}  |  Active model: {model}")

mal = int((scans["label"] == LABEL_MAL).sum())
ben = int((scans["label"] == LABEL_BEN).sum())
unc = int((scans["label"] == LABEL_UNC).sum())
acc = metrics_table().loc[model.lower().replace(" ", "_"), "accuracy"]
cols = st.columns(5)
for col, (title, val, sub) in zip(cols, [
        ("Total scans", len(scans), "scans made in this app"),
        (LABEL_MAL, mal, f"{mal / len(scans):.1%} of scans" if len(scans) else "predictions, not confirmed malware"),
        (LABEL_BEN, ben, f"{ben / len(scans):.1%} of scans" if len(scans) else "no scans yet"),
        (LABEL_UNC, unc, "models disagree or score near 0.5" if not len(scans) else f"{unc / len(scans):.1%} of scans"),
        ("Test accuracy", f"{acc:.2%}", f"{model}, test split (n=1,042)")]):
    with col.container(border=True):
        st.caption(title.upper())
        st.markdown(f"## {val}")
        st.caption(sub)

if scans.empty:
    st.info("No scans yet, so the statistics above are zeros rather than invented numbers. "
            "Use **Analyze New File**, or scan a few real rows from the test split.")
    if st.button("Scan the 5 demo files (real test-split rows)"):
        t = test_rows()
        record_scans(t.iloc[DEMO_ROWS], [f"testsplit_row_{i}" for i in DEMO_ROWS],
                     "Test split (demo)", model)
        st.rerun()

left, right = st.columns([2, 1])
with left.container(border=True):
    st.markdown("**Detection activity**")
    rng = st.selectbox("Range", ["Last 7 days", "Last 30 days", "All time"], key="ov_range", label_visibility="collapsed")
    d = scans.copy()
    if len(d):
        d["date"] = pd.to_datetime(d["created_at"])
        if rng != "All time":
            d = d[d["date"] >= datetime.now() - timedelta(days=7 if rng == "Last 7 days" else 30)]
        d["date"] = d["date"].dt.normalize()
        g = d.groupby(["date", "label"]).size().reset_index(name="scans")
        tot = d.groupby("date").size().reset_index(name="scans").assign(label="Total")
        g = pd.concat([g, tot])
        st.altair_chart(alt.Chart(g).mark_line(point=True).encode(
            x=alt.X("date:T", title=None), y=alt.Y("scans:Q", title="Scans", axis=alt.Axis(tickMinStep=1)),
            color=alt.Color("label:N", title=None, scale=alt.Scale(domain=list(COLORS), range=list(COLORS.values()))),
        ).properties(height=260), width="stretch")
    else:
        st.caption("Nothing to plot yet.")
with right.container(border=True):
    st.markdown("**Model F1 on the test split**")
    mt = metrics_table()
    for name, key in MODELS.items():
        f1 = float(mt.loc[key, "f1"])
        st.markdown(f"**{name}** &nbsp; {f1:.4f}")
        st.progress((f1 - 0.9) / 0.1)
    st.caption("Bars are scaled from F1 0.90 to 1.00. ")
    st.caption("Measured values from outputs/metrics.csv.")

st.markdown("**Recent scans**")
if len(scans):
    recent = scans.head(8)
    view = pd.DataFrame({"File": recent["name"], "Prediction": recent["label"], "Model": recent["model"],
                         "Score": recent["score"].round(3), "Analyzed": recent["created_at"]})
    ev = st.dataframe(view, hide_index=True, width="stretch", on_select="rerun",
                      selection_mode="single-row", key="recent_tbl")
    st.caption("Select a row to open its report.")
    if ev.selection.rows:
        st.session_state["view_id"] = int(recent["id"].iloc[ev.selection.rows[0]])
        st.switch_page("views/history.py")
else:
    st.caption("No scans to show.")
