import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from dash_common import CAT, ROOT, load_data, top_features


@st.cache_data
def raw_stats():
    raw = pd.read_csv(ROOT / "data/ClaMP_Integrated-5184.csv")
    return len(raw), int(raw.duplicated().sum())


feats, df = load_data()
num = [c for c in feats if c != CAT]
raw_n, raw_dups = raw_stats()
ben, mal = int((df["class"] == 0).sum()), int((df["class"] == 1).sum())
tr, te = int((df["split"] == "train").sum()), int((df["split"] == "test").sum())

st.title("Dataset Explorer")
st.caption("ClaMP Integrated: pre-extracted PE-header features. The file is named 5184 but has "
           f"{raw_n:,} rows. Only feature values are shown here; no executables are stored or downloadable.")

cards = [("Samples (cleaned)", f"{len(df):,}"), ("Benign", f"{ben:,}"), ("Malicious", f"{mal:,}"),
         ("Missing values", f"{int(df[feats].isna().sum().sum())}"),
         ("Duplicates removed", f"{raw_dups}"), ("Train / test", f"{tr:,} / {te:,}")]
for col, (t, v) in zip(st.columns(6), cards):
    with col.container(border=True):
        st.caption(t.upper())
        st.markdown(f"#### {v}")

a, b = st.columns([1, 2])
with a.container(border=True):
    st.markdown("**Class distribution**")
    cd = pd.DataFrame({"class": ["Benign", "Malicious"], "n": [ben, mal]})
    st.altair_chart(alt.Chart(cd).mark_arc(innerRadius=60).encode(
        theta="n:Q", color=alt.Color("class:N", title=None, scale=alt.Scale(
            domain=["Benign", "Malicious"], range=["#22c55e", "#ef4444"]))).properties(height=260), width="stretch")
    st.caption(f"Near-balanced ({mal / len(df):.1%} malicious), unlike real-world traffic. "
               "Split is stratified, seed 42.")

with b.container(border=True):
    st.markdown("**Feature distribution by class**")
    c1, c2 = st.columns([2, 1])
    default = top_features(1)[0]
    f = c1.selectbox("Feature", num, index=num.index(default))
    use_log = c2.checkbox("log10(x+1) scale", value=bool((df[f] > 1000).any()))
    d = df[[f, "class"]].copy()
    d["class"] = d["class"].map({0: "Benign", 1: "Malicious"})
    if use_log:
        d[f] = np.log10(d[f].clip(lower=0) + 1)
    st.altair_chart(alt.Chart(d).mark_bar(opacity=0.6, binSpacing=0).encode(
        x=alt.X(f"{f}:Q", bin=alt.Bin(maxbins=40), title=f + (" (log10)" if use_log else "")),
        y=alt.Y("count():Q", stack=None, title="Samples"),
        color=alt.Color("class:N", title=None, scale=alt.Scale(
            domain=["Benign", "Malicious"], range=["#22c55e", "#ef4444"]))).properties(height=260), width="stretch")
    st.caption("Imported-function and DLL counts are not in this dataset, so they cannot be shown.")

with st.container(border=True):
    st.markdown("**Feature correlation heatmap**")
    chosen = st.multiselect("Features", num, default=[c for c in top_features(12) if c in num])
    if len(chosen) >= 2:
        corr = df[chosen].corr(method="spearman").stack().reset_index()
        corr.columns = ["a", "b", "r"]
        base = alt.Chart(corr).encode(x=alt.X("a:N", title=None), y=alt.Y("b:N", title=None))
        st.altair_chart(base.mark_rect().encode(color=alt.Color("r:Q", scale=alt.Scale(scheme="redblue", domain=[-1, 1])))
                        + base.mark_text(fontSize=10).encode(text=alt.Text("r:Q", format=".2f")),
                        width="stretch")
    st.caption("Spearman rank correlation over all cleaned samples. Correlation does not establish causation or "
               "prove a feature is useful for detection.")

with st.expander("Dataset notes"):
    st.markdown("- Source: ClaMP Integrated (research dataset, older malware and software).\n"
                "- Cleaning: 3 exact duplicate rows removed; no feature-identical rows with conflicting labels.\n"
                "- 58 of 69 feature columns used (11 constant or duplicate columns dropped, train split only).\n"
                "- `fileinfo` and `CheckSum` differ strongly between classes and may reflect how the samples "
                "were collected; see the robustness check on Model Performance.")
