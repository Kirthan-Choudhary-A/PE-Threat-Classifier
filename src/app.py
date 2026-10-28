"""StaticScan ML dashboard. Run from the project root:  python -m streamlit run src/app.py
Static-analysis malware classifier demo: results, dataset, and scans of feature rows. Nothing is executed."""
import streamlit as st

from dash_common import MODELS, OUT, load_models

st.set_page_config(page_title="StaticScan ML", page_icon="🛡️", layout="wide")

pages = [
    st.Page("views/overview.py", title="Overview", icon=":material/dashboard:", default=True),
    st.Page("views/scan_file.py", title="Scan File", icon=":material/upload_file:"),
    st.Page("views/history.py", title="Scan History", icon=":material/history:"),
    st.Page("views/performance.py", title="Model Performance", icon=":material/monitoring:"),
    st.Page("views/dataset.py", title="Dataset Explorer", icon=":material/dataset:"),
    st.Page("views/about.py", title="About Project", icon=":material/info:"),
]
pg = st.navigation(pages)

with st.sidebar:
    st.markdown("### StaticScan ML")
    st.caption("PE-header malware classification")
    st.selectbox("Active model", list(MODELS), index=2, key="active_model")
    loaded = len(load_models())
    ok = loaded == len(MODELS) and (OUT / "metrics.csv").exists()
    st.markdown(f"{'🟢' if ok else '🔴'} Models loaded: {loaded}/{len(MODELS)}")
    st.caption("Static analysis only. Nothing is executed.")

pg.run()
