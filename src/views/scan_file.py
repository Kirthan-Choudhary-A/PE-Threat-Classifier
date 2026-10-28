import hashlib
import io

import pandas as pd
import streamlit as st

from dash_common import CAT, get_scan, load_data, ood_notes, record_scans, render_report, test_rows, validate_features
from pe_extract import extract_safely

MAX_ROWS, MAX_BYTES = 50, 2_000_000
feats, _ = load_data()
model = st.session_state.get("active_model", "Random Forest")

st.title("Scan File")
st.caption("Static analysis only. Files are parsed, never executed.")

src = st.radio("Source", ["Dataset sample (test split)", "Upload feature CSV", "Upload executable (approximate)"],
               horizontal=True)
X, names, source, sha_list, extra_list = None, None, None, None, None

if src.startswith("Dataset"):
    t = test_rows()
    mode = st.radio("Row", ["Random", "By index"], horizontal=True)
    if mode == "Random":
        if "scan_idx" not in st.session_state or st.button("Pick another random file"):
            st.session_state.scan_idx = int(t.sample(1).index[0])
        idx = st.session_state.scan_idx
    else:
        idx = int(st.number_input("Test row index", 0, len(t) - 1, 0))
    row = t.iloc[[idx]][feats].copy()
    actual = "malware" if t.loc[idx, "class"] == 1 else "benign"
    st.markdown(f"Selected **test row {idx}**  |  packer: `{row[CAT].iloc[0]}`")
    st.caption(f"Dataset label (hidden in a real scan): **{actual}**. This row was already scored once in the "
               "evaluation, so this is an illustration, not a new evaluation.")
    edited = False
    with st.expander("Edit header values (what-if)"):
        for c in ["E_file", "E_text", "E_data", "filesize", "NumberOfSections", "CheckSum", "fileinfo"]:
            v = float(row[c].iloc[0])
            new = st.number_input(c, value=v, key=f"wi_{c}_{idx}", format="%.4f" if c.startswith("E_") else "%.0f")
            edited |= new != v
            row[c] = new
    X, names = row, [f"testsplit_row_{idx}" + ("_edited" if edited else "")]
    source = f"Test split row {idx}" + (" (values edited)" if edited else "")
elif src.startswith("Upload exec"):
    st.warning("Approximate: the ClaMP feature definitions are only partly documented, so 10 of the 58 features are "
               "guessed or defaulted (packer signatures are not checked). The verdict is indicative only. It was "
               "tested for false alarms on benign programs, not on real malware (no malware was obtained).",
               icon="⚠️")
    up = st.file_uploader("Windows executable (.exe / .dll, max 20 MB). It is parsed in a separate process and "
                          "deleted; only its features and SHA-256 are stored.", type=["exe", "dll"])
    if up is not None:
        st.caption(f"Selected: {up.name} ({up.size / 1024:.1f} KB)")
        if st.button("Extract static features"):
            with st.status("Extracting static features", expanded=True) as status:
                data = up.getvalue()
                st.write("✓ File received")
                res = extract_safely(data)
                if not res["ok"]:
                    status.update(label="Could not analyze this file", state="error")
                    st.session_state.pop("pe_pending", None)
                    st.error(res["error"])
                else:
                    st.write(f"✓ PE format validated ({res['info']['pe_format']})")
                    st.write("✓ Static features extracted with pefile (file not executed)")
                    st.session_state["pe_pending"] = {"name": up.name, "sha": hashlib.sha256(data).hexdigest(), **res}
                    status.update(label="Features extracted", state="complete", expanded=False)
        pend = st.session_state.get("pe_pending")
        if pend and pend["name"] == up.name:
            X = pd.DataFrame([pend["features"]])[feats]
            names, sha_list = [pend["name"]], [pend["sha"]]
            source = "Uploaded executable (static parse, approximate features)"
            extra_list = [{"info": pend["info"], "provenance": {c: pend["provenance"][c] for c in feats},
                           "ood": ood_notes(pend["features"], pend["info"])}]
else:
    template = test_rows().iloc[[0]][feats]
    st.download_button("Download CSV template", template.to_csv(index=False), "feature_template.csv", "text/csv")
    up = st.file_uploader(f"Feature CSV (max {MAX_ROWS} rows, 2 MB). Needs the 58 feature columns; "
                          "optional `filename` column.", type="csv")
    if up is not None:
        st.caption(f"Selected: {up.name} ({up.size / 1024:.1f} KB)")
        if up.size > MAX_BYTES:
            st.error("File too large (limit 2 MB).")
        else:
            try:
                raw = pd.read_csv(io.BytesIO(up.getvalue()))
            except Exception as e:
                st.error(f"Could not read CSV: {e}")
                raw = None
            if raw is not None:
                X, err = validate_features(raw, MAX_ROWS)
                if err:
                    st.error(err)
                else:
                    fn = next((c for c in ("filename", "file_name", "name") if c in raw.columns), None)
                    names = [str(v) for v in raw[fn]] if fn else [f"{up.name}#{i + 1}" for i in range(len(raw))]
                    source = f"Uploaded CSV: {up.name}"

if X is not None and st.button(f"Analyze with {model}", type="primary"):
    with st.status("Analysis in progress", expanded=True) as status:
        st.write("✓ Input received")
        st.write(f"✓ Feature schema validated ({len(feats)} columns, {len(X)} row(s))")
        st.write("✓ Feature vector prepared")
        ids = record_scans(X, names, source, model, sha_list, extra_list)
        st.write("✓ Three models scored; result saved to scan history")
        status.update(label="Analysis complete", state="complete", expanded=False)
    st.session_state["last_scan_ids"] = ids

ids = st.session_state.get("last_scan_ids")
if ids:
    st.divider()
    if len(ids) > 1:
        pick = st.selectbox("Report for", ids, format_func=lambda i: f"{get_scan(i)['name']}  (#{i})")
    else:
        pick = ids[0]
    render_report(get_scan(pick))
