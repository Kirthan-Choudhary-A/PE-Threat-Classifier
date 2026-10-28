"""Smoke test for the dashboard. Run from the project root:  python tests/test_dashboard.py"""
import io
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, "src")
import dash_common as dc
from streamlit.testing.v1 import AppTest

dc.DB = Path(tempfile.mkdtemp()) / "scans.db"  # never touch the real scan history

# upload validation
feats, _ = dc.load_data()
t = dc.test_rows()
good = pd.read_csv(io.StringIO(t.iloc[:3][feats].to_csv(index=False)))
X, err = dc.validate_features(good)
assert err is None and len(X) == 3
assert np.allclose(dc.predict_all(X)["Random Forest"], dc.predict_all(t.iloc[:3])["Random Forest"])
assert dc.validate_features(good.drop(columns=["CheckSum"]))[1].startswith("Missing 1")
bad = good.copy(); bad["CheckSum"] = bad["CheckSum"].astype(str); bad.loc[0, "CheckSum"] = "abc"
assert "CheckSum" in dc.validate_features(bad)[1]
assert "1 to 50" in dc.validate_features(pd.concat([good] * 20))[1]

# every page renders; demo scan + analyze work and are stored
at = AppTest.from_file("../src/app.py", default_timeout=90).run()
assert not at.exception, at.exception
[b for b in at.button if "demo files" in b.label][0].click().run()
assert len(dc.list_scans()) == 5
for page in ["scan_file", "history", "performance", "dataset", "about", "overview"]:
    at.switch_page(f"views/{page}.py").run()
    assert not at.exception, (page, at.exception)
at.switch_page("views/scan_file.py").run()
[b for b in at.button if b.label.startswith("Analyze")][0].click().run()
assert not at.exception and len(dc.list_scans()) == 6
# real-file extraction (static parse of a benign Windows file), error handling, and its report
import os
import pe_extract
sample = r"C:\Windows\System32\notepad.exe"
if os.path.exists(sample):
    res = pe_extract.extract_safely(open(sample, "rb").read())
    assert res["ok"] and set(feats) <= set(res["features"]), res
    assert len(res["info"]["sections"]) > 0 and res["info"]["imported_dlls"] > 0
    Xr = pd.DataFrame([res["features"]])[feats]
    extra = {"info": res["info"], "provenance": {c: res["provenance"][c] for c in feats},
             "ood": dc.ood_notes(res["features"], res["info"])}
    assert any("64-bit" in n for n in extra["ood"])  # modern 64-bit file is flagged as unlike the training data
    rid = dc.record_scans(Xr, ["notepad.exe"], "Uploaded executable (test)", "Random Forest",
                          ["a" * 64], [extra])[0]
    at.session_state["view_id"] = rid
    at.switch_page("views/history.py").run()
    assert not at.exception, at.exception
    assert any("Approximate features" in i.value for i in at.info)
assert not pe_extract.extract_safely(b"hello world")["ok"]
assert not pe_extract.extract_safely(b"MZ" + bytes(200))["ok"]  # MZ but no valid PE headers
assert not pe_extract.extract_safely(b"MZ" + bytes(pe_extract.MAX_BYTES))["ok"]  # over the size limit
# "Uncertain" verdict: borderline score or disagreement between the models (rule fixed in advance, not tuned)
RF, DT, LR = "Random Forest", "Decision Tree", "Logistic Regression"
V = dc.verdict
assert V({RF: .97, DT: 1, LR: 1}, RF)[0] == dc.LABEL_MAL and V({RF: .02, DT: 0, LR: 0}, RF)[0] == dc.LABEL_BEN
lab, why = V({RF: .51, DT: 0, LR: .33}, RF)  # the Uninstall Notion.exe case: borderline AND disagreement
assert lab == dc.LABEL_UNC and "close to the 0.5 line" in why and "models disagree" in why
assert V({RF: .45, DT: .1, LR: .2}, RF)[0] == dc.LABEL_UNC  # all say benign, but too close to the line
assert V({RF: .9, DT: 0, LR: .9}, RF)[0] == dc.LABEL_UNC   # confident score, but a model disagrees
assert V({RF: .4, DT: 0, LR: 0}, RF)[0] == dc.LABEL_UNC and V({RF: .6, DT: 1, LR: 1}, RF)[0] == dc.LABEL_UNC  # edges inclusive
assert V({RF: .39, DT: 0, LR: 0}, RF)[0] == dc.LABEL_BEN and V({RF: .61, DT: 1, LR: 1}, RF)[0] == dc.LABEL_MAL
assert V({RF: .99, DT: 1, LR: .98}, DT)[0] == dc.LABEL_MAL  # the selected model decides which score is checked
assert V({RF: .6, DT: 1, LR: 1}, DT)[0] == dc.LABEL_MAL     # RF near the line does not matter when DT is selected and all agree

# demo rows with Random Forest selected: 0 and 1 malicious, 3 benign, 29 and 19 uncertain (models disagree)
from collections import Counter
demo = dc.list_scans().query("source == 'Test split (demo)'")
assert Counter(demo["label"]) == {dc.LABEL_MAL: 2, dc.LABEL_BEN: 1, dc.LABEL_UNC: 2}, Counter(demo["label"])
rows = dc.list_scans().set_index("name")
assert rows.loc["testsplit_row_29", "label"] == dc.LABEL_UNC and "models disagree" in rows.loc["testsplit_row_29", "reason"]
assert rows.loc["testsplit_row_19", "label"] == dc.LABEL_UNC and rows.loc["testsplit_row_3", "reason"] == ""

# a scan stored before this rule existed (binary label) is shown with the current rule, without rewriting the database
import json
with dc._con() as con:
    con.execute("INSERT INTO scans(name,sha256,source,model,score,label,scores_json,features_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("legacy.exe", "x" * 64, "old", RF, .51, dc.LABEL_MAL, json.dumps({RF: .51, DT: 0, LR: .33}), "{}", "2020-01-01T00:00:00"))
assert dc.list_scans().set_index("name").loc["legacy.exe", "label"] == dc.LABEL_UNC
import sqlite3
assert sqlite3.connect(dc.DB).execute("SELECT label FROM scans WHERE name='legacy.exe'").fetchone()[0] == dc.LABEL_MAL  # stored text untouched

# the pages render with the new label (Overview cards, History filter)
at.switch_page("views/overview.py").run()
assert not at.exception, at.exception
assert any(dc.LABEL_UNC.upper() in c.value.upper() for c in at.caption), [c.value for c in at.caption][:8]
at.switch_page("views/history.py").run()
assert not at.exception, at.exception
print("dashboard smoke test passed")
