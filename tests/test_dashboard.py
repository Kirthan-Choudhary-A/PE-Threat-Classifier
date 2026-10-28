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
print("dashboard smoke test passed")
