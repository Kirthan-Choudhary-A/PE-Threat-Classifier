"""False-alarm probe: run the extractor + trained models on programs already installed on this PC.

These files are ASSUMED benign (Windows and installed software); that is not verified, and no malware is used,
so this measures false alarms only, never detection. Results -> outputs/real_file_probe.txt.
Run from the project root:  python src/probe_benign_files.py   (about 2 minutes)"""
import os
import random
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dash_common as dc
import pe_extract

ROOTS = [r"C:\Program Files", r"C:\Program Files (x86)", r"C:\Python314", r"C:\Windows\System32",
         r"C:\Windows\SysWOW64", r"C:\Windows"]
feats, _ = dc.load_data()


def candidates(exts, limit):
    out = []
    for root in ROOTS:
        for dp, _, fn in os.walk(root):
            for f in fn:
                if f.lower().endswith(exts):
                    p = os.path.join(dp, f)
                    try:
                        if 5_000 < os.path.getsize(p) < 15_000_000:
                            out.append(p)
                    except OSError:
                        pass
            if len(out) > limit:
                return sorted(set(out))
    return sorted(set(out))


def probe(files, want_dll=None):
    res = []
    for p in files:
        r = pe_extract.extract_safely(open(p, "rb").read(), timeout=20)
        if not r["ok"] or (want_dll is not None and r["info"]["is_dll"] != want_dll):
            continue
        s = dc.predict_all(pd.DataFrame([r["features"]])[feats])
        res.append({"path": p, "fmt": r["info"]["pe_format"], "dll": r["info"]["is_dll"],
                    **{k: float(v[0]) for k, v in s.items()}})
    return pd.DataFrame(res)


lines = ["False-alarm probe on files installed on this PC (assumed benign; no malware used)", ""]
for title, exts, seed, n, want_dll in [("EXE files", (".exe",), 7, 80, False), ("DLL files", (".dll",), 42, 60, True)]:
    random.seed(seed)
    pool = candidates(exts, 6000)
    df = probe(random.sample(pool, min(n, len(pool))), want_dll)
    lines.append(f"{title}: {len(df)} parsed (sampling seed {seed}); formats {dict(Counter(df['fmt']))}")
    for m in dc.MODELS:
        lines.append(f"  {m}: flagged {int((df[m] >= 0.5).sum())}/{len(df)} as potentially malicious; "
                     f"highest score {df[m].max():.3f}")
    lines.append("")
Path(dc.OUT / "real_file_probe.txt").write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines))
