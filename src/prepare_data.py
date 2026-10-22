"""Stage 2: load, clean types, dedupe, EDA (descriptive only), ONE stratified split. Seed 42."""
import io
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
D, O = ROOT / "data", ROOT / "outputs"
log = io.StringIO()
def p(*a):
    print(*a); print(*a, file=log)

df = pd.read_csv(D / "ClaMP_Integrated-5184.csv")
p("Raw shape:", df.shape)
p("\nDtypes (counts):", df.dtypes.astype(str).value_counts().to_dict())
p("\nClass balance (raw):", df["class"].value_counts().to_dict())

# coerce non-numeric columns except packer_type (kept as text)
for c in df.columns:
    if c != "packer_type" and not pd.api.types.is_numeric_dtype(df[c]):
        before = df[c].isna().sum()
        df[c] = pd.to_numeric(df[c], errors="coerce")
        p(f"Coerced '{c}': {df[c].isna().sum() - before} new NaN")
non_num = [c for c in df.columns if not pd.api.types.is_numeric_dtype(df[c])]
p("Non-numeric columns after coercion:", non_num)
p("fileinfo values:", df["fileinfo"].value_counts(dropna=False).to_dict())

na = df.isna().sum(); na = na[na > 0]
p("\nColumns with NaN (not imputed here):", na.to_dict() if len(na) else "none")

# duplicates
feat = [c for c in df.columns if c != "class"]
exact = df.duplicated().sum()
conflict = df[df.duplicated(feat, keep=False)].groupby(feat, dropna=False)["class"].nunique()
n_conf_groups = int((conflict > 1).sum())
p(f"\nExact duplicate rows (extra copies): {exact}")
p(f"Feature-identical groups with conflicting labels: {n_conf_groups}")
df = df.drop_duplicates().reset_index(drop=True)
p(f"Rows removed: {exact}; final sample count: {len(df)}")
p("Class balance (deduped):", df["class"].value_counts().to_dict())

# descriptive EDA
p("\nCreationYear value counts:", df["CreationYear"].value_counts().to_dict())
p("packer_type nunique:", df["packer_type"].nunique(), "| top:", df["packer_type"].value_counts().head(5).to_dict())
const = [c for c in df.columns if df[c].nunique(dropna=False) == 1]
p("Constant columns:", const)
p("Mean per class for binary-ish check, fileinfo:", df.groupby("class")["fileinfo"].mean().to_dict())
p("\nNumeric describe (selected):")
p(df[["NumberOfSections", "SizeOfCode", "filesize", "E_file", "E_text", "E_data"]].describe().T.to_string())
neg = (df.select_dtypes("number") < 0).sum(); neg = neg[neg > 0]
p("Columns with negative values:", neg.to_dict() if len(neg) else "none")

# ONE split
X, y = df.drop(columns="class"), df["class"]
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
Xtr.to_csv(D / "X_train.csv", index=False); Xte.to_csv(D / "X_test.csv", index=False)
ytr.to_csv(D / "y_train.csv", index=False); yte.to_csv(D / "y_test.csv", index=False)
p("\nClass counts  full:", y.value_counts().to_dict(), "train:", ytr.value_counts().to_dict(), "test:", yte.value_counts().to_dict())
p("Shapes  X_train:", Xtr.shape, "X_test:", Xte.shape)
O.mkdir(exist_ok=True)
(O / "eda_summary.txt").write_text(log.getvalue(), encoding="utf-8")
