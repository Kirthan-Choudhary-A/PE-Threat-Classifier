# Machine-Learning-Based Classification of Executable Files Using Static Analysis

A university malware-analysis lab project. It trains and compares three classifiers (Logistic Regression, Decision Tree, Random Forest) that label Windows PE files as benign (0) or malicious (1), using only statically extracted PE-header features from the ClaMP dataset. All models are tuned with cross-validation on a single training split, and the held-out test split is used once for the final evaluation. Full write-up: [report/REPORT.md](report/REPORT.md).

## Safety note

This project works only from a pre-extracted feature CSV. No malware binary is downloaded, unpacked, or executed at any point.

## Dataset

`data/ClaMP_Integrated-5184.csv` is the dataset file (ClaMP, 69 PE-header features plus the `class` label). Despite the "5184" in the file name, it actually contains 5,210 rows. Put the file in `data/` before running anything.

## Install

```
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
```

## Run (in order, from the project root)

```
python src/prepare_data.py      # clean, dedupe, EDA, ONE stratified 80/20 split (seed 42)
python src/analyze_features.py  # feature analysis on the train split only; writes selected_features.txt
python src/train_models.py      # GridSearchCV (5-fold) on train only; saves models/*.joblib
python src/evaluate_models.py   # opens the test split once; metrics, plots, evaluation_summary.txt
python src/robustness_cv.py     # optional: CV-only robustness check (train split), wider LR C grid
python src/dll_shortcut_cv.py   # optional: CV-only check of the DLL-like flag shortcut (train split)
python src/repeated_splits.py   # optional: variance across 20 random splits (about 2 minutes)
python src/improve_cv.py        # optional: CV-only search for better models (about 10 minutes; found no clear gain)
```

Each script depends on the output of the previous one. Seed 42 is used everywhere.

## Demo dashboard

After running the four scripts above (the dashboard reads their saved outputs and models), start it from the project root:

```
python -m streamlit run src/app.py
```

Use `python -m streamlit` (not the bare `streamlit` command) so it runs in the same Python that has the project packages. It opens at http://localhost:8501 with a dark multi-page layout:

- **Overview**: scan counts, activity chart and recent scans (zeros and empty states until you scan something), plus the real test accuracy.
- **Scan File**: score a dataset sample (with what-if editing), an uploaded feature CSV (template provided), or an uploaded Windows executable (**approximate**: parsed statically with `pefile`, never run; 10 of the 58 features are guessed or defaulted, and the report says which). Shows all three models, PE sections and imports, "outside training data" warnings, top features vs dataset medians, and a Markdown download.
- **Scan History**: search, filter, export, open a report, or compare two scans.
- **Model Performance**: real test metrics, grouped bar chart, ROC and precision-recall curves, confusion matrices, feature importance, CV vs test and the robustness check.
- **Dataset Explorer**: class balance, data-quality counts, per-class feature histograms and a correlation heatmap.
- **About Project**: method and limitations.

Scans are stored in `data/scans.db` (not committed). Uploaded executables are parsed in a separate process with a timeout and deleted afterwards; only their features and SHA-256 are stored. Nothing is ever executed. Real-file scanning has only been checked for false alarms on programs installed on this PC (`python src/probe_benign_files.py`, results in `outputs/real_file_probe.txt`), not on malware. Dataset samples come from the test split, which was already scored once, so they illustrate the models and are not a new evaluation.

Smoke test: `python tests/test_dashboard.py`. Screenshots of every page are in `report/screenshots/` (regenerate with `python tests/take_screenshots.py`, needs `pip install playwright` and Microsoft Edge; it uses a throwaway scan database).

## Folder structure

```
data/      dataset CSV and the persisted split (X_train, X_test, y_train, y_test)
src/       the pipeline scripts, plus app.py and views/ (dashboard)
tests/     dashboard smoke test
models/    trained pipelines (logistic_regression, decision_tree, random_forest .joblib)
outputs/   all results: text summaries, CSV tables, PNG plots
report/    REPORT.md, DEMO_GUIDE.md (demo flow and viva Q&A), screenshots/
```

## Where the results are

- `outputs/eda_summary.txt` - dataset cleaning and split sizes
- `outputs/feature_analysis.txt`, `outputs/selected_features.txt` - feature analysis and the 58 kept features
- `outputs/cv_results.csv`, `outputs/cv_best_params.json` - cross-validation results and best hyperparameters
- `outputs/metrics.csv`, `outputs/evaluation_summary.txt` - final test-set metrics
- `outputs/robustness_cv.csv`, `outputs/lr_C_extended_cv.csv` - robustness check (CV on train only)
- `outputs/dll_shortcut_cv.csv`, `outputs/dll_shortcut_subgroups.csv` - DLL-like flag check (CV on train only)
- `outputs/repeated_splits.csv`, `outputs/repeated_splits_summary.csv` - variation across 20 random splits
- `outputs/*.png` - confusion matrices, ROC curves, model comparison, feature importance

## Report

See [report/REPORT.md](report/REPORT.md) for the aim, method, results and limitations.
