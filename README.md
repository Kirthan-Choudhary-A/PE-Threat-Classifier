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
```

Each script depends on the output of the previous one. Seed 42 is used everywhere.

## Folder structure

```
data/      dataset CSV and the persisted split (X_train, X_test, y_train, y_test)
src/       the four scripts above
models/    trained pipelines (logistic_regression, decision_tree, random_forest .joblib)
outputs/   all results: text summaries, CSV tables, PNG plots
report/    REPORT.md
```

## Where the results are

- `outputs/eda_summary.txt` - dataset cleaning and split sizes
- `outputs/feature_analysis.txt`, `outputs/selected_features.txt` - feature analysis and the 58 kept features
- `outputs/cv_results.csv`, `outputs/cv_best_params.json` - cross-validation results and best hyperparameters
- `outputs/metrics.csv`, `outputs/evaluation_summary.txt` - final test-set metrics
- `outputs/robustness_cv.csv`, `outputs/lr_C_extended_cv.csv` - robustness check (CV on train only)
- `outputs/*.png` - confusion matrices, ROC curves, model comparison, feature importance

## Report

See [report/REPORT.md](report/REPORT.md) for the aim, method, results and limitations.
