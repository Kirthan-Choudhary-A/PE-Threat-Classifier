# Machine-Learning-Based Classification of Executable Files Using Static Analysis

University malware-analysis lab project. Train and compare ML models that classify Windows PE files as benign (0) or malicious (1) using ONLY statically extracted PE-header features. These rules bind the lead agent and every subagent.

## Safety
- Work only from a pre-extracted feature CSV.
- Never download, unpack, or run a real malware binary.

## Dataset
- ClaMP `ClaMP_Integrated-5184.csv` (~5,200 labelled samples, 69 PE-header features), placed in `data/`.
- Target column: `class` (1 = malware, 0 = benign).
- `fileinfo` is a 0/1 flag stored as text. Coerce it to numeric.

## Data hygiene
- ONE stratified train/test split (`test_size=0.2`, `random_state=42`), persisted once and reused everywhere.
- Fit scalers/selectors on the TRAIN split only.
- Never tune on the test set. Use cross-validation on train.
- Touch the test set once, at final evaluation.

## Models
- Logistic Regression (scaled, inside a `Pipeline`)
- Decision Tree
- Random Forest

## Metrics (report ALL)
- Precision, recall, F1
- False-positive rate = FP / (FP + TN)
- Confusion matrix
- ROC-AUC
- Feature-importance plot for the best model

## Reproducibility
- Seed 42 everywhere.
- Maintain `requirements.txt`.
- Layout: `data/  src/  outputs/  models/  report/`.

## Honesty
- Report only real measured numbers. Never invent or round up.
- Always note limitations.
- Keep the write-up factual and student-level, not overstated as professional.

## Workflow
Stages run in order, pausing after each for user review:
ponytail (plan, wait for approval) -> data-engineer -> feature-analyst -> ml-trainer -> model-evaluator -> report-writer.
If the dataset cannot be downloaded, stop and ask the user.
