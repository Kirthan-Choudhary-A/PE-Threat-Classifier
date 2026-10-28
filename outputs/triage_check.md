# Effect of the Uncertain label on the test split (1,042 files)

Descriptive only: the rule was fixed before measuring (score within 0.40-0.60, or the three models disagree) and no model, score or official metric changes. 'Errors' are the selected model's mistakes at the usual 0.5 threshold (false alarms plus misses).

| Selected model | Errors | Files marked Uncertain | Errors among those | Errors caught | Decided files | Errors among decided | Error rate when decided |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 34 | 59 (5.7%) | 31 | 91% | 983 | 3 | 0.31% (was 3.26%) |
| Decision Tree | 28 | 54 (5.2%) | 25 | 89% | 988 | 3 | 0.30% (was 2.69%) |
| Random Forest | 11 | 58 (5.6%) | 8 | 73% | 984 | 3 | 0.30% (was 1.06%) |