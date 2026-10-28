# Demo and viva guide

All numbers below come from the files in `outputs/`.

## Before you start
1. Open a terminal in the project folder and run `python -m streamlit run src/app.py` (not the bare `streamlit` command).
2. Open http://localhost:8501 and hard-refresh (`Ctrl+Shift+R`).
3. Keep one benign Windows file ready for the upload, for example `C:\Windows\System32\notepad.exe`.

## One-sentence summary
"I trained three models (Logistic Regression, Decision Tree, Random Forest) on PE-header features from the ClaMP dataset to tell benign from malicious Windows files without running them. Random Forest is best, with test F1 0.9899, and I measured where the result is weaker."

## Demo flow (about 6 minutes)

**1. Overview (30 s).** Say what the page is for. The stat cards show zero until you scan, which is deliberate: no invented numbers. Click **Scan the 5 demo files**. These are real rows from the held-out test split. With Random Forest selected the cards then show 5 scans: 2 potentially malicious, 1 predicted benign and **2 Uncertain**.

**2. Scan File, dataset sample (2 min).** Choose *Dataset sample*, then *By index*, and scan these rows:

| Row | Dataset label | What to say |
|---|---|---|
| 0 | malware | All three models say about 1.0. A clear case. |
| 3 | benign | All three say about 0. A clear case. |
| 29 | benign | **Uncertain.** Random Forest scores 0.577, but the Decision Tree says 1.0 and Logistic Regression 0.0. On its own this would be a *false alarm*; the dashboard shows it as unknown instead. This is why I report false-positive rate, not just accuracy. |
| 19 | malware | **Uncertain.** Random Forest scores 0.477, just under the 0.5 line, while the other two lean malicious. On its own this would be a *miss*. |

Say what **Uncertain** means: the selected model's score is within 0.40-0.60, or the three models disagree. The rule was fixed in advance and changes no model or metric. On the test split it sets aside 58 of 1,042 files (5.6%), 8 of the Random Forest's 11 mistakes are among them, and the error rate on the other files is 0.30% (was 1.06%). Be upfront about the cost: 50 of those 58 were classified correctly, so it is a triage aid, not a better classifier.

Open **Edit header values (what-if)** on row 0, set `E_file`, `E_data`, `E_text`, `CheckSum` and `filesize` to 0, and rescan. In my test the Random Forest score dropped from 1.0 to 0.877. Say the models react to the values directly. Do not claim the edited file is realistic.

**3. Scan File, real executable (1.5 min).** Choose *Upload executable (approximate)* and upload `notepad.exe`. Click **Extract static features** and then **Analyze**. Point out:
- the file is parsed, never run;
- the PE sections table and import counts;
- the "outside the training data" box (64-bit, newer linker and OS versions);
- the yellow "approximate" banner, and open **Why is this approximate?**.

**4. Model Performance (1.5 min).** Test results: Random Forest F1 0.9899, FPR 0.0100 (5 false alarms among 498 benign files, 6 missed among 544 malware); Decision Tree 0.9742; Logistic Regression 0.9686; majority baseline 0.6860. Open the three expanders: cross-validation vs test, the DLL-flag check, and the 20-split variation.

**5. Close with limitations (30 s).** Read them yourself before anyone asks: old near-balanced dataset, header features only, a possible file-type shortcut, and real-file scanning not tested on malware.

## Likely questions, with honest answers

**Did you ever see a false alarm on a real program?** Yes. `Uninstall Notion.exe`, a 158 KB installer stub, scored 0.51 on the Random Forest while the other two models said benign. It is not a DLL, it has high entropy from the compressed payload, an old linker version and stripped header flags, so it looks like old packed malware to a model trained on older data. That case is why I added the **Uncertain** verdict: a borderline score or disagreeing models is shown as unknown instead of "malicious".

**Why not just report accuracy?** A false alarm blocks legitimate software, so I report precision, recall, F1, FPR, the confusion matrix and ROC-AUC. Random Forest: FPR 0.0100.

**How do you know you didn't tune on the test set?** Hyperparameters were chosen by 5-fold CV on the train split only. Random Forest was picked by CV F1 before the test split was opened, and the test split was scored once.

**Is 99% realistic?** No. ClaMP is old and near 50/50. Across 20 random re-splits, Random Forest F1 was 0.9926 +/- 0.0027 (range 0.9872 to 0.9963), so the single-split number is representative, but real traffic is different.

**Is it just detecting DLLs?** Partly, possibly. `FH_char12` (most likely the DLL flag) is the top feature: set for 56.3% of benign and 1.8% of malware samples. The bare rule "malware if not a DLL" gets F1 0.8231 on the train split, far below the models. Removing the flag barely changes Random Forest (CV F1 0.9908 to 0.9902) but lowers Logistic Regression by 0.0157. False alarms are higher on EXE-like files (Random Forest FPR 0.0262 in CV) than overall.

**Could `fileinfo` or `CheckSum` be dataset artefacts?** Possibly: they differ strongly between classes. Dropping `fileinfo`, `CheckSum` and `filesize` still leaves Random Forest at CV F1 0.9845, so the result doesn't hinge on them.

**How good is scanning a real file?** Only approximate. 31 features are read directly, 17 are flag bits whose order I inferred from the data, 8 are best-guess flags and 2 are defaults (the packer columns). I only checked false alarms on programs installed on my PC: 0 of 62 `.exe` files flagged by Random Forest (Logistic Regression 4, Decision Tree 1). I did not test it on real malware, so I can't claim it detects modern malware.

**Why not test on real malware?** No legally obtained samples, and handling them safely needs an isolated VM. The assignment says to avoid executing samples, and the dataset covers that.

**What about the imported-function and DLL counts the assignment lists?** They are not in ClaMP, so the models can't use them. The dashboard shows import counts for uploaded files only as information. The report says so in Section 3.

**Could malware evade it?** Yes. Packed, obfuscated or header-forged files and adversarial samples were not tested.

**What would you do next?** Train on a modern dataset with import features, check score calibration, and evaluate on a time-based split.

## If something goes wrong
- Page won't load or shows `ImportError`: stop the server (`Ctrl+C`) and start it again. A stale server caches old code.
- Port busy: add `--server.port 8600`.
- Screenshots of every page are in `report/screenshots/` as a fallback.
