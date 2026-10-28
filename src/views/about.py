import streamlit as st

st.title("About Project")
st.markdown("""
**Machine-Learning-Based Classification of Executable Files Using Static Analysis** is a university
malware-analysis lab project. It compares Logistic Regression, a Decision Tree and a Random Forest on
statically extracted PE-header features (ClaMP dataset).

### Method
1. Clean the dataset (3 exact duplicates removed) and make ONE stratified 80/20 split (seed 42).
2. Analyse features on the train split only and keep 58 of 69 columns.
3. Tune each model with 5-fold stratified cross-validation on train only.
4. Evaluate on the held-out test split once; the best model is chosen by CV F1 (Random Forest).

### What the Scan File page does
It scores a row of features (a dataset sample, or a CSV you upload) or an uploaded Windows executable, runs all
three models and stores the result in a local scan history. Executables are only **parsed** (`pefile`, in a
separate process with a timeout), never run, and the file is deleted after parsing.

### How reliable is real-file scanning?
Only approximately. The models need the 58 ClaMP features, but ClaMP's definitions are only partly documented:
- 31 features are read directly (header values, entropy, file size).
- 17 are bit flags whose bit order was inferred from the data.
- 8 are derived 0/1 flags whose exact definition is a best guess (`fileinfo`, `CreationYear`, `ImageBase`,
  `SizeOfImage`, `SizeOfHeaders`, `LoaderFlags`, `sus_sections`, `non_sus_sections`).
- 2 are not checked and set to defaults (`packer`, `packer_type`), because no packer signature database is used.

Every report lists where each feature came from, and warns when the file looks unlike the training data
(for example 64-bit files, newer linkers, newer Windows versions). It was tested for false alarms on programs
already installed on this PC, and **not** on real malware, so its detection ability on uploaded files is unknown.

### Limitations
- Old, near-balanced research dataset; scores do not carry over to real traffic.
- Header features only; imported-function and DLL counts are not in the dataset.
- Benign and malware samples may come from different sources (collection artefacts, e.g. `fileinfo`, `CheckSum`).
- The strongest feature (`FH_char12`, probably the DLL flag) is set for 56.3% of benign and 1.8% of malware
  samples, so part of the signal may be file type rather than behaviour.
- One split, no significance test. Packed, obfuscated or adversarial files were not tested.
- Scores are raw model scores, not calibrated probabilities. "Potentially malicious" means predicted malicious,
  not confirmed malware.
""")
