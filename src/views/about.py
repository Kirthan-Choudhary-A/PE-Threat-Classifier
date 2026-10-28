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
It takes a row of pre-extracted features (a dataset sample, or a CSV you upload), runs all three models and
stores the result in a local scan history. It does **not** parse or execute executables.

### Why there is no real `.exe` upload
The models need the exact 58 ClaMP feature definitions. Most header fields could be read with a PE parser, but
`packer_type` comes from a packer-signature database and the exact definitions of `fileinfo` and `sus_sections`
are not documented in the dataset, so features from an uploaded file would not match the training data and the
verdict would be unreliable. Supporting it would mean retraining on features that can be extracted faithfully.

### Limitations
- Old, near-balanced research dataset; scores do not carry over to real traffic.
- Header features only; imported-function and DLL counts are not in the dataset.
- Benign and malware samples may come from different sources (collection artefacts, e.g. `fileinfo`, `CheckSum`).
- One split, no significance test. Packed, obfuscated or adversarial files were not tested.
- Scores are raw model scores, not calibrated probabilities. "Potentially malicious" means predicted malicious,
  not confirmed malware.
""")
