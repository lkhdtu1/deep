# Project 5 Requirements and Report Analysis

## 1. Exact Requirement Extraction from `doc.pdf`

Project 5 in [`doc.pdf`](/home/kali/deep/doc.pdf) states:

- Core idea: make IDS decisions interpretable and assess explanation reliability.
- Dataset: NSL-KDD.
- Key challenges:
  - interpreting black-box models
  - evaluating explanation stability
  - assessing adversarial risks
- Tasks:
  - train model
  - apply explainability
  - evaluate stability
  - analyze security implications
- Deliverables:
  - explanation analysis
  - security report
- Expected output:
  - explanation and security analysis

The general course requirements also add:

- baseline model
- at least 3 experimental variations
- appropriate metrics such as precision, recall, F1, PR-AUC
- fixed random seeds
- documented preprocessing
- report PDF, code with README, reproducibility file

## 2. What Is Present in This Workspace

Core project files:

- [`pipeline.py`](/home/kali/deep/pipeline.py)
- [`KDDTrain+.txt`](/home/kali/deep/KDDTrain+.txt)
- [`KDDTest+.txt`](/home/kali/deep/KDDTest+.txt)
- [`requirements.txt`](/home/kali/deep/requirements.txt)
- [`outputs/shap_beeswarm_rf.png`](/home/kali/deep/outputs/shap_beeswarm_rf.png)
- [`outputs/shap_comparison.png`](/home/kali/deep/outputs/shap_comparison.png)
- [`outputs/shap_stability.png`](/home/kali/deep/outputs/shap_stability.png)
- [`outputs/evasion_heatmap.png`](/home/kali/deep/outputs/evasion_heatmap.png)

Older report artifacts already in the folder:

- [`Project5_FinalReport.docx`](/home/kali/deep/Project5_FinalReport.docx)
- [`Project5_StudyGuide.docx`](/home/kali/deep/Project5_StudyGuide.docx)
- [`pipeline_report.tex`](/home/kali/deep/pipeline_report.tex)
- [`pipeline_report.pdf`](/home/kali/deep/pipeline_report.pdf)

## 3. Compliance Check Against the Assignment

Requirement -> status in this workspace

- Use NSL-KDD -> satisfied.
- Train model -> satisfied.
- Apply explainability -> satisfied with SHAP and LIME.
- Evaluate stability -> satisfied with Jaccard similarity over top-10 SHAP features.
- Analyze security implications -> satisfied with SHAP-guided evasion and defense discussion.
- Include a baseline model -> satisfied with Logistic Regression.
- At least 3 experimental variations -> satisfied if framed carefully:
  - Logistic Regression baseline
  - Random Forest + TreeSHAP
  - MLP + KernelSHAP
  - LIME and adversarial analysis are additional analyses, not replacements for core model variations
- Use appropriate metrics -> satisfied.
- Fixed seeds -> satisfied in code.
- Document preprocessing -> code does it; dedicated documentation was missing and is now added.
- Code with README -> was missing; now added.
- Reproducibility file -> was missing; now added.

## 4. Verified Experimental Results

These values were produced by running [`pipeline.py`](/home/kali/deep/pipeline.py) inside the local `venv`.

### Model Performance

- Logistic Regression:
  - macro precision `0.78`
  - macro recall `0.77`
  - macro F1 `0.7535`
  - PR-AUC `0.8864`
- Random Forest:
  - macro precision `0.81`
  - macro recall `0.80`
  - macro F1 `0.7726`
  - PR-AUC `0.9650`
- MLP:
  - macro precision `0.82`
  - macro recall `0.82`
  - macro F1 `0.8060`
  - PR-AUC `0.9461`

### Explainability

Top RF SHAP features:

1. `flag_SF`
2. `logged_in`
3. `dst_host_srv_count`
4. `dst_host_same_srv_rate`
5. `same_srv_rate`
6. `diff_srv_rate`
7. `service_private`
8. `dst_host_rerror_rate`
9. `count`
10. `dst_host_srv_serror_rate`

Top LIME features:

1. `service_private`
2. `logged_in`
3. `wrong_fragment`
4. `dst_host_rerror_rate`
5. `rerror_rate`
6. `flag_SF`
7. `service_ecr_i`
8. `dst_host_srv_serror_rate`
9. `protocol_type_icmp`
10. `flag_S0`

Cross-model explanation agreement:

- SHAP Spearman correlation between RF and MLP global importances: `0.745`

### Stability

- SHAP top-10 Jaccard stability on similar attack pairs: `0.994 ± 0.037`

### Security Analysis

Observed evasion rates:

- Top-5 features:
  - `eps=0.05`: `34.86%`
  - `eps=0.10`: `33.60%`
  - `eps=0.20`: `32.26%`
- Top-10 features:
  - `eps=0.05`: `35.49%`
  - `eps=0.10`: `35.04%`
  - `eps=0.20`: `34.59%`
- Top-15 features:
  - `eps=0.05`: `35.49%`
  - `eps=0.10`: `34.14%`
  - `eps=0.20`: `33.51%`

Defense result:

- Evasion without defense: `35.04%`
- Evasion with defense: `35.04%`
- Improvement: `0.0%`

## 5. Why the Current Report Feels Unconvincing

The problem is not mainly the numerical results. The problem is the framing.

Main weaknesses in [`Project5_FinalReport.docx`](/home/kali/deep/Project5_FinalReport.docx):

- It claims deliverables that are not in the workspace, such as a separate threat-model file, reproducibility file, README, and slide deck.
- It contains placeholders like `[run output]`, which makes the report look unfinished.
- It overstates compliance by presenting optional extras as if they were already packaged.
- It does not clearly separate:
  - what the assignment explicitly requires
  - what the code actually does
  - what the measured results support
- It does not explain the apparent contradiction that the MLP has higher macro F1 while the RF has higher PR-AUC.
- It treats the `0%` defense result as a side note instead of interpreting it as an important negative finding.

## 6. Stronger Interpretation of the Results

### Why the results are defensible

- NSL-KDD is intentionally difficult because the test split includes attacks not represented in training.
- Macro F1 between `0.75` and `0.81` is therefore not evidence of failure by itself.
- RF PR-AUC `0.9650` indicates strong attack ranking quality across thresholds even when the default threshold gives lower recall.
- MLP macro F1 `0.8060` suggests better thresholded classification balance on this split, but its PR-AUC is lower than RF, so superiority is not absolute.

### What to say instead of “the results are not good”

- The models are competent but not uniformly strong across all evaluation criteria.
- The assignment is about explainability reliability and security implications, not only maximizing raw classification accuracy.
- The strongest contribution is the dual-use security argument: explanations that help analysts can also help attackers.

### What the professor is likely to find convincing

- A tight mapping to the exact assignment text.
- Honest discussion of tradeoffs between interpretability, fidelity, and robustness.
- Clear explanation of why stability is high while security risk still exists.
- Explicit statement that the defense failed and why that matters.

## 7. Recommended Final Report Structure

Use this structure for the final PDF:

1. Abstract
2. Assignment requirements and experimental framing
3. Dataset and preprocessing
4. Models and baseline/variations
5. Explainability methods
6. Results
7. Stability analysis
8. Security implications and adversarial analysis
9. Limitations
10. Conclusion

That structure matches the assignment better than the current overextended compliance-first draft.
