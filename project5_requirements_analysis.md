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
- [`outputs/evasion_heatmap_local.png`](/home/kali/deep/outputs/evasion_heatmap_local.png)

Supporting deliverables now present:

- [`README.md`](/home/kali/deep/README.md)
- [`reproducibility.md`](/home/kali/deep/reproducibility.md)
- [`threat_model.md`](/home/kali/deep/threat_model.md)
- [`project5_report_draft.md`](/home/kali/deep/project5_report_draft.md)
- [`claude_final_report_prompt.txt`](/home/kali/deep/claude_final_report_prompt.txt)

## 3. Compliance Check Against the Assignment

Requirement -> status in this workspace

- Use NSL-KDD -> satisfied.
- Train model -> satisfied.
- Apply explainability -> satisfied with SHAP and LIME.
- Evaluate stability -> satisfied with local and bootstrap SHAP stability analysis.
- Analyze security implications -> satisfied with global and local SHAP-guided evasion plus defense discussion.
- Include a baseline model -> satisfied with Logistic Regression.
- At least 3 experimental variations -> satisfied:
  - Logistic Regression baseline
  - Random Forest + TreeSHAP
  - MLP + KernelSHAP
  - LIME and adversarial analysis are additional analyses beyond the minimum requirement
- Use appropriate metrics -> satisfied with precision, recall, macro F1, PR-AUC, balanced accuracy, family recall, stability, and evasion.
- Fixed seeds -> satisfied in code.
- Document preprocessing -> satisfied in code and supporting docs.
- Code with README -> satisfied.
- Reproducibility file -> satisfied.

## 4. Verified Experimental Results

These values were produced by running [`pipeline.py`](/home/kali/deep/pipeline.py) inside the local `venv` after the tuning and analysis improvements.

### Model Performance

- Logistic Regression:
  - macro precision `0.79`
  - macro recall `0.78`
  - macro F1 `0.7601`
  - PR-AUC `0.8806`
  - balanced accuracy `0.7798`
- Random Forest:
  - macro precision `0.81`
  - macro recall `0.82`
  - macro F1 `0.8007`
  - PR-AUC `0.9677`
  - balanced accuracy `0.8156`
- MLP:
  - macro precision `0.82`
  - macro recall `0.82`
  - macro F1 `0.8047`
  - PR-AUC `0.9246`
  - balanced accuracy `0.8194`

Attack-family recall:

- Logistic Regression:
  - DoS `0.824`
  - Probe `0.815`
  - R2L `0.026`
  - U2R `0.119`
- Random Forest:
  - DoS `0.866`
  - Probe `0.867`
  - R2L `0.177`
  - U2R `0.269`
- MLP:
  - DoS `0.861`
  - Probe `0.910`
  - R2L `0.170`
  - U2R `0.448`

### Explainability

Top RF SHAP features:

1. `flag_SF`
2. `dst_host_srv_count`
3. `logged_in`
4. `same_srv_rate`
5. `dst_host_same_srv_rate`
6. `service_private`
7. `dst_host_rerror_rate`
8. `count`
9. `dst_host_diff_srv_rate`
10. `diff_srv_rate`

Top LIME features:

1. `service_private`
2. `wrong_fragment`
3. `logged_in`
4. `dst_host_rerror_rate`
5. `service_ecr_i`
6. `rerror_rate`
7. `flag_SF`
8. `protocol_type_icmp`
9. `count`
10. `serror_rate`

Cross-model explanation agreement:

- SHAP Spearman correlation between RF and MLP global importances: `0.729`
- Mean LIME local fidelity: `0.694`

### Stability

- Local SHAP top-10 Jaccard stability on nearest-neighbor attack pairs: `0.909 ± 0.141`
- Local SHAP rank-correlation stability: `0.991`
- Bootstrap SHAP top-10 Jaccard stability: `0.927`
- Bootstrap SHAP rank-correlation stability: `0.992`

### Security Analysis

Observed evasion rates:

- Global SHAP attack:
  - Top-5:
    - `eps=0.05`: `34.62%`
    - `eps=0.10`: `34.05%`
    - `eps=0.20`: `33.90%`
  - Top-10:
    - `eps=0.05`: `35.19%`
    - `eps=0.10`: `35.19%`
    - `eps=0.20`: `36.47%`
  - Top-15:
    - `eps=0.05`: `36.11%`
    - `eps=0.10`: `36.11%`
    - `eps=0.20`: `36.82%`
- Local instance-specific SHAP attack:
  - Top-5:
    - `eps=0.05`: `38.46%`
    - `eps=0.10`: `38.18%`
    - `eps=0.20`: `37.96%`
  - Top-10:
    - `eps=0.05`: `36.68%`
    - `eps=0.10`: `34.26%`
    - `eps=0.20`: `34.54%`
  - Top-15:
    - `eps=0.05`: `35.47%`
    - `eps=0.10`: `31.13%`
    - `eps=0.20`: `30.63%`

Defense result:

- Evasion without defense: `34.26%`
- Evasion with defense: `34.26%`
- Improvement: `0.0%`

## 5. Why the Earlier Report Felt Unconvincing

The problem was not mainly the numerical results. The problem was the framing.

Main weaknesses in [`Project5_FinalReport.docx`](/home/kali/deep/Project5_FinalReport.docx):

- It claimed deliverables that were not all present in the workspace.
- It contained placeholders like `[run output]`, which made the report look unfinished.
- It overstates compliance by presenting optional extras as if they were already packaged.
- It did not clearly separate:
  - what the assignment explicitly requires
  - what the code actually does
  - what the measured results support
- It did not explain the tradeoff between strong aggregate metrics and very weak minority-family recall.
- It treated the failed defense as a side note instead of interpreting it as an important negative finding.

## 6. Stronger Interpretation of the Results

### Why the results are defensible

- NSL-KDD is intentionally difficult because the test split includes attacks not represented in training.
- Macro F1 around `0.76` to `0.80` is therefore not evidence of failure by itself.
- RF PR-AUC `0.9677` indicates very strong attack ranking quality across thresholds.
- RF macro F1 `0.8007` is now close enough to MLP `0.8047` that the RF is the strongest overall model once explainability is considered.
- The family-level breakdown shows that all models still struggle badly on R2L and U2R, which is an important limitation to discuss honestly.

### What to say instead of “the results are not good”

- The models are competent but not uniformly strong across all evaluation criteria.
- The assignment is about explainability reliability and security implications, not only maximizing raw classification accuracy.
- The strongest contribution is the dual-use security argument: explanations that help analysts can also help attackers.

### What the professor is likely to find convincing

- A tight mapping to the exact assignment text.
- Honest discussion of tradeoffs between interpretability, fidelity, and robustness.
- Clear explanation of why stability is high while security risk still exists.
- Explicit discussion of poor R2L and U2R recall.
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

That structure matches the assignment better than the earlier compliance-first draft.
