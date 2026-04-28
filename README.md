# Project 5: Explainable IDS

This repository implements Project 5 from [`doc.pdf`](/home/kali/deep/doc.pdf): an explainable intrusion detection system on the NSL-KDD dataset. The pipeline trains three models, tunes lightweight configurations, generates SHAP and LIME explanations, measures explanation stability, and evaluates SHAP-guided evasion scenarios plus a simple defense.

## Files Used in This Project

- [`doc.pdf`](/home/kali/deep/doc.pdf): official assignment brief.
- [`pipeline.py`](/home/kali/deep/pipeline.py): end-to-end experiment pipeline.
- [`requirements.txt`](/home/kali/deep/requirements.txt): Python dependencies.
- [`KDDTrain+.txt`](/home/kali/deep/KDDTrain+.txt): NSL-KDD training split.
- [`KDDTest+.txt`](/home/kali/deep/KDDTest+.txt): NSL-KDD test split.
- [`outputs/shap_beeswarm_rf.png`](/home/kali/deep/outputs/shap_beeswarm_rf.png): RF SHAP summary plot.
- [`outputs/shap_comparison.png`](/home/kali/deep/outputs/shap_comparison.png): RF-vs-MLP SHAP comparison.
- [`outputs/shap_stability.png`](/home/kali/deep/outputs/shap_stability.png): SHAP stability histogram.
- [`outputs/evasion_heatmap.png`](/home/kali/deep/outputs/evasion_heatmap.png): global-attack heatmap.
- [`outputs/evasion_heatmap_local.png`](/home/kali/deep/outputs/evasion_heatmap_local.png): local instance-specific attack heatmap.
- [`project5_requirements_analysis.md`](/home/kali/deep/project5_requirements_analysis.md): exact requirement mapping and report critique.
- [`threat_model.md`](/home/kali/deep/threat_model.md): threat model and security interpretation.
- [`reproducibility.md`](/home/kali/deep/reproducibility.md): exact run instructions and expected outputs.
- [`project5_report_draft.md`](/home/kali/deep/project5_report_draft.md): improved report draft aligned to the final run.
- [`claude_final_report_prompt.txt`](/home/kali/deep/claude_final_report_prompt.txt): prompt to generate the polished final report.

## What the Assignment Actually Requires

From Project 5 in [`doc.pdf`](/home/kali/deep/doc.pdf):

- Train a model.
- Apply explainability.
- Evaluate stability.
- Analyze security implications.

Global course constraints also require:

- A baseline model.
- At least 3 experimental variations.
- Appropriate metrics.
- Fixed random seeds.
- Documented preprocessing.
- Report in PDF, code with README, and a reproducibility file.

## Implemented Experimental Design

- Baseline: Logistic Regression.
- Variation 1: Random Forest with TreeSHAP.
- Variation 2: MLP with KernelSHAP.
- Additional explanation method: LIME analysis on attack predictions.
- Security analysis: global and local SHAP-guided evasion plus feature-randomization defense.

## Verified Results

Measured by running `./venv/bin/python pipeline.py` on April 27, 2026:

- Logistic Regression: macro F1 `0.7601`, PR-AUC `0.8806`
- Random Forest: macro F1 `0.8007`, PR-AUC `0.9677`
- MLP: macro F1 `0.8047`, PR-AUC `0.9246`
- SHAP stability: local Jaccard `0.909 ± 0.141`, bootstrap Jaccard `0.927`
- SHAP/MLP importance alignment: Spearman `0.729`
- LIME local fidelity: `0.694`
- Best observed evasion rate: `38.46%`
- Defense improvement: `0.0%`

## Run

```bash
./venv/bin/python pipeline.py
```

The script uses local dataset files if present. If they are missing, it attempts to download them automatically.
