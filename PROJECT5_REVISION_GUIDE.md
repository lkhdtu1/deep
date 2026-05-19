# Project 5 Revision Guide: Explainable IDS on NSL-KDD

## 1. What This Project Is About

This project implements Project 5 from `doc.pdf`: an explainable intrusion detection system. The goal is not only to classify network traffic as normal or malicious, but also to explain why the model made its decision, check whether the explanations are stable, and analyze whether explanations can help attackers evade the IDS.

The dataset is NSL-KDD. The official files are `KDDTrain+.txt` for training and `KDDTest+.txt` for final testing. The important point is that `KDDTest+` is harder than a normal validation split because it contains attack subtypes and distributions that are not fully represented in training. This is why validation scores can be near perfect while official test performance is lower.

## 2. Assignment Requirements

The assignment requires:

- train an IDS model
- apply explainability
- evaluate explanation stability
- analyze security implications
- include a baseline model
- include at least three experimental variations
- use appropriate metrics such as precision, recall, F1, PR-AUC, and balanced accuracy
- use fixed random seeds
- document preprocessing and reproducibility

The pipeline satisfies this with Logistic Regression as a baseline, tree models, CUDA PyTorch MLPs, adversarially fine-tuned models, SHAP, Integrated Gradients, SmoothIG, stability metrics, evasion attacks, and defense experiments.

## 3. How The Pipeline Works

The main file is `pipeline_cuda.py`.

The execution order is:

1. Load `KDDTrain+.txt` and `KDDTest+.txt`.
2. Drop the `difficulty` column.
3. Map labels into five families: `normal`, `DoS`, `Probe`, `R2L`, `U2R`.
4. Create a binary label: `normal = 0`, every attack = `1`.
5. Add engineered IDS features such as log byte counts, byte ratio, service ratios, error-rate gaps, and login anomaly score.
6. One-hot encode categorical fields.
7. Scale features with `MinMaxScaler` fitted on training data only.
8. Train baseline and variation models.
9. Evaluate clean detection on `KDDTest+`.
10. Generate explanations.
11. Evaluate explanation stability.
12. Run evasion attacks.
13. Run defense experiments.
14. Save plots and `outputs_cuda/summary.json`.

## 4. Main Models

Logistic Regression is the baseline. It is simple and interpretable, so it gives a lower-bound reference.

Random Forest is the main tree explainability model. It works well with TreeSHAP and usually gives very strong PR-AUC, meaning it ranks attacks well even if the fixed threshold is not always optimal.

Torch MLP CUDA is the multiclass neural model. It predicts the five families and is explained using Integrated Gradients.

Torch Binary MLP CUDA focuses only on normal versus attack. It is explained using Smooth Integrated Gradients.

PGD-Adversarial Torch Binary MLP is the binary MLP fine-tuned with adversarial examples. It improves clean binary F1 and low-budget PGD robustness.

Adv+ExtraTrees Ensemble is the strongest operational detector. It combines adversarial Torch scores with ExtraTrees or SHAP-robust ExtraTrees scores. The idea is to combine a robust neural detector with a non-differentiable tree model.

## 5. How To Read Clean Results

The key metrics are:

- `Binary F1`: overall thresholded IDS quality for normal vs attack.
- `PR-AUC`: ranking quality across thresholds. Very important for IDS because thresholds can be adjusted.
- `Balanced Accuracy`: average of normal recall and attack recall.
- `Per-family recall`: how well the model detects each attack family.

If a model has high binary F1 but low R2L recall, it means the model is good overall but still weak on rare attack types. This is why the report must include per-family recall and not only binary F1.

The best model should be interpreted as:

- best thresholded detector: usually `Adv+ExtraTrees Ensemble IDS`
- best ranking/explainable tree model: usually `Binary RF IDS` by PR-AUC
- best neural robustness model: `PGD-Adversarial Torch Binary MLP`

## 6. Explainability Methods

TreeSHAP explains tree models such as Random Forest and ExtraTrees. It gives feature contributions and supports global feature importance.

Integrated Gradients explains neural models by accumulating gradients from a baseline input to the actual input.

SmoothIG is a smoothed Integrated Gradients variant. It averages attributions over noisy versions of the input to reduce gradient noise.

The most important features usually involve:

- connection history, such as `count`, `srv_count`, `dst_host_count`
- service density, such as `dst_host_srv_count`
- byte-volume features, such as `src_bytes_log`, `dst_bytes_log`, `traffic_total_log`
- error-rate gaps, such as `host_serror_gap`, `host_rerror_gap`, `rerror_gap`
- protocol and service indicators

These are plausible IDS signals because attacks often change traffic volume, service behavior, connection repetition, and error patterns.

## 7. Stability Interpretation

Explanation stability answers: if two inputs are similar, do they get similar explanations?

Important stability metrics:

- `local_jaccard_mean`: overlap of top-10 features between similar samples
- `local_rank_corr_mean`: rank correlation of full attribution vectors between similar samples
- `bootstrap_jaccard_mean`: how stable the global top-10 features are under resampling
- `bootstrap_rank_corr_mean`: how stable the full global ranking is under resampling

High stability is good for analysts because explanations are consistent. However, high stability is also risky because attackers can repeatedly target the same important features.

## 8. Adversarial Analysis

The project evaluates several attacks.

SHAP-guided evasion perturbs features selected by SHAP. It tests whether explanations reveal useful attack directions.

IG-guided evasion does the same with neural attributions from Integrated Gradients.

Full-feature PGD is a strong white-box attack against the differentiable Torch binary model. If PGD evasion is high, the neural model is vulnerable under worst-case gradient access.

SmoothIG-constrained PGD is more realistic than full PGD because it only perturbs features selected by SmoothIG.

Transfer PGD generates PGD examples against the Torch surrogate and evaluates whether they transfer to the Adv+ExtraTrees ensemble. This is important because the ensemble contains a non-differentiable tree component.

## 9. Defense Interpretation

The old feature-randomization defense is a negative control. It usually gives no improvement because randomizing low-importance features does not stop attacks that target high-importance features.

PGD adversarial fine-tuning helps against low-budget PGD. It reduces evasion at small epsilon values, but high-budget direct PGD can still be very strong.

Adv+ExtraTrees transfer defense is stronger in the transfer setting. Since the ensemble combines a differentiable neural model and a non-differentiable tree model, PGD examples optimized for the neural model often transfer poorly to the ensemble.

Important caveat: transfer robustness is not the same as full white-box robustness against the entire ensemble. It is still a valid and useful defense result, but it should be described accurately.

## 10. How To Interpret `summary.json`

Open `outputs_cuda/summary.json`.

The most important sections are:

- `models`: clean performance for each model
- `stability`: explanation stability metrics
- `attacks`: evasion rates for SHAP, IG, PGD, and ensemble attacks
- `defense`: RF adversarial-training defense
- `pgd_adversarial_finetune_defense`: before/after PGD fine-tuning comparison
- `adv_tree_transfer_pgd_defense`: transfer-PGD defense for the final ensemble
- `adv_tree_ensemble_explanation`: explanation results for the final ensemble

When writing the report, use `models` for clean results, `stability` for explanation reliability, and `attacks` plus `defense` for security implications.

## 11. Main Conclusion To Remember

The main conclusion is:

Stable explanations are useful for analysts, but they can also help attackers identify which features to manipulate. Explainability must therefore be evaluated together with adversarial robustness.

The strongest project contribution is not only clean IDS performance. It is the combined analysis of:

- clean detection
- explanation quality
- explanation stability
- explanation-guided evasion
- PGD robustness
- adversarial training and ensemble defense

## 12. How To Defend The Results Orally

If asked why the results are not near perfect, answer:

`KDDTest+` is distribution-shifted and contains rare attack families. Near-perfect validation scores are easier because validation comes from `KDDTrain+`. The report uses the official test split, so the results are more realistic.

If asked why binary detection is emphasized, answer:

The first operational IDS decision is whether traffic is normal or malicious. Family-level recall is still reported as error analysis so rare-family weaknesses are not hidden.

If asked why explainability is a security risk, answer:

Explanations reveal which features drive detection. If those features are stable across similar attacks, an attacker can use them as a manipulation guide.

If asked whether the defense is complete, answer:

No. PGD adversarial fine-tuning improves low-budget robustness, and Adv+ExtraTrees improves transfer robustness, but full white-box attacks against the complete mixed system remain a future-work limitation.

## 13. Files To Know

- `doc.pdf`: assignment brief
- `pipeline_cuda.py`: main implementation
- `outputs_cuda/summary.json`: verified numerical results after running the pipeline
- `outputs_cuda/*.png`: generated plots
- `Project5_CUDA_Report_corrected.docx`: corrected report
- `PROJECT5_REVISION_GUIDE.md`: this revision guide

