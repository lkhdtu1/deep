# Project 5 CUDA/XAI Results Package

This file contains the results and figure references from `pipeline_cuda.py` for use in the updated Project 5 report. The results come from `outputs_cuda/summary.json` and the copied figures in `new/images/`.

## Assignment Alignment

Project 5 in `doc.pdf` asks for an explainable intrusion detection system on NSL-KDD. The required work is to train an IDS model, apply explainability, evaluate explanation stability, and analyze security implications. The general course instructions also require a baseline model, at least three experimental variations, appropriate metrics, fixed random seeds, documented preprocessing, code with README material, and reproducibility instructions.

The CUDA pipeline satisfies these requirements with Logistic Regression as the baseline, Random Forest and tree-based IDS variants as explainable models, CUDA PyTorch MLPs as neural IDS variants, SHAP and Integrated Gradients based explanations, stability metrics, explanation-guided evasion, white-box PGD evasion, and adversarial fine-tuning as a defense experiment.

## The Defensible Improvement Strategy

The strongest improvement is not to inflate the raw numbers or hide difficult results. The defensible "trick" is to report the IDS in the form that best matches the operational task: binary intrusion detection, while preserving attack-family recall as an error analysis. NSL-KDD family-level classification is much harder because the official `KDDTest+` split contains distribution shift and rare attack families. A binary IDS view is therefore legitimate for deployment and for Project 5, because the primary decision is whether traffic is normal or malicious.

The second improvement is adversarial fine-tuning. The original CUDA binary MLP was very vulnerable to full-feature PGD attacks, but PGD-adversarial fine-tuning improved both clean binary F1 and low-budget robustness. The final improvement is a compact Adv+ExtraTrees ensemble that blends the PGD-adversarial neural detector with the ExtraTrees score and tunes only its threshold on the validation split. This is a stronger and more defensible improvement than simply searching for a better test threshold.

No result in this package uses `KDDTest+` for training. Threshold tuning and model selection are performed on training/validation data, while the reported final metrics are on the official test split.

## Environment

| Item | Value |
| --- | --- |
| Python | 3.11 |
| PyTorch | 2.6.0+cu124 |
| Device | CUDA |
| GPU | NVIDIA GeForce RTX 3060 Laptop GPU |
| Seed | 42 |
| Feature count | 478 |

## Preprocessing Summary

The pipeline loads `KDDTrain+.txt` and `KDDTest+.txt`, drops the `difficulty` column, maps raw labels into the five families `normal`, `DoS`, `Probe`, `R2L`, and `U2R`, and also derives a binary label where every non-normal family is treated as attack. It adds IDS-oriented engineered features such as log byte counts, byte ratios, traffic totals, service ratios, error-rate gaps, and a login anomaly score. Categorical fields are one-hot encoded after combining train and test columns to keep a consistent feature space, then a `MinMaxScaler` is fit on training features and applied to test features.

## Clean IDS Performance

| Model | Binary F1 | PR-AUC | Balanced Accuracy |
| --- | ---: | ---: | ---: |
| Logistic Regression | 0.8344 | 0.9388 | 0.8442 |
| Random Forest | 0.7633 | 0.9695 | 0.7899 |
| Torch MLP CUDA | 0.8470 | 0.9077 | 0.8605 |
| Torch Binary MLP CUDA | 0.8021 | 0.9095 | 0.8197 |
| PGD-Adversarial Torch Binary MLP | **0.8569** | 0.9252 | **0.8628** |
| Binary LR IDS | 0.7801 | 0.8939 | 0.7970 |
| Binary RF IDS | 0.8027 | **0.9712** | 0.8231 |
| Binary ExtraTrees IDS | 0.7969 | 0.9612 | 0.8184 |
| Binary XGBoost IDS | 0.7844 | 0.9695 | 0.8077 |
| Tuned Binary Ensemble IDS | 0.8047 | 0.9687 | 0.8252 |
| Adv+ExtraTrees Ensemble IDS | **0.8983** | 0.9596 | **0.8999** |

The best clean binary F1 is now achieved by the Adv+ExtraTrees Ensemble IDS with `0.8983`, improving over the previous best PGD-adversarial Torch binary MLP result of `0.8569`. The strongest ranking model remains the binary Random Forest with PR-AUC `0.9712`. This gives two defensible claims: the adversarial-tree ensemble is the best thresholded detector, while the tree model is the strongest ranking and explainability model.

## Family-Level Recall

| Model | Normal | DoS | Probe | R2L | U2R |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.9127 | 0.8575 | 0.8245 | 0.1701 | 0.6418 |
| Random Forest | 0.9726 | 0.7604 | 0.6650 | 0.0623 | 0.1940 |
| Torch MLP CUDA | 0.9576 | 0.8371 | 0.7972 | 0.1635 | 0.5672 |
| Torch Binary MLP CUDA | 0.9463 | 0.8675 | 0.8678 | 0.1032 | 0.3582 |
| PGD-Adversarial Torch Binary MLP | 0.8980 | **0.9512** | **0.9442** | **0.4160** | **0.6119** |
| Binary RF IDS | 0.9691 | 0.8541 | 0.8815 | 0.0599 | 0.1940 |
| Tuned Binary Ensemble IDS | 0.9721 | 0.8642 | 0.8228 | 0.0862 | 0.2836 |
| Adv+ExtraTrees Ensemble IDS | 0.9032 | **0.9693** | **0.9992** | **0.6384** | **0.7910** |

The rare-family analysis is important because binary IDS performance can hide weaknesses on R2L and U2R. The new Adv+ExtraTrees Ensemble IDS gives the strongest rare-family result in the current run, raising R2L recall to `0.6384` and U2R recall to `0.7910`, while keeping normal recall at `0.9032`.

## Explainability Results

The Random Forest TreeSHAP top features include `dst_host_srv_count`, `traffic_total_log`, `count`, `src_bytes_log`, `logged_in`, `dst_bytes_log`, `byte_ratio`, `dst_host_same_src_port_rate`, `srv_count`, and `dst_host_count`.

The Torch Binary SmoothIG top features include `host_serror_gap`, `host_rerror_gap`, `protocol_type_tcp`, `dst_host_rerror_rate`, `traffic_total_log`, `rerror_gap`, `same_srv_rate`, `same_diff_srv_gap`, `rerror_rate`, and `src_bytes_log`.

These explanations are plausible for IDS because they emphasize service density, host-level connection history, byte-volume behavior, protocol state, and error-rate patterns.

## Explanation Stability

| Explainer | Local Top-10 Jaccard | Local Rank Corr. | Bootstrap Top-10 Jaccard | Bootstrap Rank Corr. |
| --- | ---: | ---: | ---: | ---: |
| RF SHAP | 0.8802 +/- 0.1575 | 0.9960 | 0.5744 | 0.9950 |
| Torch IG | 0.8811 +/- 0.1788 | 0.9827 | 0.9964 | 0.9406 |
| Torch Binary SmoothIG | **0.8992 +/- 0.1272** | 0.6263 | 0.9564 | 0.9940 |

The stability results show that explanations are not random or purely incidental. SmoothIG has the strongest local top-10 feature stability. RF SHAP has very strong rank stability, although its exact bootstrap top-10 set changes more than the neural methods.

## Adversarial Results

### RF SHAP-Guided Evasion

| Attack | Evasion |
| --- | ---: |
| global_top5_eps0.1 | 11.74% |
| global_top10_eps0.1 | 14.98% |
| global_top15_eps0.1 | 14.98% |
| local_top10_eps0.1 | 11.74% |
| local_top15_eps0.1 | **18.22%** |

The best RF SHAP-guided evasion result is `18.22%`. This shows that explanation-guided perturbation can create a measurable attack surface even against a strong tree model.

### Torch IG-Guided Evasion

| Attack | Evasion |
| --- | ---: |
| ig_top5_eps0.1 | 8.31% |
| ig_top10_eps0.1 | 12.14% |
| ig_top15_eps0.1 | **15.97%** |

The best Torch IG-guided evasion result is `15.97%`, confirming that neural attributions also expose useful manipulation directions.

### White-Box PGD Against Torch Binary MLP

| Attack | Evasion |
| --- | ---: |
| PGD all features, eps=0.03 | 100.00% |
| PGD all features, eps=0.06 | 100.00% |
| PGD all features, eps=0.10 | 100.00% |
| PGD all features, eps=0.15 | 100.00% |

Full white-box PGD completely breaks the original binary MLP in normalized feature space. This is a severe but useful result because it identifies a real robustness failure.

### SmoothIG-Constrained PGD

| Attack | Evasion |
| --- | ---: |
| SmoothIG top-10, eps=0.15 | 17.77% |
| SmoothIG top-20, eps=0.15 | 40.69% |
| SmoothIG top-40, eps=0.10 | 62.18% |
| SmoothIG top-40, eps=0.15 | **92.84%** |

The constrained attack is more realistic than unconstrained PGD because it only perturbs explanation-selected features. It still reaches high evasion when enough important features are available.

## Defense Results

| Attack Budget | Original Torch Binary MLP | PGD-Adversarial Torch Binary MLP | Absolute Reduction |
| --- | ---: | ---: | ---: |
| PGD all features, eps=0.03 | 100.00% | 34.39% | **65.61 pp** |
| PGD all features, eps=0.06 | 100.00% | 64.65% | **35.35 pp** |
| PGD all features, eps=0.10 | 100.00% | 98.24% | 1.76 pp |
| PGD all features, eps=0.15 | 100.00% | 99.97% | 0.03 pp |

Adversarial fine-tuning is effective against small perturbation budgets and also improves clean binary F1. It is not a complete defense because high-budget PGD remains highly successful.

## Adv+ExtraTrees Transfer-PGD Defense

The weak point of the PGD-adversarial Torch binary MLP is that high-budget white-box PGD remains effective when the attack directly optimizes the differentiable neural model. The new Adv+ExtraTrees Ensemble IDS improves the defense story by combining the adversarially fine-tuned neural score with an ExtraTrees score. Since the ensemble includes a non-differentiable tree component, the evaluated attack is transfer PGD: PGD examples are generated against the adversarial Torch model and then evaluated against the mixed ensemble.

| Attack Budget | Torch Surrogate Evasion | Adv+ExtraTrees Evasion | Absolute Reduction |
| --- | ---: | ---: | ---: |
| transfer PGD, eps=0.03 | 39.40% | **7.12%** | 32.27 pp |
| transfer PGD, eps=0.06 | 67.34% | **5.21%** | 62.13 pp |
| transfer PGD, eps=0.10 | 98.38% | **4.04%** | 94.34 pp |
| transfer PGD, eps=0.15 | 99.97% | **2.73%** | 97.23 pp |

This is the strongest adversarial-defense result in the updated pipeline. It should be described carefully as transfer robustness, not as proof of full white-box robustness against every possible attack on the mixed ensemble.

![Adv+ExtraTrees transfer PGD defense](images/adv_tree_transfer_pgd_defense.png)

The older low-importance feature-randomization defense produced `0.00%` reduction, which is a useful negative control. Randomizing features the model does not depend on does not stop attacks that target high-importance features.

## Figures

### RF SHAP Top-10 Features

![RF SHAP top 10](images/rf_shap_top10.png)

### RF vs Torch Explanation Comparison

![RF vs Torch explanations](images/rf_vs_torch_explanations.png)

### Torch Binary SmoothIG Top-10 Features

![Torch Binary SmoothIG top 10](images/torch_binary_smoothig_top10.png)

### Integrated Gradients Stability

![IG stability](images/ig_stability.png)

### RF SHAP Global Evasion

![RF SHAP global evasion](images/rf_shap_evasion_global.png)

### RF SHAP Local Evasion

![RF SHAP local evasion](images/rf_shap_evasion_local.png)

### Torch IG Evasion

![Torch IG evasion](images/ig_evasion_heatmap.png)

### Torch Binary PGD Evasion

![Torch Binary PGD evasion](images/torch_binary_pgd_evasion.png)

### Adv+ExtraTrees Transfer-PGD Defense

![Adv+ExtraTrees transfer PGD defense](images/adv_tree_transfer_pgd_defense.png)

## Recommended Claims for the Report

The updated report should not claim state-of-the-art performance. It should claim that the project builds a reproducible explainable IDS pipeline and demonstrates a dual-use interpretability result. Stable explanations help analysts understand IDS decisions, but the same stable attributions can guide evasion. The best clean thresholded detector is now the Adv+ExtraTrees Ensemble IDS with binary F1 `0.8983`, while the strongest explainable ranking model is the binary Random Forest with PR-AUC `0.9712`.

The most important limitation is that the adversarial attacks operate in normalized feature space rather than generating valid raw packets or sessions. The second limitation is that NSL-KDD remains distribution-shifted and rare-family recall remains imperfect, especially for R2L and U2R. These limitations should be presented as part of the security analysis, not hidden.
