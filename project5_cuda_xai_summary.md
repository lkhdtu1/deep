# Project 5 CUDA/XAI Pipeline Summary

## Project Scope

Project 5 asks for an explainable IDS on NSL-KDD. The required work is:

- train an IDS model
- apply explainability
- evaluate explanation stability
- analyze security implications
- include a baseline, experimental variations, metrics, fixed seeds, preprocessing notes, README/reproducibility material

The current Windows/CUDA work stays inside that scope. We did not change datasets, leak `KDDTest+` into training, or replace the assignment with a different IDS task.

## What Changed From the Original CPU Report

The previous report was based on `pipeline.py`, mostly CPU-bound sklearn models:

- Logistic Regression baseline
- Random Forest + TreeSHAP
- sklearn MLP + KernelSHAP
- LIME
- SHAP-guided evasion
- weak feature-randomization defense

The Windows/CUDA pipeline in `pipeline_cuda.py` keeps the same project structure but adds stronger GPU and adversarial analysis:

- CUDA PyTorch multiclass MLP
- CUDA PyTorch binary MLP
- Smooth Integrated Gradients for the binary MLP
- white-box PGD evasion against the CUDA binary MLP
- SmoothIG-constrained PGD evasion
- binary RF / ExtraTrees / ensemble IDS variants
- optional XGBoost model if `xgboost` is installed
- adversarial-training defense experiment

The project is now more focused on explainability, stability, and adversarial security, which is closer to the Project 5 objective.

## Current Verified Results

The latest full run used:

- Python 3.11
- PyTorch `2.6.0+cu124`
- CUDA available: `True`
- GPU: NVIDIA GeForce RTX 3060 Laptop GPU
- feature count: `478`
- fixed seed: `42`

### Clean IDS Performance

Best full `KDDTest+` clean result:

| Model | Binary F1 | PR-AUC | Balanced Accuracy |
| --- | ---: | ---: | ---: |
| Logistic Regression | 0.8344 | 0.9388 | 0.8442 |
| Random Forest | 0.7633 | 0.9695 | 0.7899 |
| Torch MLP CUDA | **0.8470** | 0.9077 | **0.8605** |
| Torch Binary MLP CUDA | 0.8021 | 0.9095 | 0.8197 |
| PGD-Adversarial Torch Binary MLP | **0.8569** | 0.9252 | **0.8628** |
| Binary RF IDS | 0.8027 | **0.9712** | 0.8231 |
| Binary ExtraTrees IDS | 0.7969 | 0.9612 | 0.8184 |
| Binary XGBoost IDS | 0.7844 | 0.9695 | 0.8077 |
| Tuned Binary Ensemble IDS | 0.8013 | 0.9668 | 0.8204 |

Interpretation:

- The best binary F1 is now the PGD-adversarially fine-tuned CUDA binary MLP: `0.8569`.
- The strongest ranking model is binary RF: PR-AUC `0.9712`.
- Adversarial fine-tuning improved clean test performance, not only robustness.
- The official `KDDTest+` split remains difficult because it contains attack distribution shift and attack subtypes not present in training.
- Validation F1 values near `0.99` are not used as final claims because they come from a held-out split of `KDDTrain+`, which is easier than `KDDTest+`.

### Family-Level Weakness

R2L remains the hardest family, but the PGD-adversarial Torch model substantially improves it:

| Model | DoS Recall | Probe Recall | R2L Recall | U2R Recall |
| --- | ---: | ---: | ---: | ---: |
| Torch MLP CUDA | 0.8371 | 0.7972 | 0.1635 | 0.5672 |
| PGD-Adversarial Torch Binary MLP | **0.9512** | **0.9442** | **0.4160** | **0.6119** |

This is one of the strongest practical improvements in the current pipeline. R2L is still imperfect, but it is no longer almost ignored by the best model.

### Explainability Results

Random Forest TreeSHAP top features included:

- `dst_host_srv_count`
- `traffic_total_log`
- `count`
- `src_bytes_log`
- `logged_in`
- `dst_bytes_log`
- `byte_ratio`
- `dst_host_same_src_port_rate`
- `srv_count`
- `dst_host_count`

Torch Binary SmoothIG top features included:

- `host_serror_gap`
- `host_rerror_gap`
- `protocol_type_tcp`
- `dst_host_rerror_rate`
- `traffic_total_log`
- `rerror_gap`
- `same_srv_rate`
- `same_diff_srv_gap`
- `rerror_rate`
- `src_bytes_log`

These are plausible IDS signals: connection history, service density, byte-volume behavior, protocol state, and error-rate patterns.

### Stability Results

| Explainer | Local Top-10 Jaccard | Bootstrap Jaccard | Bootstrap Rank Corr. |
| --- | ---: | ---: | ---: |
| RF SHAP | 0.8802 ± 0.1575 | 0.5744 | 0.9950 |
| Torch IG | 0.8811 ± 0.1788 | 0.9964 | 0.9406 |
| Torch Binary SmoothIG | **0.8992 ± 0.1272** | 0.9564 | 0.9940 |

Interpretation:

- Local stability is strong across all explanation methods.
- SmoothIG gives the best local top-k stability in the current run.
- RF SHAP has strong rank stability but weaker bootstrap top-10 set stability, meaning the global ordering is stable while the exact top-10 set can shift.

## Adversarial Results

### RF SHAP-Guided Evasion

Best RF SHAP-guided evasion:

- `local_top15_eps0.1 = 18.22%`

This is a realistic explanation-guided feature-space attack: perturb only the most important SHAP features.

### Torch IG-Guided Evasion

Best Torch IG-guided evasion:

- `ig_top15_eps0.1 = 15.97%`

This shows that neural attributions also expose a useful manipulation surface.

### Strong White-Box PGD Attack

White-box PGD against the CUDA binary MLP is much stronger:

| Attack | Evasion |
| --- | ---: |
| PGD all features, eps=0.03 | 100.00% |
| PGD all features, eps=0.06 | 100.00% |
| PGD all features, eps=0.10 | 100.00% |
| PGD all features, eps=0.15 | 100.00% |

SmoothIG-constrained PGD:

| Attack | Evasion |
| --- | ---: |
| SmoothIG top-10, eps=0.15 | 17.77% |
| SmoothIG top-20, eps=0.15 | 40.69% |
| SmoothIG top-40, eps=0.10 | 62.18% |
| SmoothIG top-40, eps=0.15 | 92.84% |

Interpretation:

- Full white-box gradient access completely breaks the binary MLP in normalized feature space.
- The explanation-constrained variant is more realistic and still produces high evasion.
- This is now a strong Project 5 result: stable explanations are useful to analysts, but they also expose attack directions.

### PGD-Adversarially Fine-Tuned Torch MLP

The CUDA binary MLP was then fine-tuned on PGD-generated adversarial attack examples. This improved clean performance and reduced low-budget PGD evasion:

| Attack | Original Torch Binary MLP | PGD-Adversarial Torch Binary MLP |
| --- | ---: | ---: |
| PGD all features, eps=0.03 | 100.00% | **34.39%** |
| PGD all features, eps=0.06 | 100.00% | **64.65%** |
| PGD all features, eps=0.10 | 100.00% | 98.24% |
| PGD all features, eps=0.15 | 100.00% | 99.97% |

Defense reduction by perturbation budget:

| Budget | Absolute Reduction | Relative Reduction |
| --- | ---: | ---: |
| eps=0.03 | **65.61 percentage points** | **65.61%** |
| eps=0.06 | **35.35 percentage points** | **35.35%** |
| eps=0.10 | 1.76 percentage points | 1.76% |
| eps=0.15 | 0.03 percentage points | 0.03% |

Interpretation:

- Adversarial fine-tuning is effective against small perturbation budgets.
- High-budget PGD remains a serious unresolved risk.
- Clean accuracy did not collapse; it improved to binary F1 `0.8569`.
- This gives a better security story than the earlier randomization defense.

## Defense Results

The old low-importance feature-randomization defense still gives:

- `0.00%` reduction

This is not surprising. Randomizing features the model does not care about should not stop an attack targeting high-importance features.

The RF SHAP adversarial-training defense gives:

- without defense: `4.59%`
- with defense: `0.00%`
- reduction: `4.59%`

Interpretation:

- Feature randomization is a negative control.
- RF adversarial training is a meaningful but small defense improvement on the tested binary RF SHAP attack subset.
- The stronger defense result is the PGD-adversarial Torch model: it reduces PGD evasion by 65.61 percentage points at eps=0.03 and 35.35 percentage points at eps=0.06.
- The defense is not complete because high-budget PGD still succeeds.

## What We Learned From External Work

Recent NSL-KDD/XAI work commonly uses tree ensembles such as Random Forest and XGBoost with SHAP, sometimes combined with LIME or counterfactual analysis. Several public examples and papers report very high scores, but many use easier splits, validation subsets, or do not clearly separate `KDDTrain+` validation from full `KDDTest+` evaluation.

Useful ideas that remain compatible with this project:

- XGBoost + SHAP for a stronger explainable tree model.
- Ensemble models for the binary IDS view.
- Counterfactual or PGD-style adversarial analysis, not only simple feature perturbation.
- Stability metrics that compare top-k explanation sets and full ranking correlation.
- Adversarial training as a defense instead of random noise.

The current pipeline already implements most of these except XGBoost, which is optional because it is not installed in the current venv.

Sources consulted:

- Kaggle NSL-KDD dataset page: notes that NSL-KDD removes redundant records and is an academic IDS benchmark.
- Recent XAI IDS articles commonly use Random Forest/XGBoost with SHAP and LIME.
- Work on XAI for IDS reports that NSL-KDD class imbalance and attack-category structure can bias model explanations and performance.

## Limits

1. Feature-space attacks are not packet-level attacks.
   Perturbing normalized features does not guarantee a valid network packet or session.

2. `KDDTest+` is distribution-shifted.
   Some attacks in test are absent from training, so test performance is lower than validation performance.

3. R2L remains weak.
   The model can perform well as a binary IDS while still missing many R2L examples.

4. PGD is a strong white-box attack.
   It is useful for worst-case robustness analysis, but it assumes the attacker knows the model and can optimize directly against it.

5. The current defense is not complete.
   Adversarial training was tested against one binary RF SHAP attack setting. It should also be tested against Torch PGD and SmoothIG-constrained PGD.

6. XGBoost is optional.
   The code now supports it if installed, but the verified run did not include it.

## Recommended Next Improvements

1. Install and test XGBoost:

```powershell
.\venv\Scripts\python.exe -m pip install xgboost
.\venv\Scripts\python.exe pipeline_cuda.py
```

2. Add adversarial training for the CUDA binary MLP using PGD-generated examples.

3. Add counterfactual explanations for a small number of attack instances.

4. Add a table separating:

- clean IDS performance
- explanation stability
- explanation-guided evasion
- full white-box evasion
- defense effectiveness

5. In the final report, avoid claiming state-of-the-art clean accuracy. The strongest contribution is the explainability/security result: stable explanations are useful but can be weaponized.
