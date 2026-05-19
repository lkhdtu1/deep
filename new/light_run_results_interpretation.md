# Light CUDA Run Results Interpretation

Run command:

```powershell
.\venv\Scripts\python.exe pipeline_cuda.py
```

Run mode:

- `ENABLE_SHAP_ROBUST_ET` was not enabled.
- `ENABLE_HEAVY_ADV_TREE_XAI` was not enabled.
- This is the submit-safe light pipeline.

## What Changed Methodologically

The light version uses the improved `Adv+ExtraTrees Ensemble IDS`, selected with robustness-aware validation tuning. The ensemble validation stage now reports both clean validation F1 and validation evasion. In this run, the selected ensemble was:

```text
weights = {'adv': 0.2, 'et': 0.8}
threshold = 0.20
validation evasion = 1.00%
```

This means the ensemble selection was not based only on clean F1. It also considered transfer-PGD behavior on a validation attack subset. The heavier optional additions, SHAP-robust ExtraTrees and direct ensemble explanation, were skipped to keep runtime practical.

## Clean Detection Results

The best clean detector is still:

| Model | Binary F1 | PR-AUC | Balanced Accuracy |
| --- | ---: | ---: | ---: |
| Adv+ExtraTrees Ensemble IDS | **0.8983** | 0.9596 | **0.8999** |

The best ranking model remains:

| Model | Binary F1 | PR-AUC | Balanced Accuracy |
| --- | ---: | ---: | ---: |
| Binary RF IDS | 0.8027 | **0.9712** | 0.8231 |

This supports two separate claims. The Adv+ExtraTrees ensemble is the best fixed-threshold operational detector, while the binary Random Forest is the strongest ranking model.

## Rare-Family Recall

The strongest family-level result is also the Adv+ExtraTrees ensemble:

| Family | Recall |
| --- | ---: |
| DoS | 0.9693 |
| Probe | 0.9992 |
| R2L | 0.6384 |
| U2R | 0.7910 |

This is important because R2L and U2R are the difficult families in NSL-KDD. The ensemble does not solve them completely, but it improves them enough to be a major result.

## Explainability Results

The light run includes:

- Random Forest TreeSHAP
- Torch Integrated Gradients
- Torch Binary SmoothIG

The direct Adv+ExtraTrees explanation was skipped in the light run. Therefore, the report should not claim that the final ensemble itself was directly explained unless the heavy mode is run.

Top RF SHAP features:

1. `dst_host_srv_count`
2. `traffic_total_log`
3. `count`
4. `src_bytes_log`
5. `logged_in`
6. `dst_bytes_log`
7. `byte_ratio`
8. `dst_host_same_src_port_rate`
9. `srv_count`
10. `dst_host_count`

Top Torch Binary SmoothIG features:

1. `host_serror_gap`
2. `host_rerror_gap`
3. `protocol_type_tcp`
4. `dst_host_rerror_rate`
5. `traffic_total_log`
6. `rerror_gap`
7. `same_srv_rate`
8. `same_diff_srv_gap`
9. `rerror_rate`
10. `src_bytes_log`

The report can say that the ensemble combines components whose explanations are already analyzed, but it should not overclaim full direct ensemble XAI in the light run.

## Stability Results

| Explainer | Local Jaccard | Local Rank Corr. | Bootstrap Jaccard | Bootstrap Rank Corr. |
| --- | ---: | ---: | ---: | ---: |
| RF SHAP | 0.8802 +/- 0.1575 | 0.9960 | 0.5744 | 0.9950 |
| Torch IG | 0.8811 +/- 0.1788 | 0.9827 | 0.9964 | 0.9406 |
| Torch Binary SmoothIG | 0.8992 +/- 0.1272 | 0.6263 | 0.9564 | 0.9940 |

These are strong enough to support the claim that explanations are stable under the tested protocols.

## Attack Results

Explanation-guided attacks:

| Attack | Best Evasion |
| --- | ---: |
| RF SHAP-guided evasion | 18.22% |
| Torch IG-guided evasion | 15.97% |

Direct neural PGD:

| Model | Attack | Evasion |
| --- | --- | ---: |
| Original Torch Binary MLP | PGD all features | 100.00% at all tested budgets |
| PGD-Adversarial Torch Binary MLP | PGD eps=0.03 | 34.39% |
| PGD-Adversarial Torch Binary MLP | PGD eps=0.06 | 64.65% |
| PGD-Adversarial Torch Binary MLP | PGD eps=0.10 | 98.24% |
| PGD-Adversarial Torch Binary MLP | PGD eps=0.15 | 99.97% |

This shows that adversarial fine-tuning helps at low budgets but does not solve high-budget direct white-box PGD against the differentiable Torch model.

## Defense Results

The best defense result is transfer-PGD defense with the Adv+ExtraTrees ensemble:

| Budget | Torch Surrogate Evasion | Ensemble Evasion | Reduction |
| --- | ---: | ---: | ---: |
| eps=0.03 | 39.40% | **7.12%** | 32.27 pp |
| eps=0.06 | 67.34% | **5.21%** | 62.13 pp |
| eps=0.10 | 98.38% | **4.04%** | 94.34 pp |
| eps=0.15 | 99.97% | **2.73%** | 97.23 pp |

This should be described as transfer robustness, not full white-box robustness. It means PGD examples optimized for the differentiable Torch surrogate transfer poorly to the mixed neural-tree ensemble.

The RF SHAP adversarial-training defense has a smaller effect:

```text
without defense = 4.59%
with defense = 0.00%
reduction = 4.59 pp
```

This is still useful, but the stronger security claim comes from the Adv+ExtraTrees transfer-PGD defense.

## What The Report Should Claim

The report should claim:

The final light pipeline uses a robustness-aware Adv+ExtraTrees ensemble. It achieves the best clean binary F1 of `0.8983` and the best rare-family recall balance. Explanations for RF SHAP, Torch IG, and Torch SmoothIG are stable, with local top-10 Jaccard around `0.88-0.90`. Explanation-guided attacks achieve moderate evasion, showing that explanations are dual-use. Direct PGD remains dangerous for differentiable neural models, but the Adv+ExtraTrees ensemble sharply reduces transfer-PGD evasion, keeping it below `8%` for all tested budgets.

The report should not claim:

- that high-budget direct PGD is solved
- that the final ensemble has full white-box robustness
- that direct ensemble-level XAI was run in the light mode
- that the dataset is easy or that the results are state of the art

## Is The Dataset Responsible?

Partly, yes. NSL-KDD `KDDTest+` contains distribution shift and rare attack families. This explains why validation scores are near perfect while official test performance is lower, especially for R2L and U2R.

However, the adversarial weakness is also model-related. Direct PGD is strong because the Torch model is differentiable and the attack optimizes directly against its input gradients. The dataset explains part of the clean detection difficulty; the model and threat model explain the PGD vulnerability.

