# Final Heavy Results For Report

These values are taken from the corrected `outputs_cuda/summary.json` after the calibrated `Security-OR` update.

## Selected Final Model

The selected final detector is the `Adv+ExtraTrees Ensemble IDS`. It is preferred because it gives the best overall balance between clean detection, rare-family recall, explainability, and adversarial transfer robustness.

| Model | Binary F1 | PR-AUC | Balanced Accuracy | Threshold |
| --- | ---: | ---: | ---: | ---: |
| Adv+ExtraTrees Ensemble IDS | 0.9063 | 0.9626 | 0.9064 | 0.15 |
| SHAP-Robust ExtraTrees IDS | 0.8912 | 0.9592 | 0.8941 | 0.12 |
| Security-OR Ensemble IDS | 0.8796 | 0.9451 | 0.8839 | 1.25 |
| Torch MLP CUDA | 0.8470 | 0.9077 | 0.8605 | n/a |

## Final Model Family Recall

| Family | Recall |
| --- | ---: |
| Normal | 0.8943 |
| DoS | 0.9859 |
| Probe | 1.0000 |
| R2L | 0.6786 |
| U2R | 0.8060 |

## Final Ensemble Explainability

The final ensemble explanation used a combined explanation over the adversarial Torch component and the SHAP-robust ExtraTrees component.

Top features:

1. `flag_SF`
2. `same_srv_rate`
3. `dst_host_srv_count`
4. `logged_in`
5. `dst_host_same_srv_rate`
6. `rerror_rate`
7. `dst_host_rerror_rate`
8. `service_private`
9. `same_diff_srv_gap`
10. `dst_host_srv_serror_rate`

Explanation stability:

| Metric | Value |
| --- | ---: |
| Local Jaccard | 0.8453 +/- 0.1621 |
| Local Rank Correlation | 0.6861 |
| Bootstrap Jaccard | 0.8873 |
| Bootstrap Rank Correlation | 0.9899 |

## Adversarial Defense

Transfer-PGD defense for the selected `Adv+ExtraTrees Ensemble IDS`:

| Epsilon | Surrogate Torch Evasion | Ensemble Evasion | Absolute Reduction |
| --- | ---: | ---: | ---: |
| 0.03 | 37.29% | 0.50% | 36.79 pp |
| 0.06 | 63.99% | 0.00% | 63.99 pp |
| 0.10 | 91.24% | 0.00% | 91.24 pp |
| 0.15 | 100.00% | 0.00% | 100.00 pp |

Security-OR transfer-PGD defense:

| Epsilon | Surrogate Torch Evasion | Security-OR Evasion | Absolute Reduction |
| --- | ---: | ---: | ---: |
| 0.03 | 33.39% | 0.00% | 33.39 pp |
| 0.06 | 61.74% | 0.00% | 61.74 pp |
| 0.10 | 90.69% | 0.00% | 90.69 pp |
| 0.15 | 100.00% | 0.00% | 100.00 pp |

The `Security-OR` mode is useful as a stricter high-security operating point, but it is not the selected final model because its clean binary F1 is lower than `Adv+ExtraTrees`.

## Mutable-Feature PGD

Mutable-feature PGD freezes categorical protocol/service/flag fields and binary login/status indicators.

| Epsilon | Before Multi-Eps Training | After Multi-Eps Training | Reduction |
| --- | ---: | ---: | ---: |
| 0.03 | 11.70% | 14.05% | -2.35 pp |
| 0.06 | 30.76% | 26.38% | 4.38 pp |
| 0.10 | 71.21% | 39.18% | 32.03 pp |
| 0.15 | 100.00% | 57.97% | 42.03 pp |

This should be interpreted as a tradeoff: multi-epsilon adversarial training improves medium and high perturbation robustness, but not the smallest perturbation budget.
