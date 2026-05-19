# Heavy CUDA Run Results Interpretation

This file interprets the heavy run output pasted after enabling the SHAP-robust ExtraTrees and direct ensemble explainability stages.

## Main Result To Use In The Report

The best operational detector in this run is the `Adv+ExtraTrees Ensemble IDS`.

| Model | Binary F1 | PR-AUC | Balanced Accuracy | Threshold |
| --- | ---: | ---: | ---: | ---: |
| Adv+ExtraTrees Ensemble IDS | 0.9063 | 0.9626 | 0.9064 | 0.15 |
| SHAP-Robust ExtraTrees IDS | 0.8912 | 0.9592 | 0.8941 | 0.12 |
| Security-OR Ensemble IDS | 0.8796 | 0.9451 | 0.8839 | 1.25 |
| Torch MLP CUDA | 0.8470 | 0.9077 | 0.8605 | n/a |

The heavy run improved the previous light-run main result. The light run achieved `0.8983` binary F1 for the `Adv+ExtraTrees Ensemble IDS`; the heavy run increased this to `0.9063`.

## Rare-Family Recall

The final `Adv+ExtraTrees Ensemble IDS` achieved the strongest rare-family detection behavior:

| Family | Recall |
| --- | ---: |
| DoS | 0.9859 |
| Probe | 1.0000 |
| R2L | 0.6786 |
| U2R | 0.8060 |

This is the strongest reportable detection result because R2L and U2R are the hardest NSL-KDD families. The improvement comes mainly from the SHAP-robust ExtraTrees component and the robustness-aware ensemble threshold.

## Explainability Results

The heavy run includes direct explanation of the final ensemble. The top `Adv+ExtraTrees` explanation features were:

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

The final ensemble explanation was stable enough to report:

| Explanation | Local Jaccard | Local Rank | Bootstrap Jaccard | Bootstrap Rank |
| --- | ---: | ---: | ---: | ---: |
| Adv+ExtraTrees ensemble | 0.8453 +/- 0.1621 | 0.6861 | 0.8873 | 0.9899 |

This gives a stronger explainability section than the light run because the final ensemble itself is now explained, not only its baseline components.

## Adversarial Attack And Defense Results

The most important defense result is the transfer-PGD evaluation against the final `Adv+ExtraTrees` ensemble:

| Epsilon | Surrogate Torch Evasion | Ensemble Evasion | Absolute Reduction |
| --- | ---: | ---: | ---: |
| 0.03 | 37.29% | 0.50% | 36.79 pp |
| 0.06 | 63.99% | 0.00% | 63.99 pp |
| 0.10 | 91.24% | 0.00% | 91.24 pp |
| 0.15 | 100.00% | 0.00% | 100.00 pp |

This is the cleanest adversarial-defense claim in the report. The adversarially trained Torch model remains vulnerable under direct white-box PGD, especially at high epsilon values, but the final tree-neural ensemble blocks the transferred adversarial examples almost completely.

The TreeSHAP-guided attack against the final ensemble also failed in this run. The ensemble evasion was `0.00%` for all tested top-k and epsilon combinations. This supports the claim that the SHAP-robust tree component meaningfully hardens the final detector against explanation-guided feature attacks.

## Mutable-Feature PGD Interpretation

The mutable-feature PGD experiment is useful because it freezes categorical protocol/service/flag fields and binary login/status indicators. This is more realistic than allowing every normalized feature to move freely.

| Epsilon | Before Adv Training | After Multi-Eps Adv Training | Reduction |
| --- | ---: | ---: | ---: |
| 0.03 | 11.70% | 14.05% | -2.35 pp |
| 0.06 | 30.76% | 26.38% | 4.38 pp |
| 0.10 | 71.21% | 39.18% | 32.03 pp |
| 0.15 | 100.00% | 57.97% | 42.03 pp |

The correct interpretation is that multi-epsilon adversarial fine-tuning improves medium and high perturbation robustness, but it does not uniformly improve every perturbation budget. The small negative result at `eps=0.03` should be reported transparently as a tradeoff.

## Security-OR Note

The corrected `Security-OR Ensemble IDS` uses calibrated threshold margins rather than raw probability maxima. Its clean detection performance is lower than the final `Adv+ExtraTrees Ensemble IDS`, with binary F1 `0.8796` compared with `0.9063`. However, the corrected Security-OR transfer-PGD evaluation reports `0.00%` evasion at all tested epsilon values. This means it can be discussed as a stricter high-security operating point, but it should not replace `Adv+ExtraTrees` as the final selected model because it sacrifices clean balanced accuracy and rare-family recall.

| Epsilon | Surrogate Torch Evasion | Security-OR Evasion | Absolute Reduction |
| --- | ---: | ---: | ---: |
| 0.03 | 33.39% | 0.00% | 33.39 pp |
| 0.06 | 61.74% | 0.00% | 61.74 pp |
| 0.10 | 90.69% | 0.00% | 90.69 pp |
| 0.15 | 100.00% | 0.00% | 100.00 pp |

## Report Recommendation

The report should present `Adv+ExtraTrees Ensemble IDS` as the final selected model. The `SHAP-Robust ExtraTrees IDS` should be described as a robustness-improving component rather than the final deployed detector. The direct adversarial Torch model should be described as a surrogate and robustness training component, not as the best standalone classifier. The `Security-OR Ensemble IDS` may be mentioned as an alternative high-security thresholding strategy, but the main model remains `Adv+ExtraTrees`.
