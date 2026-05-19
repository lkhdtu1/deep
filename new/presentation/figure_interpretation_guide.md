# Figure Interpretation Guide For The 10-Slide Presentation

Use this guide to understand what each figure means and how to explain it during the oral defense.

## Important Scale Warning

Do not compare the raw height of SHAP bars with the raw height of SmoothIG bars. They are produced by different explanation methods and have different numerical units.

TreeSHAP values are average contribution magnitudes for tree-based predictions. A mean SHAP value around 0.02 or 0.05 can be important because it is measured in the model's tree-output contribution scale.

SmoothIG values are smoothed integrated-gradient attribution magnitudes for a neural score. They can be much larger, for example 5 or 6, because they come from accumulated gradients along an input path and are not normalized like SHAP values.

The correct comparison is therefore: compare feature rankings inside the same method, compare whether the selected features make security sense, and compare stability metrics. Do not say that SmoothIG is "more important" than SHAP only because its bars are numerically larger.

## Slide 4 - Final Ensemble Explanation

Figure: `adv_tree_ensemble_top10.png`

This figure explains what the final Adv+ExtraTrees ensemble uses to make IDS decisions. The most important features include connection flag behavior, service concentration, host-service counts, login state, and error-rate features. These are logical IDS features because attacks often change connection success patterns, service repetition, and error behavior.

How to say it orally: "This figure shows that the final model is not using arbitrary variables. It relies on meaningful network behavior: successful connection flags, repeated service access, login status, and host-level error rates."

## Slide 5 - RF SHAP And SmoothIG

Figures: `rf_shap_top10.png` and `torch_binary_smoothig_top10.png`

TreeSHAP explains the Random Forest or tree model. It gives average feature contributions. SmoothIG explains the neural binary MLP. It averages Integrated Gradients over noisy inputs to reduce gradient noise.

The key point is that both methods highlight security-relevant features, but their numerical scales differ. RF SHAP values below 0.025 can still be important in the tree model. SmoothIG values above 5 are not "five times stronger" than SHAP values; they are a different attribution scale.

How to say it orally: "We use several explainers because model families are different. TreeSHAP is appropriate for trees, while SmoothIG is appropriate for neural networks. We compare the meaning and stability of top features, not raw values across methods."

## Slide 5 - Stability Results

The stability values summarize whether explanations keep similar top features across local perturbations or resampled data. Local Jaccard close to 1 means that the top features are mostly preserved. The results are high: RF SHAP 0.880, Torch IG 0.881, SmoothIG 0.899, and final ensemble 0.845.

How to say it orally: "The explanations are stable enough to be useful for analysts, but this stability also creates a risk because attackers can repeatedly identify the same important features."

## Slide 6 - Explanation-Guided Attacks

Figures: `rf_shap_evasion_local.png`, `ig_evasion_heatmap.png`, and `adv_tree_shap_evasion.png`

The first figure shows that local SHAP-guided perturbations can evade the Random Forest, with a best result of 18.22%. The second shows that Integrated-Gradient-guided perturbations can evade the Torch MLP, with a best result of 15.97%. The third shows that the final robust ensemble remains at 0.00% evasion under the tested TreeSHAP-guided attack settings.

How to say it orally: "This is the dual-use part of explainability. Explanations help analysts understand alerts, but they also tell attackers which features are worth manipulating. The final ensemble is more resistant under the tested explanation-guided attack."

## Slide 7 - PGD Stress Tests

Figures: `torch_binary_pgd_evasion.png` and `torch_binary_adv_constrained_pgd_evasion.png`

Full-feature PGD is a white-box stress test against the differentiable Torch Binary MLP. It can perturb all normalized features, so it is strong but not fully realistic. It reaches 100% evasion on the original neural model.

Mutable-feature PGD is more realistic because categorical and binary fields are frozen. It still attacks the neural model but only through continuous behavior-derived features. After adversarial fine-tuning, evasion is reduced strongly at eps 0.10 and eps 0.15.

How to say it orally: "Full PGD proves the neural model alone is fragile. Mutable-feature PGD is more realistic and shows that adversarial fine-tuning helps, but does not solve all attacks."

## Slide 8 - Transfer-PGD Defense

Figure: `adv_tree_transfer_pgd_defense.png`

This is the strongest defense figure. The attack is generated against the Torch surrogate. The surrogate is highly vulnerable, but the same adversarial examples do not transfer well to the final Adv+ExtraTrees ensemble. Evasion falls from 37.29%, 63.99%, 91.24%, and 100.00% on the surrogate to 0.50%, 0.00%, 0.00%, and 0.00% on the ensemble.

How to say it orally: "The final model is not just a stronger neural network. It is heterogeneous. The attacker follows the neural gradients, but the robust tree-heavy ensemble has a different decision structure, so transferability breaks under the tested setting."

## Slide 9 - Security-OR

Security-OR is not the final default model. It is a stricter mode that flags a sample if either calibrated component is confident. It is useful when false negatives are very expensive, but its clean F1 is lower than the selected Adv+ExtraTrees model.

How to say it orally: "Security-OR is a high-security operating mode, not our main performance claim. The default model is Adv+ExtraTrees because it has better clean F1 and still strong defense."

## Most Defensible Final Explanation

The final result is coherent because the IDS uses meaningful security features, the explanations are stable, explanation-guided attacks reveal a real dual-use risk, and the final heterogeneous ensemble strongly reduces tested transfer-PGD evasion. The limitations are also clear: NSL-KDD is old, feature-space attacks are imperfect, and 0.00% evasion is empirical under tested settings, not certified universal robustness.
