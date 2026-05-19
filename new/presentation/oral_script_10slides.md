# 10-Slide Oral Defense Script

This script matches `project5_presentation_10slides.html`. It is designed for a shorter 10 to 12 minute defense. The key is to present the work as an explainable and security-tested IDS pipeline, not as a simple accuracy benchmark.

## Slide 1 - Explainable IDS Under Adversarial Pressure

Good morning. We are TAMIS Mohammed and GRYACH IKRAM, and our project is about explainable intrusion detection under adversarial pressure. The dataset is NSL-KDD, and the final selected model is the Adv+ExtraTrees Ensemble IDS.

The final model reaches a binary F1 score of 0.9063 and a PR-AUC of 0.9626. More importantly, the model is not evaluated only on clean performance. We also explain its decisions, measure whether the explanations are stable, use explanations to guide attacks, and test defenses against adversarial evasion.

The strongest defense result is that transfer-PGD evasion drops to 0.50% at eps 0.03 and 0.00% at eps 0.06, 0.10, and 0.15. This does not mean the IDS is impossible to attack. It means the final ensemble is empirically robust under the tested transfer-PGD setting.

## Slide 2 - From Dataset To Defensible IDS Decision

This slide shows the full pipeline. The training set contains 125,973 records, the test set contains 22,544 records, and after preprocessing we obtain 478 features. The preprocessing includes one-hot encoding, scaling, and engineered traffic features.

The pipeline follows the assignment requirements. We train several models, including Logistic Regression, Random Forest, ExtraTrees, XGBoost, and Torch MLPs. Then we explain the decisions with TreeSHAP, Integrated Gradients, and SmoothIG. After that, we measure explanation stability and test adversarial attacks such as SHAP-guided evasion, IG-guided evasion, PGD, and mutable-feature PGD.

The final step is defense. We use adversarial training, SHAP-guided robust ExtraTrees, and a heterogeneous ensemble. This is why the project is not only about classification; it connects IDS performance, explainability, stability, and security analysis.

## Slide 3 - Best Default Model

The selected default model is Adv+ExtraTrees Ensemble IDS. It has binary F1 of 0.9063, PR-AUC of 0.9626, and balanced accuracy of 0.9064. These values are better than the main baselines and better than the SHAP-Robust ExtraTrees model alone.

The family recall plot is important because global metrics can hide weak behavior on rare attack families. DoS and Probe are detected very well, with recall values of 0.9859 and 1.0000. R2L and U2R are harder because they are rarer and more similar to normal behavior, but the final model still reaches 0.6786 for R2L and 0.8060 for U2R.

The conclusion from this slide is that the final model gives the best operational compromise. It performs well on clean data, improves difficult families, and will later show strong adversarial defense.

## Slide 4 - Explanations Show Meaningful Network Evidence

This slide explains the final ensemble. The top features include connection flags, service concentration, host-service counts, login state, and error-rate variables. These are meaningful for intrusion detection because attacks often change connection success patterns, repeated service behavior, and error rates.

There is an important point about scale. SHAP and SmoothIG values are not directly comparable. A SHAP value around 0.02 or 0.05 can be important because it is measured in the tree model's contribution scale. SmoothIG values can reach 5 or 6 because they come from integrated gradient magnitudes in a neural network.

So we do not say that SmoothIG is more important than SHAP because the number is larger. We compare the feature ranking inside each method, the security meaning of the features, and the stability of explanations.

## Slide 5 - Different Explainers, Same Security Story

This slide shows why one explanation method is not enough. TreeSHAP is used for tree-based models because it explains tree decisions through feature contributions. SmoothIG is used for the neural binary model because it smooths Integrated Gradients and reduces gradient noise.

The stability metrics show that the explanations are relatively reliable. RF SHAP has local Jaccard stability of 0.880, Torch IG has 0.881, SmoothIG has 0.899, and the final ensemble has 0.845. These values mean that top important features are mostly preserved across local variations.

The security deduction is double-sided. Stable explanations are good for analysts because they make alerts easier to trust. But stable explanations can also help attackers because they reveal consistent features to manipulate.

## Slide 6 - Explanations Help Analysts, But Also Guide Evasion

Here we test the dual-use risk of explainability. For the Random Forest, SHAP-guided evasion reaches 18.22% in the best tested setting. For the Torch MLP, Integrated-Gradient-guided evasion reaches 15.97%.

This proves that explanations are not just passive descriptions. They can identify features that matter enough to change the model's decision. In cybersecurity, this is important because the same information that helps an analyst can also guide an attacker.

The final ensemble behaves better under the tested explanation-guided attack. TreeSHAP-guided evasion against the final ensemble is 0.00% under the tested settings. This supports the hardening effect of the robust tree model and the ensemble.

## Slide 7 - Neural IDS Alone Remains Vulnerable

This slide explains the PGD results. Full-feature PGD is a white-box stress test against the differentiable Torch Binary MLP. It is very strong because it uses gradients and can modify all normalized features. The original Torch Binary MLP reaches 100% evasion under this attack.

However, full-feature PGD is not fully realistic because it can modify categorical and binary fields in feature space. That is why we also test mutable-feature PGD, where categorical and binary features are frozen and only continuous behavior-derived features are changed.

Adversarial fine-tuning improves mutable-feature PGD robustness at stronger budgets. The reduction is 32.03 percentage points at eps 0.10 and 42.03 percentage points at eps 0.15. The limit is that direct high-budget white-box PGD remains strong, so the neural detector should not be deployed alone.

## Slide 8 - The Final Ensemble Breaks Transferability

This is the strongest defense result. The attack is generated against the Torch surrogate model and then transferred to the final ensemble. On the surrogate, evasion is high: 37.29%, 63.99%, 91.24%, and 100.00% across the eps values.

When the same adversarial examples are evaluated on the final Adv+ExtraTrees ensemble, evasion becomes 0.50%, 0.00%, 0.00%, and 0.00%. This means the adversarial examples that fool the neural surrogate do not transfer well to the final heterogeneous model.

The deduction is that the final model benefits from diversity. The attacker follows the neural gradient direction, but the robust tree-heavy ensemble has a different decision structure. This breaks transferability under the tested setting.

## Slide 9 - Security-OR Is Optional, Not The Main Claim

Security-OR is a stricter operating mode. It flags a sample if either calibrated component is confident that the sample is malicious. It reaches 0.00% transfer-PGD evasion in the corrected results, so it is useful in high-security settings.

However, it is not the final default because its clean F1 is 0.8796, lower than the Adv+ExtraTrees F1 of 0.9063. In a real deployment, Security-OR could be used when false negatives are more expensive than additional alerts.

The important limitation is that no defense here is certified. NSL-KDD is old, feature-space attacks are imperfect, and rare families remain challenging. Our claim is strong empirical robustness under tested attacks, not universal immunity.

## Slide 10 - What This Project Demonstrates

To conclude, this project demonstrates a reproducible CUDA pipeline for explainable and adversarially tested IDS. We trained multiple models, selected Adv+ExtraTrees as the best default, explained the final decision, measured stability, attacked the models, and evaluated defenses.

The final model reaches 0.9063 binary F1, 0.9626 PR-AUC, 0.9064 balanced accuracy, and 0.845 final ensemble local explanation stability. It also reduces tested transfer-PGD evasion to near zero.

The main message is that explainability is necessary for analyst trust, but in cybersecurity it must also be treated as a possible attack surface. A good explainable IDS should therefore be accurate, interpretable, stable, and tested under adversarial pressure.
