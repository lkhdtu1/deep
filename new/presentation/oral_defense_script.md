# Project 5 Oral Defense Script

Target duration: 10 to 15 minutes.

## Slide 1: Title

Good morning. Today I will present our Project 5 work: an explainable and adversarially evaluated intrusion detection system built on the NSL-KDD dataset. The final selected model is the Adv+ExtraTrees Ensemble IDS. It achieves a binary F1 score of 0.9063, a PR-AUC of 0.9626, and a balanced accuracy of 0.9064. The important point of this project is that we did not evaluate the IDS only with accuracy. We also studied whether the model decisions are explainable, whether those explanations are stable, and whether explanations can create adversarial risk.

## Slide 2: Project Objective And Requirements

The assignment asks us to train an IDS model, apply explainability, evaluate explanation stability, and analyze security implications. Our main research question is whether an IDS can be both interpretable and robust when its explanations may also be visible to an attacker. This is a dual-use problem. Explanations help security analysts understand alerts and validate model behavior, but they can also reveal which features an adversary should manipulate to evade detection.

## Slide 3: Dataset And Preprocessing

We used NSL-KDD, with 125,973 training records and 22,544 test records. The labels are mapped into normal, DoS, Probe, R2L, and U2R. We also use a binary label where every attack family is class 1 and normal traffic is class 0. The final feature representation has 478 features after one-hot encoding and feature engineering. The categorical fields protocol type, service, and flag are one-hot encoded, and MinMax scaling is fitted only on the training set to avoid test leakage. We also add IDS-oriented engineered features such as log-transformed byte counts, byte ratios, traffic totals, service ratios, error-rate gaps, and a login anomaly score. R2L and U2R are especially important because they are rare and harder to detect than DoS or Probe.

## Slide 4: Model Pipeline

The pipeline starts with a Logistic Regression baseline, then adds Random Forest with TreeSHAP, a CUDA Torch MLP with Integrated Gradients, and a Torch Binary MLP with SmoothIG. We then improve robustness in two ways. First, the Torch Binary MLP is fine-tuned using multi-epsilon PGD adversarial examples. Second, the ExtraTrees model is made more robust using SHAP-guided adversarial data augmentation. The final selected model is a heterogeneous ensemble combining the adversarial Torch detector with the SHAP-Robust ExtraTrees detector. This design is useful because attacks generated against the differentiable neural surrogate do not transfer well to the tree-heavy final ensemble.

## Slide 5: Main Clean Results

The clean results show that the Adv+ExtraTrees Ensemble IDS is the best final operating model. It achieves binary F1 0.9063, PR-AUC 0.9626, and balanced accuracy 0.9064. The SHAP-Robust ExtraTrees component alone is already strong, with F1 0.8912, but the final ensemble improves the clean operating balance. The Security-OR mode reaches a lower clean F1 of 0.8796, so it is not the selected final model. It is kept only as an optional stricter operating point for high-security situations.

## Slide 6: Rare-Family Recall

Looking only at global metrics can hide poor performance on rare attacks. That is why we report per-family recall. The final model reaches 0.9859 recall for DoS and 1.0000 for Probe. More importantly, it reaches 0.6786 recall for R2L and 0.8060 for U2R. These are the most difficult families because they are rare, subtle, and affected by the KDDTest+ distribution shift. We do not claim these classes are solved, but the final ensemble gives a much stronger result than standard tree and neural baselines.

## Slide 7: Explainability Methods

We use several explanation methods because the models have different structures. TreeSHAP explains the Random Forest and tree components. Integrated Gradients explains the Torch MLP by integrating gradients from a baseline to the input. SmoothIG is used for the Torch Binary MLP to reduce noisy local gradients. For the final ensemble, we combine normalized tree explanations with the neural attribution component. The final top features are meaningful for IDS decision-making: flag_SF and logged_in describe connection and login state, same_srv_rate and dst_host_same_srv_rate describe service consistency, and rerror_rate and dst_host_rerror_rate describe error behavior. This supports the claim that the IDS decisions are based on relevant traffic patterns rather than arbitrary features.

## Slide 8: Explanation Stability

The project also evaluates explanation stability. This means checking whether similar samples or resampled models produce similar important features. RF SHAP has local Jaccard 0.8802, Torch IG has local Jaccard 0.8811, SmoothIG has local Jaccard 0.8992, and the final ensemble has local Jaccard 0.8453. These values show that the explanations are reasonably stable. This is useful for analysts because stable explanations are easier to trust. However, it is also a security risk because stable explanations reveal consistent manipulation directions to an attacker.

## Slide 9: Adversarial Attacks

The adversarial analysis confirms the dual-use risk of explanations. A SHAP-guided attack reaches 18.22 percent evasion against the Random Forest, and an Integrated-Gradient-guided attack reaches 15.97 percent against the Torch MLP. The original Torch Binary MLP is completely vulnerable to full-feature PGD, with 100 percent evasion at all tested epsilon values. After multi-epsilon adversarial fine-tuning, low-budget PGD improves, but high-budget direct white-box PGD remains difficult. This is why the final model does not rely on the neural detector alone. Against the final Adv+ExtraTrees ensemble, TreeSHAP-guided evasion is 0.00 percent under the tested settings.

## Slide 10: Defense Results

The strongest result is the transfer-PGD defense evaluation. In this experiment, PGD adversarial examples are generated against the differentiable adversarial Torch surrogate, then tested against the final Adv+ExtraTrees ensemble. The surrogate model is vulnerable: evasion rises from 37.29 percent at epsilon 0.03 to 100 percent at epsilon 0.15. However, the final ensemble reduces transfer evasion to 0.50 percent at epsilon 0.03 and 0.00 percent at epsilon 0.06, 0.10, and 0.15. This is the central defense result. We describe it carefully: it is empirical robustness under the tested transfer-PGD threat model, not a mathematical guarantee against every possible adaptive attacker.

## Slide 11: Limitations

The limitations are important. NSL-KDD is a useful benchmark, but it is old and does not fully represent modern cloud or encrypted network traffic. KDDTest+ also has distribution shift and novel attack types, so validation performance is easier than final test performance. R2L and U2R remain difficult because they are rare. Full-feature PGD is a strong stress test, but it may be unrealistic because it can perturb one-hot and binary fields. Mutable-feature PGD is more realistic, but it still works in feature space rather than generating valid packet traces. Finally, the robustness results are empirical and not certified.

## Slide 12: Conclusion

The conclusion is that explainability is necessary but dual-use in cybersecurity. Stable explanations help analysts understand IDS decisions, but they can also guide evasion. The final Adv+ExtraTrees Ensemble IDS provides the best balance in this project: strong clean detection, improved rare-family recall, direct final-model explanation, and near-zero transfer-PGD evasion under the tested threat model. Security-OR is useful as an optional stricter mode, but Adv+ExtraTrees remains the recommended final model.
