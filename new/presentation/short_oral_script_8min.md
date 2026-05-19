# Short Oral Script For The Improved Presentation

Target duration: about 8 to 10 minutes.

## Slide 1

This project is about building an intrusion detection system that is not only accurate, but also explainable and evaluated under adversarial conditions. The final selected model is the Adv+ExtraTrees Ensemble IDS. It reaches binary F1 0.9063, PR-AUC 0.9626, and balanced accuracy 0.9064. The central idea is that explainability is useful for analysts, but it can also reveal information to attackers.

## Slide 2

The project requirements from the assignment are to train an IDS model, apply explainability, evaluate explanation stability, and analyze security implications. Our pipeline follows these points directly. We include a baseline, several model variations, multiple explanation methods, stability metrics, adversarial attacks, defenses, and reproducibility files.

## Slide 3

We use NSL-KDD with KDDTrain+ for training and KDDTest+ for final evaluation. The final feature space contains 478 features after one-hot encoding and IDS-specific feature engineering. The difficult part is not only detecting DoS and Probe attacks, but also detecting R2L and U2R, which are rarer and more subtle.

## Slide 4

The model design starts with simple baselines and gradually adds stronger components. Logistic Regression gives the baseline. Random Forest and Torch MLP provide explainable variations. Then we add multi-epsilon PGD adversarial training and SHAP-guided adversarial augmentation for ExtraTrees. The final Adv+ExtraTrees ensemble combines the adversarial neural detector with the robust tree detector.

## Slide 5

The clean results justify the model choice. Adv+ExtraTrees gives the best fixed-threshold performance, with binary F1 0.9063 and balanced accuracy 0.9064. Security-OR is stricter under transfer-PGD, but it has lower clean F1, so it is not the default final model. The selected model is the one that balances clean detection and robustness.

## Slide 6

Per-family recall shows whether the IDS is useful beyond global metrics. The final model performs very well on DoS and Probe, and it improves R2L and U2R compared with standard baselines. R2L recall is 0.6786 and U2R recall is 0.8060. These are not perfect, but they are strong because these families are rare and difficult.

## Slide 7

This slide explains what the final IDS uses to make decisions. The most important features include connection state, service consistency, host-service counts, login state, and error-rate features. These are meaningful for network security, so the model decisions are not arbitrary. This satisfies the explainability goal: the IDS can be interpreted by a security analyst.

## Slide 8

Explanation stability tells us whether the explanations are reliable. The final ensemble has local Jaccard 0.8453 and bootstrap Jaccard 0.8873, which means its important features remain reasonably consistent. This is good for analyst trust. However, it is also a security risk because stable explanations can guide attackers toward the same important features.

## Slide 9

The adversarial analysis shows the dual-use risk of explanations. SHAP-guided and IG-guided attacks can evade standalone models. RF SHAP reaches 18.22% evasion and Torch IG reaches 15.97%. However, the final Adv+ExtraTrees ensemble has 0.00% TreeSHAP-guided evasion under the tested settings.

## Slide 10

This is the strongest defense result. PGD examples are generated against the differentiable Torch surrogate and then transferred to the final ensemble. The surrogate is highly vulnerable, but the final ensemble reduces transfer evasion to 0.50% at epsilon 0.03 and 0.00% at epsilon 0.06, 0.10, and 0.15. This is empirical robustness under the tested transfer-PGD threat model, not a certified guarantee.

## Slide 11

The limitations are important. NSL-KDD is old, KDDTest+ has distribution shift, and R2L/U2R remain difficult. Full-feature PGD is a worst-case feature-space attack and may not be fully realistic. Mutable-feature PGD is more realistic, but it is still not packet-level generation. Therefore, our claims are strong but bounded.

## Slide 12

To conclude, the final Adv+ExtraTrees Ensemble IDS gives the best balance between clean IDS performance, rare-family recall, explainability, stability, and adversarial transfer robustness. The main lesson is that explainability must be evaluated together with security, because explanations can help both defenders and attackers.
