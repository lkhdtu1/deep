# Project 5 Oral Defense Q&A

## 1. Why did you use NSL-KDD?

NSL-KDD is the dataset required for Project 5 and is a standard benchmark for intrusion detection experiments. It is useful because it has a fixed training split and a harder test split, KDDTest+, which includes distribution shift and novel attack types. However, we also mention its limitation: it is old and does not fully represent modern network traffic.

## 2. Why are R2L and U2R harder than DoS and Probe?

R2L and U2R are much rarer and more heterogeneous. DoS and Probe attacks often create strong traffic-volume or scanning patterns, while R2L and U2R attacks can be subtle and may look similar to normal connections. This is why per-family recall is important; a global F1 score alone can hide poor rare-class behavior.

## 3. Why is PR-AUC important for IDS?

IDS thresholds are operational decisions. A SOC may choose a lower or higher threshold depending on its tolerance for false positives. PR-AUC evaluates ranking quality across thresholds and is more informative than accuracy when the classes are imbalanced.

## 4. Why is Adv+ExtraTrees the final selected model?

It gives the best overall balance. It has the strongest clean binary F1 and balanced accuracy among the main models, strong rare-family recall, direct final-model explanations, and excellent transfer-PGD defense. Security-OR is stricter against transfer-PGD, but its clean F1 is lower, so it is treated as an optional high-security mode rather than the final model.

## 5. Why not select Security-OR if it has 0.00% transfer-PGD evasion?

Security-OR is useful as a strict high-security mode, but its clean binary F1 is 0.8796, lower than Adv+ExtraTrees at 0.9063. The final model should balance clean detection and robustness, so Adv+ExtraTrees is the better default operating point.

## 6. Does 0.00% evasion mean the model is fully robust?

No. It means 0.00% evasion under the tested transfer-PGD threat model. It is an empirical result, not a certified robustness guarantee. A different adaptive attacker, such as a direct black-box or zeroth-order attack against the full ensemble, could still be investigated.

## 7. What is the difference between direct white-box PGD and transfer-PGD?

Direct white-box PGD attacks the exact differentiable model being evaluated. Transfer-PGD generates adversarial examples against a surrogate model, then tests whether those examples also fool another target model. In our case, attacks generated against the Torch surrogate transfer poorly to the tree-heavy ensemble.

## 8. Why is full-feature PGD unrealistic?

Full-feature PGD can perturb all normalized features, including one-hot encoded protocol/service/flag fields and binary status features. In real network traffic, an attacker cannot arbitrarily change all of these fields independently without violating protocol semantics.

## 9. Why include mutable-feature PGD?

Mutable-feature PGD is more realistic because it freezes categorical and binary fields and only perturbs continuous behavior-derived features. It still does not generate real packets, but it is a more defensible tabular attack model than unrestricted full-feature PGD.

## 10. What does TreeSHAP explain?

TreeSHAP explains tree-based model predictions by assigning Shapley values to features. It tells us how much each feature contributes to pushing a prediction toward attack or normal for tree models such as Random Forest and ExtraTrees.

## 11. What does Integrated Gradients explain?

Integrated Gradients explains neural network predictions by integrating gradients from a baseline input to the real input. It attributes the neural output to input features while satisfying useful axioms such as sensitivity and completeness.

## 12. Why use SmoothIG?

SmoothIG averages Integrated Gradients over noisy versions of the input. This reduces local gradient noise and produces more stable neural attributions, which is useful for IDS analysis.

## 13. What does explanation stability mean?

Explanation stability measures whether important features remain similar across nearby samples or resampled training subsets. Stable explanations are more reliable for analysts, but they can also be more useful to attackers because the important features are predictable.

## 14. Why can stable explanations be dangerous?

If explanations consistently identify the same features as important, an attacker can target those features during evasion. This is the dual-use problem: the same stability that improves analyst trust can create a reliable attack guide.

## 15. How was SHAP-Robust ExtraTrees trained?

The pipeline uses SHAP-guided adversarial augmentation. It identifies important attack features using SHAP, creates perturbed adversarial examples along those important feature directions, and adds them back to the training data with attack labels. This teaches the tree model to resist those explanation-guided manipulations.

## 16. Why did adversarial fine-tuning not solve high-epsilon PGD?

Adversarial fine-tuning improves robustness at lower and medium perturbation budgets, but high-epsilon direct white-box PGD remains very strong because it has full gradient access and a large perturbation budget. This is why the final defense uses a heterogeneous ensemble instead of relying only on the neural model.

## 17. What is the most important defense result?

The transfer-PGD defense of Adv+ExtraTrees. The surrogate Torch model is heavily attacked, but when those adversarial examples are transferred to the ensemble, evasion drops to 0.50% at eps 0.03 and 0.00% at eps 0.06, 0.10, and 0.15.

## 18. What are the main limitations?

The main limitations are the age of NSL-KDD, train-test distribution shift, rare R2L/U2R classes, feature-space attack realism, and lack of certified robustness. The report is careful to state that the defense is empirical under tested attacks, not a universal guarantee.

## 19. How can the results be reproduced?

The code is in `pipeline_cuda.py`. The heavy run uses fixed seed 42 and can be reproduced with:

```powershell
$env:ENABLE_MULTI_EPS_ADV_TRAIN="1"
$env:ENABLE_SHAP_ROBUST_ET="1"
$env:ENABLE_HEAVY_ADV_TREE_XAI="1"
.\venv\Scripts\python.exe pipeline_cuda.py
```

## 20. What is the single best sentence to defend the project?

The final Adv+ExtraTrees Ensemble IDS is not claimed to be fully robust, but it provides the best tested balance of clean IDS performance, rare-family recall, explainability, explanation stability, and empirical transfer-PGD robustness.
