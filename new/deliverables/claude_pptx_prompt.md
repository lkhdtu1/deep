Create a formal 10-12 slide PowerPoint presentation for the attached Project 5 report about an Explainable Intrusion Detection System on NSL-KDD.

Use a professional academic cybersecurity style. Keep slides concise, with clear visuals and speaker notes. Use the figures from the report where appropriate.

Required slide structure:
1. Title slide: Project 5 Explainable IDS, NSL-KDD, group names, date.
2. Problem and objective: explain IDS interpretability, stability, and adversarial risk.
3. Dataset and preprocessing: KDDTrain+/KDDTest+, 478 features, family mapping, feature engineering.
4. Model pipeline: Logistic Regression baseline, Random Forest, Torch MLP, Torch Binary MLP, SHAP-Robust ExtraTrees, Adv+ExtraTrees Ensemble.
5. Main clean results: show that Adv+ExtraTrees is selected with binary F1 0.9063, PR-AUC 0.9626, balanced accuracy 0.9064.
6. Rare-family recall: emphasize R2L recall 0.6786 and U2R recall 0.8060.
7. Explainability: TreeSHAP, Integrated Gradients, SmoothIG, combined ensemble explanation; include top features.
8. Stability analysis: local Jaccard/rank and bootstrap stability; explain dual-use implication.
9. Adversarial attacks: SHAP-guided, IG-guided, PGD, mutable-feature PGD.
10. Defense results: transfer-PGD reduced to 0.50% at eps 0.03 and 0.00% at eps 0.06/0.10/0.15 for Adv+ExtraTrees.
11. Limitations: NSL-KDD age, distribution shift, rare classes, full-feature PGD realism, empirical not certified robustness.
12. Conclusion: Adv+ExtraTrees is final selected model; Security-OR is optional high-security mode.

Important numbers:
- Adv+ExtraTrees binary F1: 0.9063
- Adv+ExtraTrees PR-AUC: 0.9626
- Adv+ExtraTrees balanced accuracy: 0.9064
- Final recall: DoS 0.9859, Probe 1.0000, R2L 0.6786, U2R 0.8060
- Adv+ExtraTrees transfer-PGD evasion: 0.50%, 0.00%, 0.00%, 0.00% for eps 0.03, 0.06, 0.10, 0.15
- Security-OR transfer-PGD evasion: 0.00% at all tested eps values, but lower clean F1 0.8796, so it is not the selected final model.

Please generate the `.pptx` file with clean tables, readable charts, and short speaker notes for each slide.
