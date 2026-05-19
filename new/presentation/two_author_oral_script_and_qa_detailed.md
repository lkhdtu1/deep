# Project 5 Detailed Two-Author Oral Defense Script and Q&A

This script is written for the recommended presentation file `project5_presentation_showcase.html`. It follows the 16-slide structure of the deck and is designed for a 10 to 15 minute oral defense. The two authors can split the presentation as follows: TAMIS Mohammed presents the project framing, dataset, pipeline, model selection, tools, and operating choices; GRYACH Ikram presents explainability, stability, adversarial attacks, robustness results, and conclusion. The split can be adjusted, but this version keeps the technical flow coherent.

## Speaking Strategy

The main message to defend is that the project is not only a classification experiment. It is an explainable and security-aware IDS pipeline. The final model, Adv+ExtraTrees Ensemble IDS, was selected because it gives the best tested balance between clean detection performance, rare attack-family recall, explanation quality, explanation stability, and adversarial robustness under the evaluated attacks.

The most important numerical result is the final model performance: binary F1 of 0.9063, PR-AUC of 0.9626, and balanced accuracy of 0.9064. The most important security result is that transfer-PGD evasion falls from 37.29%, 63.99%, 91.24%, and 100.00% on the Torch surrogate to 0.50%, 0.00%, 0.00%, and 0.00% on the final Adv+ExtraTrees ensemble. This is the strongest result to emphasize because it connects the adversarial part directly to the final IDS decision.

The most important limitation to state clearly is that 0.00% evasion is not a proof of universal robustness. It means 0.00% evasion under the tested transfer-PGD and TreeSHAP-guided attack settings. The defense is empirical, not certified. Saying this clearly makes the project easier to defend because it shows that the results are strong but not exaggerated.

## Slide 1 - Title: Explainable Intrusion Detection Under Adversarial Pressure

Speaker: TAMIS Mohammed

Good morning. We are TAMIS Mohammed and GRYACH Ikram, and our project is titled Explainable Intrusion Detection Under Adversarial Pressure. The objective of this work is to build an intrusion detection system on the NSL-KDD dataset, explain its decisions, evaluate whether those explanations are stable, and then test whether the same explanations can be used by an attacker to evade detection.

The final system is based on an Adv+ExtraTrees ensemble. It reaches a binary F1 score of 0.9063, a PR-AUC of 0.9626, and a balanced accuracy of 0.9064. These results are important because the model is not evaluated only on clean classification metrics. We also tested adversarial evasion and found that the final ensemble strongly reduces transfer-PGD attacks compared with the neural surrogate. At perturbation budgets eps 0.06, 0.10, and 0.15, the measured transfer evasion on the ensemble is 0.00% under the tested setting.

The key idea of the project is that explainability is useful for analysts, but it is also dual-use. The features that explain malicious behavior can help a security analyst understand why an alert was generated, but they can also guide an attacker toward the features that should be modified. Our work treats explainability as both a transparency tool and a security object that must be tested.

## Slide 2 - What The Project Asked For

Speaker: TAMIS Mohammed

This slide summarizes how the work maps to the assignment requirements. The project asks for an IDS trained on NSL-KDD, with explainability methods, stability evaluation, security analysis, and a clear discussion of limitations. We therefore structured the work around four questions.

First, can the IDS detect attacks with reasonable performance, including difficult minority families? Second, can we explain the IDS decision using methods adapted to the model type? Third, are the explanations stable enough to be trusted by an analyst? Fourth, can those explanations become a weakness if an attacker uses them to guide adversarial perturbations?

The workflow shown on the slide is important because it shows that the pipeline is not a simple model benchmark. We train models, explain them, measure explanation stability, attack them using explanation-guided and gradient-based attacks, and finally evaluate defenses. This follows the assignment requirement to connect machine learning performance with security reasoning.

## Slide 3 - Why The IDS Decision Is Difficult

Speaker: TAMIS Mohammed

NSL-KDD is a useful benchmark because it has a fixed training split and a harder test split, KDDTest+. However, it also has important challenges. The test set is not simply an identical distribution copy of the training set. Some attack types appear differently, and rare attack families are underrepresented. This means that high overall accuracy can be misleading.

The main difficult families are R2L and U2R. DoS and Probe attacks usually create strong traffic-volume or scanning patterns, so they are easier to detect. R2L and U2R are more subtle. They can look closer to normal traffic and they have fewer examples. For this reason, the report and presentation do not rely only on global accuracy. We also report binary F1, PR-AUC, balanced accuracy, and family-level recall.

This explains why some baseline models have high PR-AUC but weak family F1. A model may rank attacks reasonably well in binary terms, but still fail to identify rare families after thresholding. That is why the final model is chosen for a balanced operational decision, not only for one isolated metric.

## Slide 4 - A Pipeline Built To Answer The Assignment

Speaker: TAMIS Mohammed

The pipeline starts by preprocessing NSL-KDD using structured tabular transformations. Categorical fields such as protocol, service, and flag are one-hot encoded, and numerical traffic variables are scaled or transformed where appropriate. Additional engineered features summarize traffic volume, byte ratios, and error-rate relationships. After preprocessing, the input has 478 features.

We trained several model families to satisfy the requirement for a baseline and multiple experimental variations. Logistic Regression acts as the interpretable baseline. Random Forest and ExtraTrees represent tree-based IDS models. XGBoost provides a strong boosting-based comparison. Torch MLP models provide differentiable neural IDS models that can be attacked directly with gradient-based methods. Finally, the robust ExtraTrees and Adv+ExtraTrees ensemble add the adversarial defense layer.

This design is deliberate. Tree models are strong for tabular IDS and can be explained with TreeSHAP. Neural models are useful because Integrated Gradients and PGD attacks require differentiability. The ensemble combines both perspectives: it uses the neural model for adversarial training and the robust tree model for stable tabular decision boundaries.

## Slide 5 - Which IDS Is Best To Deploy?

Speaker: TAMIS Mohammed

This slide compares the main candidate models. The selected model is Adv+ExtraTrees Ensemble IDS. It achieves binary F1 of 0.9063, PR-AUC of 0.9626, and balanced accuracy of 0.9064. The SHAP-Robust ExtraTrees model is also strong, with F1 of 0.8912 and balanced accuracy of 0.8941, but the ensemble improves the final operating point.

The baseline models are useful for comparison, but they do not provide the same tradeoff. Logistic Regression reaches binary F1 of 0.8344, which is acceptable but weaker. Random Forest reaches only 0.7633 binary F1 on the test set, despite high validation behavior, showing the effect of dataset shift. The plain Torch Binary MLP reaches 0.8021 binary F1, and the PGD-adversarial Torch model has lower clean F1 in the heavy setting, at 0.7592.

The important deduction is that the final model is not selected because it maximizes only one number. It is selected because it combines clean detection quality with adversarial robustness and explainability. Security-OR is stricter against transfer-PGD, but its F1 is lower, so it is kept as an optional high-security mode rather than the default model.

## Slide 6 - Tools Used To Explain, Test, Attack, And Defend

Speaker: TAMIS Mohammed

This slide is the technical toolbox. We used TreeSHAP to explain tree-based models because it is designed for decision trees and gives feature contribution values. We used Integrated Gradients for the multiclass Torch MLP because it explains differentiable neural networks by accumulating gradients from a baseline to the input. We used Smooth Integrated Gradients for the binary Torch MLP because averaging over noisy inputs reduces local gradient noise and improves attribution stability.

For stability, we measured local Jaccard similarity, rank stability, bootstrap Jaccard, and bootstrap rank stability. Local stability checks whether nearby samples produce similar important features. Bootstrap stability checks whether explanations remain similar when the data sample changes. These measures are important because an explanation that changes completely with small perturbations is not reliable for security analysis.

For attacks, we used SHAP-guided evasion, Integrated-Gradient-guided evasion, full-feature PGD, SmoothIG-constrained PGD, mutable-feature PGD, and transfer-PGD. This allows us to test both explanation-guided attacks and gradient-based attacks. For defenses, we used adversarial fine-tuning, SHAP-guided adversarial augmentation for ExtraTrees, and a heterogeneous ensemble designed to reduce attack transferability.

## Slide 7 - Does The Final IDS Catch The Difficult Families?

Speaker: TAMIS Mohammed

This slide focuses on family recall for the final Adv+ExtraTrees ensemble. The model reaches 0.9859 recall for DoS and 1.0000 recall for Probe, which confirms that the easier high-pattern attacks are detected very well. More importantly, the final model also improves the difficult families: R2L recall reaches 0.6786 and U2R recall reaches 0.8060.

This is a strong result because R2L and U2R are usually the weakest classes on NSL-KDD. They are rare, heterogeneous, and often close to normal behavior. The final model does not solve them perfectly, but it clearly improves their detection compared with many of the simpler models. For example, Random Forest has R2L recall of only 0.0623 and U2R recall of 0.1940, while the final ensemble reaches 0.6786 and 0.8060.

The deduction is that the defense strategy did not only make the model robust on artificial attacks. It also improved the operational IDS behavior for rare attack families. This matters for security because missing rare attacks can be more dangerous than missing common obvious attacks.

## Slide 8 - What The Final Ensemble Uses To Decide

Speaker: GRYACH Ikram

Now we move to explainability. This slide shows the top features used by the final Adv+ExtraTrees ensemble. The most important features include `flag_SF`, `same_srv_rate`, `dst_host_srv_count`, `logged_in`, `dst_host_same_srv_rate`, `rerror_rate`, `dst_host_rerror_rate`, `service_private`, `same_diff_srv_gap`, and `dst_host_srv_serror_rate`.

These features are coherent from a network security perspective. For example, `flag_SF` is related to normal successful connection behavior. `same_srv_rate` and `dst_host_same_srv_rate` describe whether recent connections are concentrated on the same service, which is useful for detecting scans or repeated attack behavior. Error-rate features such as `rerror_rate` and `dst_host_rerror_rate` capture abnormal failed or rejected connections. The `logged_in` feature helps distinguish authenticated and unauthenticated behavior, which is especially relevant for user-level attack families.

The explanation therefore supports the IDS decision. The final model is not relying on arbitrary or meaningless variables. It uses connection status, service concentration, host-level behavior, and error patterns. These are exactly the types of features a security analyst would expect in network intrusion detection.

## Slide 9 - Why One Explanation Method Is Not Enough

Speaker: GRYACH Ikram

This slide compares several explanation views. TreeSHAP for Random Forest emphasizes traffic volume and host-service aggregation features such as `dst_host_srv_count`, `traffic_total_log`, `count`, and byte-related variables. Integrated Gradients for the Torch MLP emphasizes error-rate gaps and protocol-related variables such as `host_serror_gap`, `host_rerror_gap`, `rerror_gap`, and `protocol_type_tcp`. SmoothIG for the binary Torch model also highlights error-rate and traffic features, but with smoother neural attributions.

The Spearman correlation between RF SHAP and Torch Integrated Gradients is 0.6774. This is useful because it means the explanations are not identical, but they are also not contradictory. They have moderate to strong agreement. In other words, different model families see some of the same security patterns, but they also emphasize different aspects of the data.

The deduction is that using multiple explanation methods makes the analysis stronger. If we used only one method, we might confuse one model's bias with a general security conclusion. By comparing TreeSHAP, Integrated Gradients, SmoothIG, and the final ensemble explanation, we can separate stable security signals from model-specific behavior.

## Slide 10 - Are The Explanations Reliable?

Speaker: GRYACH Ikram

This slide evaluates explanation stability. RF SHAP has local Jaccard stability of 0.8802 and local rank stability of 0.9960. Torch IG has local Jaccard stability of 0.8811 and local rank stability of 0.9827. Torch Binary SmoothIG has local Jaccard stability of 0.8992. The final Adv+ExtraTrees ensemble has local Jaccard stability of 0.8453 and bootstrap Jaccard stability of 0.8873.

These values show that the explanations are relatively stable. The exact order of every feature can change, especially across bootstrapped samples, but the important feature set remains largely consistent. This is important for analyst trust. If an IDS says that an alert is due to connection status, service concentration, and error-rate behavior, those reasons should not change randomly from one nearly similar sample to another.

However, stability has a security downside. Stable explanations reveal consistent high-value attack surfaces. If an attacker knows that the IDS consistently depends on a set of features, they may target those features to evade detection. This is why the project does not stop at explainability. It uses explanation stability as a bridge toward adversarial testing.

## Slide 11 - Explanations Help Analysts, But Also Guide Attacks

Speaker: GRYACH Ikram

This slide demonstrates the dual-use nature of explainability. We used SHAP-guided evasion against the Random Forest and Integrated-Gradient-guided evasion against the Torch MLP. The best RF SHAP-guided evasion reaches 18.22% under the local top-15, eps 0.10 setting. The best Torch IG-guided evasion reaches 15.97% under the top-15, eps 0.10 setting.

These evasion rates are not catastrophic, but they are meaningful. They show that explanation methods can identify features that matter enough to influence model decisions. For an analyst, this helps interpret alerts. For an attacker, it gives a map of where to perturb the input. This is exactly the security implication requested by the assignment.

The final ensemble behaves differently. TreeSHAP-guided evasion against the Adv+ExtraTrees ensemble remains 0.00% under the tested settings. This suggests that the robust tree augmentation and ensemble design make the final model less vulnerable to the same explanation-guided manipulation that affects simpler models.

## Slide 12 - Why The Neural Detector Alone Is Not Enough

Speaker: GRYACH Ikram

This slide shows the direct PGD stress test against the Torch Binary MLP. The original Torch Binary model is completely vulnerable to unrestricted full-feature PGD: evasion reaches 100.00% even at eps 0.03. This is a severe result, but it must be interpreted carefully.

Full-feature PGD is a strong white-box attack. It can perturb all normalized features, including features that may not be freely mutable in real network traffic. Therefore, it is useful as a stress test, but not as a perfect simulation of a real attacker. It tells us that a differentiable neural IDS alone should not be trusted without additional defenses.

After multi-epsilon PGD adversarial fine-tuning, the neural model improves at lower and medium eps values. Evasion falls from 100.00% to 33.34% at eps 0.03, to 61.72% at eps 0.06, and to 90.69% at eps 0.10. At eps 0.15, it remains 100.00%. The deduction is that adversarial training helps, but it does not solve high-budget white-box evasion by itself.

## Slide 13 - A More Realistic Feature Manipulation Attack

Speaker: GRYACH Ikram

Because unrestricted full-feature PGD is too permissive, the pipeline also evaluates mutable-feature PGD. In this version, categorical and binary fields are frozen, and only continuous behavior-derived features are perturbed. This is still a feature-space attack, but it is more realistic than allowing arbitrary changes to one-hot protocol or service fields.

For the original Torch Binary MLP, mutable-feature PGD reaches 11.70% evasion at eps 0.03, 30.76% at eps 0.06, 71.21% at eps 0.10, and 100.00% at eps 0.15. After adversarial fine-tuning, the results become 14.05%, 26.38%, 39.18%, and 57.97%. The reduction is negative at eps 0.03, because the defended model is slightly worse at that very low budget, but it becomes meaningful at higher budgets: 32.03 percentage points reduction at eps 0.10 and 42.03 percentage points reduction at eps 0.15.

This is an important nuance. Defense is not uniformly better at every possible perturbation budget. The report states this honestly. The strong conclusion is not that adversarial fine-tuning solves everything, but that it improves robustness under more realistic medium and high perturbation budgets while showing limits at low budgets.

## Slide 14 - The Final Ensemble Breaks Transferability

Speaker: TAMIS Mohammed

This is the strongest defense result in the project. Transfer-PGD adversarial examples are generated against the Torch surrogate, and then tested against the final Adv+ExtraTrees ensemble. On the surrogate, evasion is high: 37.29% at eps 0.03, 63.99% at eps 0.06, 91.24% at eps 0.10, and 100.00% at eps 0.15.

When these same adversarial examples are transferred to the final ensemble, evasion falls to 0.50%, 0.00%, 0.00%, and 0.00%. This means the adversarial examples that fool the differentiable Torch model do not transfer effectively to the heterogeneous tree-heavy ensemble. The reductions are 36.79, 63.99, 91.24, and 100.00 percentage points.

The deduction is that the final model benefits from diversity. The attacker optimizes against a differentiable neural decision surface, but the final deployed detector combines that information with a robust ExtraTrees model trained with SHAP-guided adversarial augmentation. This breaks transferability under the tested setting and gives a stronger IDS decision than either component alone.

## Slide 15 - Security-OR Is A High-Security Mode, Not The Final Default

Speaker: TAMIS Mohammed

Security-OR is an optional stricter operating mode. It flags a sample if either calibrated component is confident that the sample is malicious. In the presentation, it achieves 0.00% transfer-PGD evasion at all tested eps values. This is attractive from a security perspective, especially in environments where false negatives are extremely costly.

However, Security-OR is not selected as the final default because its clean F1 is lower than the Adv+ExtraTrees default. The final model has F1 of 0.9063, while Security-OR has F1 of 0.8796 in the corrected deck results. This means Security-OR is more conservative, but less balanced as a general IDS operating point.

The correct defense position is to treat Security-OR as a deployment option. If the environment is high-risk and the cost of missing an intrusion is much higher than the cost of additional alerts, Security-OR is reasonable. If the goal is a balanced IDS for the assignment evaluation, Adv+ExtraTrees is the better final model.

## Slide 16 - What This Project Demonstrates

Speaker: GRYACH Ikram

To conclude, this project demonstrates an explainable IDS pipeline that goes beyond ordinary classification. We trained several IDS models, explained their decisions with TreeSHAP, Integrated Gradients, SmoothIG, and final ensemble explanations, measured explanation stability, used explanations to guide evasion attacks, and then evaluated adversarial defenses.

The final Adv+ExtraTrees ensemble provides the best tested balance. It reaches 0.9063 binary F1, 0.9626 PR-AUC, and 0.9064 balanced accuracy. It also improves difficult attack-family recall, especially R2L and U2R, compared with weaker baselines. Its explanations are coherent with network security logic because they rely on connection status, service concentration, host-level behavior, login behavior, and error-rate features.

The most important security conclusion is that explainability must be handled carefully. Stable explanations help analysts understand IDS alerts, but they can also guide attacks. The final defense does not claim universal robustness, but it shows strong empirical robustness under tested explanation-guided attacks and transfer-PGD attacks. The main limitations are the age of NSL-KDD, the difficulty of rare classes, the imperfect realism of feature-space attacks, and the absence of certified robustness. These limitations are acknowledged clearly, which makes the results more defensible.

Thank you for your attention. We are ready to answer your questions.

# Detailed Q&A for Oral Defense

## 1. Why did you use NSL-KDD?

NSL-KDD is the dataset required by Project 5 and is a standard benchmark for intrusion detection experiments. It is useful because it provides fixed train and test splits, including KDDTest+, which is harder than the training distribution. At the same time, we clearly state its limitation: it is an old dataset and does not fully represent modern encrypted, cloud, or IoT traffic. Therefore, our conclusions are valid for the benchmark and the tested threat models, not for all real networks.

## 2. Why is IDS evaluation harder than normal classification?

IDS evaluation is harder because the cost of mistakes is asymmetric. A false negative means an attack is missed, while a false positive creates unnecessary alerts. Also, the dataset is imbalanced and some attack families are rare. Accuracy can hide these problems, so we use binary F1, PR-AUC, balanced accuracy, and family recall.

## 3. Why are R2L and U2R difficult?

R2L and U2R are rare and subtle. They often do not generate the same strong traffic-volume patterns as DoS or Probe attacks. They can resemble normal authenticated or low-volume traffic, so models trained on general patterns tend to miss them. This is why the final ensemble's R2L recall of 0.6786 and U2R recall of 0.8060 are important improvements.

## 4. Why did you choose Adv+ExtraTrees as the final model?

Adv+ExtraTrees is the best default because it balances clean detection, rare-family recall, explainability, and adversarial robustness. It has binary F1 of 0.9063, PR-AUC of 0.9626, and balanced accuracy of 0.9064. It also has direct final-model explanations and strong transfer-PGD defense. Security-OR is stricter, but its clean F1 is lower, so it is not the best default operating point.

## 5. Why not choose the model with the highest PR-AUC only?

PR-AUC measures ranking quality across thresholds, but deployment requires a threshold decision. A model with high PR-AUC can still perform poorly after thresholding or on rare attack families. We selected the final model using a broader view: F1, balanced accuracy, family recall, explainability, and adversarial behavior.

## 6. What is the difference between binary classification and family classification here?

Binary classification answers whether a connection is normal or attack. Family classification identifies the attack family, such as DoS, Probe, R2L, or U2R. Binary detection is the main IDS alarm decision, while family-level analysis tells us whether the detector is missing specific types of attacks.

## 7. What does PR-AUC mean in this project?

PR-AUC measures the precision-recall tradeoff across possible thresholds. It is useful for IDS because class imbalance makes accuracy less informative. A high PR-AUC means the model ranks malicious samples above normal samples well, but the final threshold still determines the practical alert behavior.

## 8. Why use TreeSHAP?

TreeSHAP is appropriate for tree-based models such as Random Forest and ExtraTrees. It assigns feature contribution values to predictions and helps us see which features push the model toward attack or normal. It is especially useful here because the final ensemble includes a robust ExtraTrees component.

## 9. Why use Integrated Gradients?

Integrated Gradients is appropriate for neural networks. It attributes a neural prediction to input features by integrating gradients from a baseline input to the actual input. We used it for the Torch MLP because it explains differentiable models better than tree-specific methods.

## 10. Why use SmoothIG instead of only Integrated Gradients?

SmoothIG averages Integrated Gradients over noisy versions of the same input. This reduces local gradient noise and gives more stable attributions. In our results, Torch Binary SmoothIG has local Jaccard stability of 0.8992, which supports its use as a more stable neural explanation method.

## 11. What does the RF/Torch Spearman correlation of 0.6774 mean?

It means the Random Forest SHAP explanation and Torch Integrated Gradients explanation have moderate to strong agreement in feature importance ranking. They are not identical because the models learn different decision boundaries, but they are aligned enough to suggest that the explanations are capturing real security patterns rather than random artifacts.

## 12. What does explanation stability mean?

Explanation stability means that important features remain similar when we evaluate nearby samples or resampled data. We measured it using local Jaccard similarity, local rank stability, bootstrap Jaccard, and bootstrap rank stability. Stable explanations are more trustworthy for analysts because they do not change randomly.

## 13. Can stable explanations be dangerous?

Yes. Stable explanations are useful for analysts, but they can also reveal a stable attack surface. If the same features are always important, an attacker can target those features during evasion. This is why the project evaluates explanation-guided attacks.

## 14. What was the strongest explanation-guided attack result?

The strongest RF SHAP-guided evasion result is 18.22% under local top-15 features and eps 0.10. The strongest Torch IG-guided evasion result is 15.97% under top-15 features and eps 0.10. These results show that explanations can guide attacks, but they are less damaging than unrestricted PGD against the neural model.

## 15. Why did TreeSHAP-guided evasion against the final ensemble reach 0.00%?

The final ensemble includes robust ExtraTrees trained with SHAP-guided adversarial augmentation and combined with the adversarially fine-tuned neural model. Under the tested TreeSHAP-guided attack settings, the perturbed examples did not evade the ensemble. This supports the hardening effect, but it is still an empirical result, not a proof of universal robustness.

## 16. Why was the Torch Binary MLP so vulnerable to full-feature PGD?

Full-feature PGD is a direct white-box attack against a differentiable model. It has access to gradients and can perturb all normalized features, including features that may not be realistically mutable. Because the Torch model is differentiable, PGD can efficiently find directions that reduce the attack score and cause evasion.

## 17. Is full-feature PGD realistic?

Not fully. It is useful as a stress test, but it is too permissive because it can change categorical and binary features in feature space. Real attackers cannot freely modify all one-hot encoded protocol, service, or flag variables independently without changing the actual network semantics.

## 18. Why include mutable-feature PGD?

Mutable-feature PGD is more realistic because it freezes categorical and binary fields and only changes continuous behavior-derived features. It still does not generate real packets, but it is a better approximation of what an attacker could manipulate in tabular network features.

## 19. Why did adversarial fine-tuning give a negative reduction at eps 0.03 for mutable PGD?

At eps 0.03, mutable PGD evasion increased from 11.70% to 14.05%, giving a -2.35 percentage point reduction. This can happen because adversarial training changes the decision boundary and may improve robustness at medium or high budgets while slightly worsening a very low-budget region. This is why we report all eps values instead of hiding unfavorable results.

## 20. What is the strongest adversarial fine-tuning result?

For mutable-feature PGD, the strongest improvements are at eps 0.10 and eps 0.15. Evasion falls from 71.21% to 39.18% at eps 0.10, a 32.03 percentage point reduction, and from 100.00% to 57.97% at eps 0.15, a 42.03 percentage point reduction. This shows that fine-tuning helps more at stronger realistic perturbation budgets.

## 21. What is transfer-PGD?

Transfer-PGD generates adversarial examples against one model, usually a differentiable surrogate, and then tests whether those examples also fool another target model. This is realistic because attackers often do not have exact access to the deployed model. In our project, PGD examples generated against the Torch surrogate transfer poorly to the final Adv+ExtraTrees ensemble.

## 22. What is the strongest defense result?

The strongest defense result is the Adv+ExtraTrees transfer-PGD defense. Surrogate evasion is 37.29%, 63.99%, 91.24%, and 100.00% across eps values. On the final ensemble, evasion becomes 0.50%, 0.00%, 0.00%, and 0.00%. This is the main evidence that the final heterogeneous ensemble breaks transferability under the tested threat model.

## 23. Does 0.00% evasion mean the model cannot be attacked?

No. It means no successful evasions were observed under the specific tested attack configuration. It does not prove certified robustness. A different adaptive attack, black-box search method, or real packet-level evasion strategy could still be tested in future work.

## 24. Why is Security-OR not the final selected model?

Security-OR is stricter and reaches 0.00% transfer-PGD evasion in the corrected presentation results, but its clean F1 is 0.8796, lower than the final Adv+ExtraTrees F1 of 0.9063. Therefore, Security-OR is better as a high-security operating mode, while Adv+ExtraTrees is the best default balance.

## 25. What is SHAP-guided adversarial augmentation?

SHAP-guided adversarial augmentation uses SHAP explanations to identify important attack-related features, then creates perturbed training examples along those influential directions and labels them as attacks. This teaches the tree model not to treat those perturbations as normal behavior. It is one reason the robust ExtraTrees component performs better against explanation-guided evasion.

## 26. Why is feature randomization not a strong defense here?

Feature randomization did not reduce the local RF SHAP attack: evasion stayed at 11.74% with and without the defense. This suggests that simple randomization of selected features is not enough. More structured defenses, such as adversarial augmentation and heterogeneous ensembling, are more effective in this project.

## 27. What are the main limitations?

The main limitations are the age of NSL-KDD, dataset shift between training and test splits, rare R2L and U2R classes, imperfect realism of feature-space adversarial attacks, and lack of certified robustness. The results should be interpreted as strong empirical benchmark results, not as a universal guarantee for all network environments.

## 28. How did you ensure reproducibility?

The pipeline uses fixed seeds, documented preprocessing, a single script `pipeline_cuda.py`, and saved outputs in `outputs_cuda`. The heavy run is controlled by environment variables for multi-eps adversarial training, SHAP-Robust ExtraTrees, and heavy final-model XAI. The report and presentation use the saved `new_results.txt` and generated figures.

## 29. What would you improve if you had more time?

The next improvements would be to test on a more modern IDS dataset, such as CICIDS or UNSW-NB15, add packet- or flow-valid adversarial generation, evaluate adaptive black-box attacks against the full ensemble, and calibrate thresholds for different SOC operating costs. We would also study explanation drift over time if the traffic distribution changes.

## 30. What is the one-sentence conclusion of the project?

The final Adv+ExtraTrees Ensemble IDS is not claimed to be universally robust, but it provides the strongest tested balance of clean IDS performance, rare-family detection, explainability, explanation stability, and empirical adversarial robustness on NSL-KDD.

# Quick Backup Answers

If asked why the results are not perfect, answer that NSL-KDD has rare and shifted families, especially R2L and U2R, and that realistic IDS performance should be measured with family recall and balanced accuracy, not only accuracy.

If asked whether the results are strong enough, answer that the final model improves the most important weaknesses: it reaches 0.9063 binary F1, improves rare-family recall, provides stable explanations, and strongly reduces transfer-PGD evasion under the tested setting.

If asked whether the defense is a trick, answer that the improvement comes from a defensible security design: adversarial fine-tuning, SHAP-guided adversarial augmentation, and heterogeneous ensembling. The report explicitly states the limitations and does not claim certified robustness.

If asked what the examiner should remember, answer that explainability is useful but dangerous. The project shows both sides: explanations support analyst trust, but they also guide attacks, so an explainable IDS must be evaluated under adversarial pressure.
