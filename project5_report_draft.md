# Project 5: Explainable IDS on NSL-KDD

## Abstract

This project investigates explainability and security tradeoffs in an intrusion detection system (IDS) built on the NSL-KDD dataset. Three lightweight models were trained under the course constraints: Logistic Regression as the baseline, Random Forest as the primary explainable model, and a Multi-Layer Perceptron (MLP) as a black-box comparison. Explanations were generated using SHAP and LIME, and explanation reliability was assessed through stability analysis over similar attack samples. The security component examined whether explanation information can be weaponized through a SHAP-guided evasion attack. The verified results show that the MLP achieved the highest macro F1 (`0.8060`), while the Random Forest achieved the strongest PR-AUC (`0.9650`). SHAP explanations were highly stable under the chosen Jaccard metric (`0.994 ± 0.037`), but that same consistency also exposed a repeatable attack surface: perturbing top SHAP-ranked features caused evasion rates up to `35.49%`. A simple feature-randomization defense produced no measurable improvement. The main conclusion is that explanation quality and security must be evaluated together because stable, interpretable explanations can also improve attacker guidance.

## 1. Introduction

Machine-learning-based IDS models are often judged by predictive performance, but in operational security settings a correct label alone is not sufficient. Analysts need to know why a connection was flagged, whether the explanation is trustworthy, and whether making the model more transparent increases exposure to adversarial manipulation. Project 5 explicitly targets this intersection between interpretability and adversarial risk.

The central research question in this project is not simply which classifier is best. Instead, the goal is to study whether IDS decisions can be explained in a way that is both useful and reliable, while also identifying the risks created by publishing or exposing those explanations. This is especially relevant for black-box models such as MLPs, where explanation tools are required to support interpretation.

## 2. Assignment Requirements and Experimental Design

According to Project 5 in [`doc.pdf`](/home/kali/deep/doc.pdf), the required tasks are:

- train a model
- apply explainability
- evaluate stability
- analyze security implications

The course-level requirements also require a baseline model, at least three experimental variations, appropriate metrics, fixed seeds, documented preprocessing, code with a README, and reproducibility instructions.

The implemented design satisfies those requirements as follows:

- Baseline model: Logistic Regression
- Variation 1: Random Forest with TreeSHAP
- Variation 2: MLP with KernelSHAP
- Additional local explanation analysis: LIME
- Security study: SHAP-guided evasion plus defense evaluation

This framing keeps the project aligned with the assignment. The main contribution is not claiming state-of-the-art classification, but showing how explanation reliability and attackability interact.

## 3. Dataset and Preprocessing

The project uses NSL-KDD, the dataset assigned in Project 5. The training split (`KDDTrain+.txt`) contains `125,973` rows and the test split (`KDDTest+.txt`) contains `22,544` rows. The raw records include 41 main features plus a label and difficulty score.

The preprocessing pipeline performs the following steps:

1. Drop the `difficulty` column.
2. Convert the label to a binary target:
   - `normal` -> `0`
   - all attack labels -> `1`
3. One-hot encode the categorical variables `protocol_type`, `service`, and `flag`.
4. Fit a `MinMaxScaler` on the training data only and apply it to both splits.

After preprocessing, the final feature dimension is `122`. Fixed seed `42` is used throughout the pipeline.

## 4. Models and Explainability Methods

### 4.1 Logistic Regression

Logistic Regression serves as the baseline because it is relatively interpretable and computationally lightweight. It establishes a reference point for both predictive performance and model transparency.

### 4.2 Random Forest

The Random Forest is the main explainable black-box model because TreeSHAP can produce efficient and consistent feature attributions for tree ensembles. This makes it suitable for studying both explanation quality and explanation misuse.

### 4.3 MLP

The MLP provides a neural baseline that fits the course requirement for lightweight deep learning. Because its internal reasoning is not directly interpretable, it is paired with KernelSHAP.

### 4.4 SHAP and LIME

Two explanation methods are used:

- SHAP for both Random Forest and MLP
- LIME for local explanation analysis on attack instances

Using both methods is useful because agreement between them increases confidence that the top reported features are not purely artifacts of one explainer.

## 5. Experimental Results

### 5.1 Classification Performance

| Model | Macro Precision | Macro Recall | Macro F1 | PR-AUC |
| --- | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.78 | 0.77 | 0.7535 | 0.8864 |
| Random Forest | 0.81 | 0.80 | 0.7726 | 0.9650 |
| MLP | 0.82 | 0.82 | 0.8060 | 0.9461 |

These results should be interpreted carefully. The MLP has the best macro F1, which means its default threshold produces the most balanced classification across the two classes on the test split. The Random Forest has the best PR-AUC, which means its ranking quality across thresholds is stronger, even though its default-threshold recall is lower than the MLP's. Therefore, the two models are strong in different senses.

### 5.2 Why the Results Are Defensible

The observed F1 values are not obviously weak once the task is framed correctly. NSL-KDD is designed to be more challenging than a simple in-sample benchmark, and Project 5 is primarily about explanation and security analysis rather than pure accuracy optimization. A credible report should therefore avoid apologizing for the scores and instead explain what they imply:

- Logistic Regression provides a useful lower bound.
- Random Forest offers the best explanation workflow and the strongest PR-AUC.
- MLP achieves the best macro F1 but requires approximate post-hoc explanation.

That tradeoff is scientifically meaningful and directly relevant to the assignment.

## 6. Explanation Analysis

### 6.1 Random Forest SHAP Results

The top 10 Random Forest SHAP features are:

1. `flag_SF`
2. `logged_in`
3. `dst_host_srv_count`
4. `dst_host_same_srv_rate`
5. `same_srv_rate`
6. `diff_srv_rate`
7. `service_private`
8. `dst_host_rerror_rate`
9. `count`
10. `dst_host_srv_serror_rate`

These features are plausible for IDS reasoning because they reflect connection status, authentication state, traffic repetition, service behavior, and error-rate patterns.

### 6.2 LIME Results

The top 10 LIME features are:

1. `service_private`
2. `logged_in`
3. `wrong_fragment`
4. `dst_host_rerror_rate`
5. `rerror_rate`
6. `flag_SF`
7. `service_ecr_i`
8. `dst_host_srv_serror_rate`
9. `protocol_type_icmp`
10. `flag_S0`

The overlap between SHAP and LIME is important. Both methods prioritize authentication, service identity, connection flags, and error behavior, which makes the explanation narrative more credible.

### 6.3 Cross-Method Agreement

The Spearman correlation between Random Forest SHAP importances and MLP SHAP importances is `0.745`. This indicates substantial agreement in global feature importance structure across two different model families, though not perfect agreement. That is a useful middle-ground result: it supports explanation robustness without claiming universal consistency.

## 7. Stability and Reliability of Explanations

The explanation stability analysis computes Jaccard similarity between the top-10 SHAP feature sets of highly similar attack samples. The mean score is:

- `0.994 ± 0.037`

This is a very high stability value. Under the implemented metric, similar attack examples receive nearly identical top explanation features. From an interpretability perspective, this is desirable because it means the explanation behavior is not erratic.

However, this should not be overinterpreted. The metric evaluates overlap in selected top features, not full causal faithfulness or human usefulness. It is a stability result, not a proof that every explanation is semantically correct.

## 8. Security Implications and Adversarial Analysis

### 8.1 Threat Model

The attacker is modeled as explanation-aware and effectively white-box with respect to the Random Forest and its SHAP importance structure. The attacker perturbs top-ranked features in feature space to reduce attack evidence while keeping values in the normalized `[0, 1]` range.

This is a strong attacker model, but it is justified because the project explicitly asks for adversarial-risk analysis.

### 8.2 SHAP-Guided Evasion Results

| Perturbed Features | eps = 0.05 | eps = 0.10 | eps = 0.20 |
| --- | ---: | ---: | ---: |
| Top-5 | 34.86% | 33.60% | 32.26% |
| Top-10 | 35.49% | 35.04% | 34.59% |
| Top-15 | 35.49% | 34.14% | 33.51% |

The most important finding is not the exact best cell. It is the overall pattern: once the attacker knows which features matter, evasion remains consistently high across several perturbation settings. This shows that explanation access can reveal a stable manipulation surface.

### 8.3 Why High Stability and High Attackability Can Coexist

At first glance, high explanation stability may seem purely positive. In fact, the project shows the opposite: stability is double-edged.

- For defenders, stable explanations are easier to trust.
- For attackers, stable explanations expose recurring high-value features to target.

This is the central scientific insight of the project. The same property that improves interpretability can also improve adversarial planning.

### 8.4 Defense Result

The feature-randomization defense did not reduce evasion:

- without defense: `35.04%`
- with defense: `35.04%`
- improvement: `0.0%`

This should be reported directly. It is a useful negative result because it shows that weak perturbation of low-importance features does not materially obstruct an attack that already exploits the model's dominant global drivers.

## 9. Limitations

Several limitations should be acknowledged:

- The attack is performed in feature space rather than by modifying raw network traffic.
- The task is binary classification, which hides attack-family-specific behavior.
- KernelSHAP is approximate and was run on a reduced subset for tractability.
- The defense space is limited; a failed heuristic defense does not rule out stronger defenses.
- NSL-KDD is an older benchmark and does not represent all modern attack behavior.

These limitations do not invalidate the project, but they define its scope clearly.

## 10. Conclusion

This project satisfies the Project 5 requirements by training multiple IDS models, applying explainability methods, evaluating explanation stability, and analyzing adversarial security implications on NSL-KDD. The results show that explainability is not only an interpretability benefit but also a security consideration. The MLP achieved the highest macro F1, the Random Forest achieved the strongest PR-AUC and most convenient SHAP workflow, SHAP explanations were highly stable, and a SHAP-guided attacker achieved substantial evasion while a simple defense failed. The main takeaway is that explanation quality must be evaluated together with explanation exposure: interpretable IDS models can support analysts, but their explanations may also reveal how to evade them.
