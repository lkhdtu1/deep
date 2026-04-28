# Threat Model and Security Analysis

## Objective

Project 5 requires more than showing explanations. It explicitly asks for security implications. This document defines the security framing that the final report should use.

## System Under Study

- Task: binary intrusion detection on NSL-KDD (`normal` vs `attack`)
- Features: 122 after one-hot encoding and scaling
- Primary explainable model: Random Forest with TreeSHAP
- Secondary black-box model: MLP with KernelSHAP

## Defender Goal

The defender wants:

- high-quality attack detection
- explanations that help analysts understand alerts
- explanations that are stable enough to be trusted

## Attacker Goal

The attacker wants:

- a malicious connection to be classified as `normal`
- to use available explanation information to identify which features to manipulate

## Attacker Knowledge Level

This project evaluates a white-box explanation-aware attacker:

- knows the trained Random Forest
- has access to SHAP importance information
- can perturb feature values in the scaled feature space

This is stronger than many real deployments, but it is appropriate because the project brief explicitly asks for adversarial-risk assessment.

## Attacker Constraints

- Perturbations are clipped to `[0, 1]` after MinMax scaling.
- The attacker modifies only selected high-importance features.
- The attack is performed in feature space, not packet space.
- The malicious label is assumed to remain semantically malicious after perturbation.

## Security Question

Does explanation access help an attacker evade detection?

In this project, the answer is yes. SHAP highlights the features that most affect the Random Forest's attack decision. The global SHAP attack yields evasion around `34%` to `37%`, while the stronger local instance-specific SHAP attack reaches `38.46%`.

## Interpretation of the Stability Result

The explanation stability results remain strong:

- local top-10 Jaccard `0.909 ± 0.141`
- local rank correlation `0.991`
- bootstrap top-10 Jaccard `0.927`
- bootstrap rank correlation `0.992`

That does not mean the system is safe. It means:

- similar attack samples receive highly consistent explanation patterns
- the explanation method is internally consistent under the chosen metrics

But that same consistency also helps the attacker:

- stable explanations reveal a repeatable manipulation surface
- if the same few features dominate many attack explanations, those features become obvious attack targets

So the core tension is:

- high explanation stability improves analyst trust
- high explanation stability may also improve attacker planning

## Defense Interpretation

The tested feature-randomization defense produced `0.0%` improvement.

This is an important negative result, not an embarrassment. It shows:

- weak obscuration of low-importance features is insufficient
- the attack relies on strong decision drivers
- cosmetic explanation hardening is not the same as robust model defense

## Practical Security Conclusion

The right security conclusion is not “do not use explainability.” It is:

- use explainability for analysts
- avoid exposing raw explanation outputs broadly
- treat explanation interfaces as a sensitive asset
- consider stronger defenses such as adversarial training, restricted explanation access, or noisy/private explanation release

## Limits of This Threat Model

- Feature-space perturbations are easier than real traffic manipulation.
- The study is binary, so attack-family-specific behavior is hidden in the main classifier setup.
- The defense space is minimal and not exhaustive.
- NSL-KDD is old, so direct operational generalization is limited.

These limits should be stated explicitly in the final report.
