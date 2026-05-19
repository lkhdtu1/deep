# Heavy Improvement Revision Note

Use this note after rerunning `pipeline_cuda.py`. The new version adds heavier adversarial robustness logic, so the report must describe these changes instead of presenting the new numbers as a simple rerun.

## What Was Added

The adversarially trained Torch binary IDS now uses multi-epsilon PGD fine-tuning when `ENABLE_MULTI_EPS_ADV_TRAIN=1`, which is enabled by default. Instead of training only against one perturbation size, the model cycles through `eps=0.03`, `eps=0.06`, and `eps=0.10`. Model selection is also more robust because each epoch is evaluated with a validation PGD subset, and the selected checkpoint balances clean validation F1 with validation evasion reduction.

The pipeline now includes a `Security-OR Ensemble IDS`. This detector combines the adversarially fine-tuned Torch IDS with the ExtraTrees detector using an OR-style calibrated margin. Each component score is divided by that component's own tuned detection threshold, then the detector takes the maximum margin. This is important because the adversarial Torch model and the robust tree model do not use the same probability scale. The mode is designed as a high-security operating point: the objective is to reduce transfer-PGD evasion, even if this sacrifices a small amount of clean F1 compared with the balanced `Adv+ExtraTrees Ensemble IDS`.

The adversarial evaluation now separates full-feature PGD from realistic mutable-feature PGD. Full-feature PGD is still useful as a worst-case stress test, but it can be unrealistic for NSL-KDD because it perturbs one-hot protocol, service, and flag indicators as well as binary login/status features. Mutable-feature PGD freezes those categorical and binary indicators and only perturbs continuous traffic-derived features. This gives the report a more defensible adversarial interpretation.

## New Output Lines To Look For

After the run, copy the updated block printed under `COPY THIS BLOCK FOR REPORT UPDATE`. In particular, look for:

- `Multi-Eps PGD-Adversarial Torch Binary MLP`
- `Security-OR Ensemble IDS`
- `Mutable-feature PGD adversarial fine-tuning defense reductions`
- `Security-OR transfer-PGD defense reductions`

The important comparison is no longer only whether direct PGD against the Torch model remains high at `eps=0.10` or `eps=0.15`. The stronger claim is whether the ensemble transfer attack drops from the adversarial Torch surrogate to the `Adv+ExtraTrees` and `Security-OR` ensemble scores.

## Suggested Report Wording

The report should state that a second robustness-oriented operating point was introduced. The balanced `Adv+ExtraTrees Ensemble IDS` remains the main detector when clean detection performance and robustness must be traded off. The `Security-OR Ensemble IDS` is a stricter deployment configuration where an event is treated as malicious if either the adversarial neural detector or the tree detector assigns a high attack probability. This design is appropriate for intrusion detection because false negatives are often more costly than additional alerts.

The report should also clarify that very high full-feature PGD evasion is not necessarily a dataset failure alone. It is partly caused by the white-box threat model, where the attacker is allowed to modify all normalized features directly. In tabular network intrusion data, this can include fields that are not freely mutable in a real packet or connection record. For this reason, the mutable-feature PGD experiment is included as a more realistic secondary adversarial test.

## Heavy Run Command

```powershell
$env:ENABLE_MULTI_EPS_ADV_TRAIN="1"
$env:ENABLE_SHAP_ROBUST_ET="1"
$env:ENABLE_HEAVY_ADV_TREE_XAI="1"
.\venv\Scripts\python.exe pipeline_cuda.py
```

If the SHAP-robust ExtraTrees stage is too slow, keep the multi-epsilon and Security-OR improvements but disable the heaviest SHAP steps:

```powershell
$env:ENABLE_MULTI_EPS_ADV_TRAIN="1"
$env:ENABLE_SHAP_ROBUST_ET="0"
$env:ENABLE_HEAVY_ADV_TREE_XAI="0"
.\venv\Scripts\python.exe pipeline_cuda.py
```
