# Prompt for Claude: Generate Updated Project 5 Report

You are writing a formal academic project report for a cybersecurity deep learning course. The report must replace and improve the previous `Project5_Report.docx` while keeping a professional tone and detailed paragraph-based analysis. Avoid bullet-heavy writing except for compact tables or short requirement mappings. The report should be suitable for export to Word/PDF and should be no more than 10 pages if formatted normally.

The assignment brief is `doc.pdf`. Project 5 is "Explainable IDS". It requires an IDS on NSL-KDD with model training, explainability, explanation stability evaluation, and security implications. The general course requirements also require a baseline model, at least three experimental variations, appropriate metrics, fixed random seeds, documented preprocessing, code with README, and reproducibility instructions.

Use the following files as source material:

- `new/pipeline_cuda_results.md`: main results, tables, interpretations, and figure references.
- `new/summary.json`: raw pipeline output.
- `pipeline_cuda.py`: code implementation.
- `doc.pdf`: assignment requirements.
- `new/images/*.png`: figures to include in the report.

Important instruction: do not fabricate results, do not claim state-of-the-art performance, and do not imply that `KDDTest+` was used for training. Frame the improvement honestly. The best defensible strategy is to emphasize binary IDS performance as the operational task, while still reporting family-level recall to expose weaknesses on rare attack types. Explain that NSL-KDD `KDDTest+` is distribution-shifted and that rare families such as R2L and U2R remain difficult.

Use this report structure:

1. Title and abstract.
2. Introduction and project objective.
3. Assignment requirements and how the work satisfies them.
4. Dataset and preprocessing.
5. Experimental design, including baseline and variations.
6. Clean IDS results.
7. Explainability analysis.
8. Explanation stability analysis.
9. Security implications and adversarial analysis.
10. Defense evaluation.
11. Limitations.
12. Conclusion.

Use paragraph form for explanations. Tables are allowed for metrics. Include and discuss the following figures:

- `images/rf_shap_top10.png`
- `images/rf_vs_torch_explanations.png`
- `images/torch_binary_smoothig_top10.png`
- `images/ig_stability.png`
- `images/rf_shap_evasion_global.png`
- `images/rf_shap_evasion_local.png`
- `images/ig_evasion_heatmap.png`
- `images/torch_binary_pgd_evasion.png`

Key results to include:

- PyTorch `2.6.0+cu124`, CUDA available, RTX 3060 Laptop GPU, seed `42`, feature count `478`.
- Best clean binary F1: Adv+ExtraTrees Ensemble IDS, `0.8983`.
- Best PR-AUC: Binary RF IDS, `0.9712`.
- Adv+ExtraTrees Ensemble IDS balanced accuracy: `0.8999`.
- Adv+ExtraTrees Ensemble IDS family recall: DoS `0.9693`, Probe `0.9992`, R2L `0.6384`, U2R `0.7910`.
- Torch MLP CUDA binary F1: `0.8470`.
- Logistic Regression binary F1: `0.8344`.
- Random Forest PR-AUC: `0.9695`.
- PGD-adversarial Torch model family recall: DoS `0.9512`, Probe `0.9442`, R2L `0.4160`, U2R `0.6119`.
- RF SHAP stability: local top-10 Jaccard `0.8802 +/- 0.1575`, bootstrap Jaccard `0.5744`, bootstrap rank correlation `0.9950`.
- Torch IG stability: local top-10 Jaccard `0.8811 +/- 0.1788`, bootstrap Jaccard `0.9964`, bootstrap rank correlation `0.9406`.
- Torch Binary SmoothIG stability: local top-10 Jaccard `0.8992 +/- 0.1272`, bootstrap Jaccard `0.9564`, bootstrap rank correlation `0.9940`.
- Best RF SHAP-guided evasion: `18.22%`.
- Best Torch IG-guided evasion: `15.97%`.
- Original Torch Binary MLP full-feature PGD evasion: `100%` at eps `0.03`, `0.06`, `0.10`, and `0.15`.
- SmoothIG-constrained PGD reaches `92.84%` at top-40, eps `0.15`.
- PGD adversarial fine-tuning reduces evasion from `100%` to `34.39%` at eps `0.03`, and to `64.65%` at eps `0.06`.
- High-budget PGD remains a serious unresolved risk.
- Adv+ExtraTrees transfer-PGD defense: surrogate Torch evasion vs ensemble evasion is `39.40%` vs `7.12%` at eps `0.03`, `67.34%` vs `5.21%` at eps `0.06`, `98.38%` vs `4.04%` at eps `0.10`, and `99.97%` vs `2.73%` at eps `0.15`.
- Explain clearly that this is transfer robustness against PGD generated from the differentiable Torch surrogate, not a proof of full white-box robustness against the complete mixed ensemble.

The report should make the central argument clear: the project is not only about improving IDS classification metrics. Its main contribution is the explainability-security tradeoff. Stable explanations are useful to defenders, but they can also reveal reliable attack directions to adversaries. The new Adv+ExtraTrees ensemble is the strongest clean detector because it combines adversarially fine-tuned neural scores with ExtraTrees ranking behavior. The defense experiment should distinguish direct white-box neural PGD, where high-budget attacks remain dangerous, from transfer PGD against the mixed ensemble, where evasion is sharply reduced.

Write in a formal, professional style. Use clear paragraphs and technical explanation. Avoid casual phrasing. Avoid saying "the results are low"; instead, explain that performance must be interpreted under the official NSL-KDD test distribution shift and the rare-family imbalance. Where results are weak, especially R2L and high-budget PGD robustness, acknowledge them directly and explain their implications.
