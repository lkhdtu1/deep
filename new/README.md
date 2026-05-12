# New Project 5 Report Package

This directory contains the updated CUDA/XAI report material.

## Files

- `pipeline_cuda_results.md`: clean results, stability metrics, adversarial results, defense results, and figure references from `pipeline_cuda.py`.
- `updated_report.md`: formal updated report draft in paragraph form.
- `Project5_Report_Updated.docx`: Word-compatible version of the updated report.
- `claude_report_prompt.md`: prompt for Claude to generate or polish a final Word/PDF report.
- `summary.json`: raw `outputs_cuda/summary.json` copied from the verified CUDA run.
- `Project5_Report_previous_copy.docx`: copy of the previous report for comparison.
- `images/`: copied CUDA figures used by the Markdown and report.

## Main Reporting Position

The report should present binary IDS performance as the primary operational result and family-level recall as the error analysis. This improves the report framing without falsifying results. The best clean binary detector is now the Adv+ExtraTrees Ensemble IDS with binary F1 `0.8983`; the strongest ranking and explainability model is the binary Random Forest with PR-AUC `0.9712`.

The central technical conclusion is that stable explanations are useful for analysts but can also guide evasion attacks. PGD adversarial fine-tuning improves low-budget robustness but high-budget direct neural PGD remains unresolved. The new Adv+ExtraTrees ensemble adds a stronger transfer-PGD defense result, reducing surrogate PGD evasion to `7.12%`, `5.21%`, `4.04%`, and `2.73%` across the tested budgets.
