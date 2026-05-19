# Project 5 Final Deliverables

This folder contains the final submission package for the Explainable IDS project.

## Main Files

- `Project5_CUDA_Report_final_heavy.docx`: final formal report with updated heavy-run results, figures, analysis, improvements, limitations, and deliverables.
- `pipeline_cuda.py`: final CUDA pipeline used to generate the reported results.
- `summary.json`: final numerical output from the pipeline.
- `claude_pptx_prompt.md`: prompt for generating a `.pptx` presentation from the final report.
- `final_heavy_results_for_report.md`: compact report-ready metrics.
- `heavy_run_results_interpretation.md`: interpretation of the heavy run and how to discuss it in the report.
- `images/`: generated figures used in the report.

## Final Selected Model

The selected final detector is `Adv+ExtraTrees Ensemble IDS`.

- Binary F1: `0.9063`
- PR-AUC: `0.9626`
- Balanced accuracy: `0.9064`
- R2L recall: `0.6786`
- U2R recall: `0.8060`

The `Security-OR Ensemble IDS` is included only as an optional high-security operating point.
