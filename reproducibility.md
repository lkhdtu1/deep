# Reproducibility Guide

## Environment

This project was executed from:

- working directory: `/home/kali/deep`
- Python interpreter: `./venv/bin/python`
- date of verified run: `2026-04-27`

## Dependencies

Install requirements with:

```bash
./venv/bin/pip install -r requirements.txt
```

Main dependency versions observed in the local `venv`:

- `numpy 2.4.4`
- `pandas 2.3.3`
- `scikit-learn 1.8.0`
- `shap 0.51.0`
- `matplotlib 3.10.8`
- `scipy 1.17.1`
- `lime 0.2.0.1`

## Required Input Files

The pipeline expects:

- [`KDDTrain+.txt`](/home/kali/deep/KDDTrain+.txt)
- [`KDDTest+.txt`](/home/kali/deep/KDDTest+.txt)

If they are missing, [`pipeline.py`](/home/kali/deep/pipeline.py) tries to download them automatically.

## Run Command

```bash
./venv/bin/python pipeline.py
```

## Fixed Randomness

The code sets `SEED = 42` and uses it in:

- NumPy
- Logistic Regression
- Random Forest
- MLP
- SHAP sampling
- LIME explainer
- defense noise generation

## Preprocessing Pipeline

1. Load NSL-KDD train and test files.
2. Drop the `difficulty` column.
3. Convert labels to binary:
   - `normal` -> `0`
   - everything else -> `1`
4. One-hot encode:
   - `protocol_type`
   - `service`
   - `flag`
5. Fit `MinMaxScaler` on training features only.
6. Transform both train and test splits.

## Expected Data Shapes

- training rows: `125973`
- test rows: `22544`
- final feature count: `122`

## Expected Core Metrics

The following values were observed on the improved verified run and should be close if the environment is reproduced correctly:

- Logistic Regression:
  - macro F1 `0.7601`
  - PR-AUC `0.8806`
  - balanced accuracy `0.7798`
- Random Forest:
  - macro F1 `0.8007`
  - PR-AUC `0.9677`
  - balanced accuracy `0.8156`
- MLP:
  - macro F1 `0.8047`
  - PR-AUC `0.9246`
  - balanced accuracy `0.8194`
- SHAP stability:
  - local Jaccard `0.909 ± 0.141`
  - bootstrap Jaccard `0.927`
- best evasion rate:
  - `38.46%`

## Expected Output Files

Successful execution should produce:

- [`outputs/shap_beeswarm_rf.png`](/home/kali/deep/outputs/shap_beeswarm_rf.png)
- [`outputs/shap_comparison.png`](/home/kali/deep/outputs/shap_comparison.png)
- [`outputs/shap_stability.png`](/home/kali/deep/outputs/shap_stability.png)
- [`outputs/evasion_heatmap.png`](/home/kali/deep/outputs/evasion_heatmap.png)
- [`outputs/evasion_heatmap_local.png`](/home/kali/deep/outputs/evasion_heatmap_local.png)

## Notes

- The pipeline is CPU-friendly and matches the course requirement for lightweight models.
- The MLP uses a stratified subset during tuning and final fitting to keep runtime practical under course compute limits.
- KernelSHAP is computed on a reduced subset for runtime reasons.
- Small numerical variation is possible if package versions differ.
