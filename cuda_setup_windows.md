# Windows 11 CUDA Setup for Project 5

This machine already exposes the RTX 3060 to Windows:

- GPU: NVIDIA GeForce RTX 3060 Laptop GPU, 6 GB VRAM
- Driver: 580.88
- `nvidia-smi` reported CUDA runtime capability: 13.0
- Python: 3.11.4

## Recommended Setup

Use PyTorch's bundled CUDA runtime. You do not need to install the full CUDA Toolkit just to run this project.

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements-cuda.txt
.\venv\Scripts\python.exe -m pip install --no-cache-dir torch==2.6.0+cu124 --index-url https://download.pytorch.org/whl/cu124
```

This exact install was verified in this venv:

- `torch 2.6.0+cu124`
- `torch.version.cuda == 12.4`
- `torch.cuda.is_available() == True`
- device: `NVIDIA GeForce RTX 3060 Laptop GPU`

Your NVIDIA driver reports CUDA runtime capability 13.0, which is new enough to run CUDA 12.4 wheels. If this pinned wheel becomes unavailable for your Python version, use the selector at:

https://pytorch.org/get-started/locally/

## Verify CUDA

```powershell
nvidia-smi
.\venv\Scripts\python.exe -c "import torch; print(torch.__version__); print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU')"
```

Expected result:

- `torch.cuda.is_available()` prints `True`
- device name prints your RTX 3060

For live monitoring while a CUDA job is running:

```powershell
for ($i=0; $i -lt 60; $i++) { nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader; Start-Sleep -Seconds 1 }
```

Task Manager can be misleading if it is showing the default `3D` graph. In the GPU panel, change one of the graph dropdowns to `CUDA` or `Compute_0`. The Project 5 pipeline also has CPU-heavy sections: Logistic Regression, Random Forest, and TreeSHAP run on the CPU. The GPU is used during the PyTorch MLP training and integrated-gradient explanation steps.

## Run the CUDA Pipeline

```powershell
.\venv\Scripts\python.exe pipeline_cuda.py
```

Outputs go to `outputs_cuda/`:

- `summary.json`
- `rf_shap_top10.png`
- `rf_vs_torch_explanations.png`
- `ig_stability.png`
- `ig_evasion_heatmap.png`

## Why This Pipeline Should Be Faster

The old pipeline trained an sklearn MLP on CPU and used KernelSHAP for neural explanations, which is expensive. The CUDA pipeline trains the neural variation in PyTorch on the GPU and uses integrated gradients for neural explanations. Random Forest and Logistic Regression remain CPU models because they are still useful assignment variations and TreeSHAP is efficient for the RF.

## Full CUDA Toolkit

Install the NVIDIA CUDA Toolkit only if you need to compile CUDA extensions or run `nvcc`. For this project, the PyTorch CUDA wheel is enough.
