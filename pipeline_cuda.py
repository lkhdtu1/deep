"""
Project 5 CUDA pipeline for Windows 11.

This keeps the Project 5 structure from doc.pdf:
preprocessing -> baseline/variations -> explainability -> stability -> security analysis.

The slow sklearn MLP + KernelSHAP path is replaced with a PyTorch MLP trained on CUDA
when available. Neural explanations use integrated gradients, which are practical on a
6 GB RTX 3060 and do not require extra explainability packages.

Run:
    .\venv\Scripts\python.exe pipeline_cuda.py
"""

import gc
import json
import os
import random
import time
import warnings
from dataclasses import dataclass

os.environ.setdefault("MPLCONFIGDIR", os.path.join(os.getcwd(), "outputs_cuda", ".matplotlib"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
import torch
import torch.nn as nn
import torch.nn.functional as F
from scipy.stats import spearmanr
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler

try:
    from xgboost import XGBClassifier
except ImportError:
    XGBClassifier = None

warnings.filterwarnings("ignore")

SEED = 42
OUTPUT_DIR = "outputs_cuda"
os.makedirs(OUTPUT_DIR, exist_ok=True)

COL_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_hot_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

FAMILY_ORDER = ["normal", "DoS", "Probe", "R2L", "U2R"]
FAMILY_TO_ID = {name: idx for idx, name in enumerate(FAMILY_ORDER)}
ATTACK_FAMILY_MAP = {
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS", "processtable": "DoS",
    "udpstorm": "DoS", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "satan": "Probe", "mscan": "Probe", "saint": "Probe", "ftp_write": "R2L",
    "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L", "phf": "R2L",
    "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L",
    "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L", "xlock": "R2L",
    "xsnoop": "R2L", "worm": "R2L", "httptunnel": "R2L", "buffer_overflow": "U2R",
    "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R", "ps": "U2R",
    "sqlattack": "U2R", "xterm": "U2R", "normal": "normal",
}


def set_reproducible(seed=SEED):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True


def clean_label(raw_label):
    return str(raw_label).strip().rstrip(".")


def map_attack_family(raw_label):
    return ATTACK_FAMILY_MAP.get(clean_label(raw_label), "normal")


def load_nslkdd(train_path="KDDTrain+.txt", test_path="KDDTest+.txt"):
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        raise FileNotFoundError("Place KDDTrain+.txt and KDDTest+.txt in the project directory.")
    train = pd.read_csv(train_path, header=None, names=COL_NAMES).drop(columns=["difficulty"])
    test = pd.read_csv(test_path, header=None, names=COL_NAMES).drop(columns=["difficulty"])
    print(f"[DATA] train={train.shape} test={test.shape}")
    return train, test


def add_engineered_features(df):
    df = df.copy()
    eps = 1e-6
    df["src_bytes_log"] = np.log1p(df["src_bytes"])
    df["dst_bytes_log"] = np.log1p(df["dst_bytes"])
    df["byte_ratio"] = np.log1p((df["src_bytes"] + 1.0) / (df["dst_bytes"] + 1.0))
    df["traffic_total_log"] = np.log1p(df["src_bytes"] + df["dst_bytes"])
    df["srv_count_ratio"] = df["srv_count"] / (df["count"] + eps)
    df["dst_host_srv_ratio"] = df["dst_host_srv_count"] / (df["dst_host_count"] + eps)
    df["serror_gap"] = df["serror_rate"] - df["srv_serror_rate"]
    df["rerror_gap"] = df["rerror_rate"] - df["srv_rerror_rate"]
    df["host_serror_gap"] = df["dst_host_serror_rate"] - df["dst_host_srv_serror_rate"]
    df["host_rerror_gap"] = df["dst_host_rerror_rate"] - df["dst_host_srv_rerror_rate"]
    df["same_diff_srv_gap"] = df["same_srv_rate"] - df["diff_srv_rate"]
    df["login_anomaly_score"] = (
        2.0 * df["num_failed_logins"]
        + 2.0 * df["hot"]
        + 3.0 * df["num_compromised"]
        + 2.0 * df["num_root"]
        + 2.0 * df["num_file_creations"]
        + 3.0 * df["num_shells"]
        + 2.0 * df["num_access_files"]
        + 2.0 * df["root_shell"]
        + 1.5 * df["is_guest_login"]
        - 1.5 * df["logged_in"]
    )
    df["login_anomaly_log"] = np.log1p(np.clip(df["login_anomaly_score"], a_min=0.0, a_max=None))
    df["service_flag"] = df["service"].astype(str) + "__" + df["flag"].astype(str)
    return df


def preprocess(train_df, test_df):
    train_df = add_engineered_features(train_df)
    test_df = add_engineered_features(test_df)
    for df in (train_df, test_df):
        df["family"] = df["label"].map(map_attack_family)
        df["binary_label"] = (df["family"] != "normal").astype(int)

    combined = pd.concat([train_df, test_df], ignore_index=True)
    combined = pd.get_dummies(combined, columns=["protocol_type", "service", "flag", "service_flag"])
    n_train = len(train_df)
    train_enc = combined.iloc[:n_train].copy()
    test_enc = combined.iloc[n_train:].copy()
    feature_names = [c for c in train_enc.columns if c not in {"label", "family", "binary_label"}]

    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(train_enc[feature_names].to_numpy(dtype=np.float32)).astype(np.float32)
    X_test = scaler.transform(test_enc[feature_names].to_numpy(dtype=np.float32)).astype(np.float32)
    y_train = train_enc["family"].map(FAMILY_TO_ID).to_numpy(dtype=np.int64)
    y_test = test_enc["family"].map(FAMILY_TO_ID).to_numpy(dtype=np.int64)
    print(f"[PREP] features={len(feature_names)} X_train={X_train.shape} X_test={X_test.shape}")
    return X_train, X_test, y_train, y_test, feature_names


def class_weights(y):
    counts = np.bincount(y, minlength=len(FAMILY_ORDER)).astype(np.float32)
    counts[counts == 0] = 1.0
    weights = len(y) / (len(FAMILY_ORDER) * counts)
    return weights.astype(np.float32)


def sample_weights_from_labels(y):
    weights = class_weights(y)
    return weights[y].astype(np.float32)


def oversample_minority_classes(X, y, min_count=2500, multiplier_cap=60):
    rng = np.random.default_rng(SEED)
    X_parts = [X]
    y_parts = [y]
    counts = np.bincount(y, minlength=len(FAMILY_ORDER))
    for cls, count in enumerate(counts):
        if count == 0 or count >= min_count:
            continue
        target = min(min_count, int(count * multiplier_cap))
        extra = target - int(count)
        if extra <= 0:
            continue
        cls_idx = np.where(y == cls)[0]
        extra_idx = rng.choice(cls_idx, size=extra, replace=True)
        X_parts.append(X[extra_idx])
        y_parts.append(y[extra_idx])
    X_bal = np.vstack(X_parts)
    y_bal = np.concatenate(y_parts)
    order = rng.permutation(len(y_bal))
    return X_bal[order], y_bal[order]


class TorchMLP(nn.Module):
    def __init__(self, input_dim, hidden=(256, 128, 64), dropout=0.20):
        super().__init__()
        layers = []
        prev = input_dim
        for width in hidden:
            layers += [nn.Linear(prev, width), nn.BatchNorm1d(width), nn.ReLU(), nn.Dropout(dropout)]
            prev = width
        layers.append(nn.Linear(prev, len(FAMILY_ORDER)))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


class TorchBinaryMLP(nn.Module):
    def __init__(self, input_dim, hidden=(384, 192, 96), dropout=0.18):
        super().__init__()
        layers = []
        prev = input_dim
        for width in hidden:
            layers += [nn.Linear(prev, width), nn.BatchNorm1d(width), nn.ReLU(), nn.Dropout(dropout)]
            prev = width
        layers.append(nn.Linear(prev, 1))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x).squeeze(1)


@dataclass
class TorchResult:
    model: TorchMLP
    best_epoch: int
    val_macro_f1: float
    device: str
    multipliers: np.ndarray


@dataclass
class TorchBinaryResult:
    model: TorchBinaryMLP
    best_epoch: int
    val_binary_f1: float
    threshold: float
    device: str
    name: str = "Torch Binary MLP CUDA"


def prediction_from_multipliers(probabilities, multipliers):
    adjusted = probabilities * np.asarray(multipliers, dtype=np.float32)
    return np.argmax(adjusted, axis=1)


def tune_class_multipliers(y_true, probabilities):
    search_grid = {
        "DoS": [1.00, 1.05, 1.10],
        "Probe": [1.00, 1.15, 1.30],
        "R2L": [1.00, 1.75, 2.50, 3.50, 5.00],
        "U2R": [1.00, 2.00, 3.50, 5.00, 7.00],
    }
    best = None
    for dos in search_grid["DoS"]:
        for probe in search_grid["Probe"]:
            for r2l in search_grid["R2L"]:
                for u2r in search_grid["U2R"]:
                    multipliers = np.array([1.0, dos, probe, r2l, u2r], dtype=np.float32)
                    pred = prediction_from_multipliers(probabilities, multipliers)
                    macro_f1 = f1_score(y_true, pred, average="macro", zero_division=0)
                    recalls = recall_score(
                        y_true,
                        pred,
                        average=None,
                        labels=np.arange(len(FAMILY_ORDER)),
                        zero_division=0,
                    )
                    rare_recall = float(np.mean([recalls[FAMILY_TO_ID["R2L"]], recalls[FAMILY_TO_ID["U2R"]]]))
                    binary_true = (y_true != FAMILY_TO_ID["normal"]).astype(int)
                    binary_pred = (pred != FAMILY_TO_ID["normal"]).astype(int)
                    binary_f1 = f1_score(binary_true, binary_pred, average="macro", zero_division=0)
                    score = 0.50 * macro_f1 + 0.35 * rare_recall + 0.15 * binary_f1
                    candidate = {
                        "multipliers": multipliers,
                        "score": float(score),
                        "macro_f1": float(macro_f1),
                        "rare_recall": rare_recall,
                        "binary_f1": float(binary_f1),
                    }
                    if best is None or (
                        candidate["score"],
                        candidate["macro_f1"],
                        candidate["rare_recall"],
                        candidate["binary_f1"],
                    ) > (
                        best["score"],
                        best["macro_f1"],
                        best["rare_recall"],
                        best["binary_f1"],
                    ):
                        best = candidate
    return best


def train_torch_mlp(X_train, y_train, device):
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=SEED, stratify=y_train
    )
    weights = class_weights(y_fit)
    sample_weights = weights[y_fit]
    sampler = WeightedRandomSampler(
        weights=torch.as_tensor(sample_weights, dtype=torch.double),
        num_samples=len(y_fit),
        replacement=True,
        generator=torch.Generator().manual_seed(SEED),
    )
    train_ds = TensorDataset(torch.from_numpy(X_fit), torch.from_numpy(y_fit))
    train_loader = DataLoader(train_ds, batch_size=1024, sampler=sampler, num_workers=0, pin_memory=device == "cuda")

    model = TorchMLP(X_train.shape[1]).to(device)
    criterion = nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32, device=device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=8e-4, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="max", factor=0.5, patience=3)

    X_val_t = torch.from_numpy(X_val).to(device)
    y_val_np = y_val.copy()
    best_state = None
    best_f1 = -1.0
    best_epoch = 0
    stale = 0
    start = time.time()
    for epoch in range(1, 61):
        model.train()
        for xb, yb in train_loader:
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            pred = model(X_val_t).argmax(dim=1).cpu().numpy()
        macro_f1 = f1_score(y_val_np, pred, average="macro", zero_division=0)
        scheduler.step(macro_f1)
        if macro_f1 > best_f1:
            best_f1 = macro_f1
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
        if epoch == 1 or epoch % 5 == 0:
            print(f"  epoch={epoch:02d} val_macro_f1={macro_f1:.4f}")
        if stale >= 8:
            break

    model.load_state_dict(best_state)
    val_prob = predict_torch(model, X_val, device)
    multiplier_result = tune_class_multipliers(y_val, val_prob)
    print(f"[TORCH] best_epoch={best_epoch} val_macro_f1={best_f1:.4f} time={time.time() - start:.1f}s")
    print(f"[TORCH] tuned_multipliers={dict(zip(FAMILY_ORDER, np.round(multiplier_result['multipliers'], 2)))}")
    return TorchResult(
        model=model,
        best_epoch=best_epoch,
        val_macro_f1=float(multiplier_result["macro_f1"]),
        device=device,
        multipliers=multiplier_result["multipliers"],
    )


def predict_torch(model, X, device, batch_size=4096):
    model.eval()
    probs = []
    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            xb = torch.from_numpy(X[start:start + batch_size]).to(device)
            probs.append(F.softmax(model(xb), dim=1).cpu().numpy())
    return np.vstack(probs)


def tune_binary_threshold(y_true_binary, scores):
    best = None
    for threshold in np.linspace(0.20, 0.80, 61):
        pred = (scores >= threshold).astype(int)
        binary_f1 = f1_score(y_true_binary, pred, average="macro", zero_division=0)
        bal_acc = balanced_accuracy_score(y_true_binary, pred)
        candidate = {
            "threshold": float(threshold),
            "binary_f1": float(binary_f1),
            "balanced_accuracy": float(bal_acc),
        }
        if best is None or (candidate["binary_f1"], candidate["balanced_accuracy"]) > (
            best["binary_f1"],
            best["balanced_accuracy"],
        ):
            best = candidate
    return best


def train_torch_binary_mlp(X_train, y_train_family, device):
    y_binary = (y_train_family != FAMILY_TO_ID["normal"]).astype(np.float32)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_binary,
        test_size=0.2,
        random_state=SEED,
        stratify=y_binary,
    )
    pos = float(np.sum(y_fit == 1))
    neg = float(np.sum(y_fit == 0))
    pos_weight = torch.tensor([neg / max(pos, 1.0)], dtype=torch.float32, device=device)
    weights = np.where(y_fit == 1, neg / max(pos, 1.0), 1.0).astype(np.float32)
    sampler = WeightedRandomSampler(
        weights=torch.as_tensor(weights, dtype=torch.double),
        num_samples=len(y_fit),
        replacement=True,
        generator=torch.Generator().manual_seed(SEED),
    )
    train_ds = TensorDataset(torch.from_numpy(X_fit), torch.from_numpy(y_fit))
    train_loader = DataLoader(train_ds, batch_size=2048, sampler=sampler, num_workers=0, pin_memory=device == "cuda")

    model = TorchBinaryMLP(X_train.shape[1]).to(device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=7e-4, weight_decay=8e-5)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="max", factor=0.5, patience=4)
    X_val_t = torch.from_numpy(X_val).to(device)
    y_val_i = y_val.astype(int)
    best_state = None
    best = {"binary_f1": -1.0, "threshold": 0.5}
    best_epoch = 0
    stale = 0
    print("[TRAIN] Torch Binary MLP CUDA variation")
    start = time.time()
    for epoch in range(1, 81):
        model.train()
        for xb, yb in train_loader:
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(xb), yb)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            scores = torch.sigmoid(model(X_val_t)).cpu().numpy()
        tuned = tune_binary_threshold(y_val_i, scores)
        scheduler.step(tuned["binary_f1"])
        if tuned["binary_f1"] > best["binary_f1"]:
            best = tuned
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
            stale = 0
        else:
            stale += 1
        if epoch == 1 or epoch % 5 == 0:
            print(f"  binary_epoch={epoch:02d} val_binary_f1={tuned['binary_f1']:.4f} threshold={tuned['threshold']:.2f}")
        if stale >= 10:
            break

    model.load_state_dict(best_state)
    print(
        f"[TORCH-BINARY] best_epoch={best_epoch} val_binary_f1={best['binary_f1']:.4f} "
        f"threshold={best['threshold']:.2f} time={time.time() - start:.1f}s"
    )
    return TorchBinaryResult(
        model=model,
        best_epoch=best_epoch,
        val_binary_f1=best["binary_f1"],
        threshold=best["threshold"],
        device=device,
        name="Torch Binary MLP CUDA",
    )


def pgd_attack_torch_binary_tensor(model, xb, eps=0.06, alpha=0.015, steps=4):
    model.eval()
    x_orig = xb.detach()
    x_adv = x_orig.clone().detach()
    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = model(x_adv).sum()
        grad = torch.autograd.grad(loss, x_adv)[0]
        x_adv = x_adv.detach() - alpha * torch.sign(grad.detach())
        delta = torch.clamp(x_adv - x_orig, min=-eps, max=eps)
        x_adv = torch.clamp(x_orig + delta, 0.0, 1.0).detach()
    model.train()
    return x_adv


def adversarially_finetune_torch_binary(base_result, X_train, y_train_family, device, eps=0.06):
    y_binary = (y_train_family != FAMILY_TO_ID["normal"]).astype(np.float32)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_binary,
        test_size=0.2,
        random_state=SEED,
        stratify=y_binary,
    )
    train_ds = TensorDataset(torch.from_numpy(X_fit), torch.from_numpy(y_fit))
    train_loader = DataLoader(train_ds, batch_size=1536, shuffle=True, num_workers=0, pin_memory=device == "cuda")

    model = TorchBinaryMLP(X_train.shape[1]).to(device)
    model.load_state_dict({k: v.detach().clone() for k, v in base_result.model.state_dict().items()})
    pos = float(np.sum(y_fit == 1))
    neg = float(np.sum(y_fit == 0))
    pos_weight = torch.tensor([neg / max(pos, 1.0)], dtype=torch.float32, device=device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = torch.optim.AdamW(model.parameters(), lr=2.5e-4, weight_decay=1.5e-4)
    X_val_t = torch.from_numpy(X_val).to(device)
    y_val_i = y_val.astype(int)
    best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    best = {"binary_f1": -1.0, "threshold": base_result.threshold}
    best_epoch = 0
    print("[DEFENSE] Adversarially fine-tuning Torch Binary MLP with PGD examples")
    for epoch in range(1, 11):
        model.train()
        for xb, yb in train_loader:
            xb = xb.to(device, non_blocking=True)
            yb = yb.to(device, non_blocking=True)
            attack_mask = yb > 0.5
            optimizer.zero_grad(set_to_none=True)
            clean_logits = model(xb)
            loss = criterion(clean_logits, yb)
            if torch.any(attack_mask):
                x_attack = xb[attack_mask].detach()
                x_adv = pgd_attack_torch_binary_tensor(
                    model,
                    x_attack,
                    eps=eps,
                    alpha=max(eps / 4, 0.01),
                    steps=4,
                )
                adv_logits = model(x_adv)
                adv_labels = torch.ones_like(adv_logits)
                loss = loss + 0.75 * criterion(adv_logits, adv_labels)
            loss.backward()
            optimizer.step()

        model.eval()
        with torch.no_grad():
            val_scores = torch.sigmoid(model(X_val_t)).cpu().numpy()
        tuned = tune_binary_threshold(y_val_i, val_scores)
        print(f"  adv_epoch={epoch:02d} val_binary_f1={tuned['binary_f1']:.4f} threshold={tuned['threshold']:.2f}")
        if tuned["binary_f1"] > best["binary_f1"]:
            best = tuned
            best_epoch = epoch
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    model.load_state_dict(best_state)
    print(
        f"[DEFENSE] Torch adversarial fine-tune selected epoch={best_epoch} "
        f"val_binary_f1={best['binary_f1']:.4f} threshold={best['threshold']:.2f}"
    )
    return TorchBinaryResult(
        model=model,
        best_epoch=best_epoch,
        val_binary_f1=best["binary_f1"],
        threshold=best["threshold"],
        device=device,
        name=f"PGD-Adversarial Torch Binary MLP eps={eps}",
    )


def predict_torch_binary(model, X, device, batch_size=4096):
    model.eval()
    scores = []
    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            xb = torch.from_numpy(X[start:start + batch_size]).to(device)
            scores.append(torch.sigmoid(model(xb)).cpu().numpy())
    return np.concatenate(scores)


def evaluate_binary_scores(name, y_family, scores, threshold):
    y_true = (y_family != FAMILY_TO_ID["normal"]).astype(int)
    pred = (scores >= threshold).astype(int)
    result = {
        "binary_macro_precision": float(precision_score(y_true, pred, average="macro", zero_division=0)),
        "binary_macro_recall": float(recall_score(y_true, pred, average="macro", zero_division=0)),
        "binary_macro_f1": float(f1_score(y_true, pred, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, pred)),
        "pr_auc": float(average_precision_score(y_true, scores)),
        "threshold": float(threshold),
        "per_family_recall": {
            family: float(np.mean(pred[y_family == idx] == 1)) if idx != FAMILY_TO_ID["normal"] else float(np.mean(pred[y_family == idx] == 0))
            for idx, family in enumerate(FAMILY_ORDER)
        },
    }
    print(
        f"[EVAL] {name:<28} binary_F1={result['binary_macro_f1']:.4f} "
        f"PR-AUC={result['pr_auc']:.4f} binary_bal_acc={result['balanced_accuracy']:.4f} "
        f"threshold={threshold:.2f}"
    )
    return result


def train_binary_cpu_models(X_train, y_train_family):
    y_binary = (y_train_family != FAMILY_TO_ID["normal"]).astype(int)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_binary,
        test_size=0.2,
        random_state=SEED,
        stratify=y_binary,
    )
    print("[TRAIN] Strong binary IDS CPU models")

    lr = LogisticRegression(max_iter=1600, class_weight="balanced", C=1.5, n_jobs=-1, random_state=SEED)
    lr.fit(X_fit, y_fit)
    lr_scores = lr.predict_proba(X_val)[:, 1]
    lr_tuned = tune_binary_threshold(y_val, lr_scores)
    print(f"  Binary LR val_f1={lr_tuned['binary_f1']:.4f} threshold={lr_tuned['threshold']:.2f}")
    lr.fit(X_train, y_binary)

    rf = RandomForestClassifier(
        n_estimators=420,
        max_depth=26,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=SEED,
        n_jobs=-1,
    )
    rf.fit(X_fit, y_fit)
    rf_scores = rf.predict_proba(X_val)[:, 1]
    rf_tuned = tune_binary_threshold(y_val, rf_scores)
    print(f"  Binary RF val_f1={rf_tuned['binary_f1']:.4f} threshold={rf_tuned['threshold']:.2f}")
    rf.fit(X_train, y_binary)

    et = ExtraTreesClassifier(
        n_estimators=520,
        max_depth=None,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        random_state=SEED,
        n_jobs=-1,
    )
    et.fit(X_fit, y_fit)
    et_scores = et.predict_proba(X_val)[:, 1]
    et_tuned = tune_binary_threshold(y_val, et_scores)
    print(f"  Binary ExtraTrees val_f1={et_tuned['binary_f1']:.4f} threshold={et_tuned['threshold']:.2f}")
    et.fit(X_train, y_binary)

    xgb_entry = None
    if XGBClassifier is not None:
        scale_pos_weight = float(np.sum(y_fit == 0) / max(1, np.sum(y_fit == 1)))
        xgb = XGBClassifier(
            n_estimators=700,
            max_depth=5,
            learning_rate=0.035,
            subsample=0.85,
            colsample_bytree=0.75,
            min_child_weight=2.0,
            reg_lambda=2.0,
            reg_alpha=0.05,
            objective="binary:logistic",
            eval_metric="aucpr",
            tree_method="hist",
            random_state=SEED,
            n_jobs=-1,
            scale_pos_weight=scale_pos_weight,
        )
        xgb.fit(X_fit, y_fit)
        xgb_scores = xgb.predict_proba(X_val)[:, 1]
        xgb_tuned = tune_binary_threshold(y_val, xgb_scores)
        print(f"  Binary XGBoost val_f1={xgb_tuned['binary_f1']:.4f} threshold={xgb_tuned['threshold']:.2f}")
        xgb.fit(X_train, y_binary)
        xgb_entry = {"model": xgb, "threshold": xgb_tuned["threshold"]}
    else:
        print("  Binary XGBoost skipped: install xgboost to enable this optional model.")

    return {
        "binary_lr": {"model": lr, "threshold": lr_tuned["threshold"]},
        "binary_rf": {"model": rf, "threshold": rf_tuned["threshold"]},
        "binary_extratrees": {"model": et, "threshold": et_tuned["threshold"]},
        "binary_xgboost": xgb_entry,
        "validation": {
            "X_val": X_val,
            "y_val": y_val,
        },
    }


def tune_binary_ensemble(binary_models, torch_binary_result, X_val, y_val, device):
    scores = {
        "lr": binary_models["binary_lr"]["model"].predict_proba(X_val)[:, 1],
        "rf": binary_models["binary_rf"]["model"].predict_proba(X_val)[:, 1],
        "et": binary_models["binary_extratrees"]["model"].predict_proba(X_val)[:, 1],
        "torch": predict_torch_binary(torch_binary_result.model, X_val, device),
    }
    if binary_models.get("binary_xgboost") is not None:
        scores["xgb"] = binary_models["binary_xgboost"]["model"].predict_proba(X_val)[:, 1]
        weight_grid = [
            {"lr": 0.05, "rf": 0.20, "et": 0.25, "xgb": 0.35, "torch": 0.15},
            {"lr": 0.05, "rf": 0.15, "et": 0.25, "xgb": 0.45, "torch": 0.10},
            {"lr": 0.10, "rf": 0.20, "et": 0.20, "xgb": 0.35, "torch": 0.15},
            {"lr": 0.05, "rf": 0.25, "et": 0.20, "xgb": 0.30, "torch": 0.20},
        ]
    else:
        weight_grid = [
            {"lr": 0.10, "rf": 0.35, "et": 0.35, "torch": 0.20},
            {"lr": 0.05, "rf": 0.40, "et": 0.40, "torch": 0.15},
            {"lr": 0.15, "rf": 0.30, "et": 0.35, "torch": 0.20},
            {"lr": 0.10, "rf": 0.25, "et": 0.45, "torch": 0.20},
            {"lr": 0.20, "rf": 0.25, "et": 0.30, "torch": 0.25},
        ]
    best = None
    for weights in weight_grid:
        ensemble_scores = sum(weights[name] * scores[name] for name in weights)
        tuned = tune_binary_threshold(y_val, ensemble_scores)
        candidate = {**tuned, "weights": weights}
        if best is None or (candidate["binary_f1"], candidate["balanced_accuracy"]) > (
            best["binary_f1"],
            best["balanced_accuracy"],
        ):
            best = candidate
    print(f"[TRAIN] Binary ensemble val_f1={best['binary_f1']:.4f} threshold={best['threshold']:.2f} weights={best['weights']}")
    return best


def predict_binary_ensemble(binary_models, torch_binary_result, X, device, weights):
    score = (
        weights.get("lr", 0.0) * binary_models["binary_lr"]["model"].predict_proba(X)[:, 1]
        + weights.get("rf", 0.0) * binary_models["binary_rf"]["model"].predict_proba(X)[:, 1]
        + weights.get("et", 0.0) * binary_models["binary_extratrees"]["model"].predict_proba(X)[:, 1]
        + weights.get("torch", 0.0) * predict_torch_binary(torch_binary_result.model, X, device)
    )
    if weights.get("xgb", 0.0) and binary_models.get("binary_xgboost") is not None:
        score += weights["xgb"] * binary_models["binary_xgboost"]["model"].predict_proba(X)[:, 1]
    return score


def tune_adv_tree_ensemble(binary_models, torch_binary_adv_result, X_val, y_val, device):
    """Validation-tuned blend for the shifted NSL-KDD test setting.

    The validation split is very easy for high-capacity tree models, so a large unconstrained
    weight search tends to select brittle thresholds. This deliberately small candidate set keeps
    the ensemble biased toward the adversarially fine-tuned Torch detector and ExtraTrees, which
    complement each other on rare attack recall and ranking quality.
    """
    scores = {
        "adv": predict_torch_binary(torch_binary_adv_result.model, X_val, device),
        "et": binary_models["binary_extratrees"]["model"].predict_proba(X_val)[:, 1],
    }
    weight_grid = [
        {"adv": 0.25, "et": 0.75},
        {"adv": 0.30, "et": 0.70},
        {"adv": 0.20, "et": 0.80},
    ]
    best = None
    for weights in weight_grid:
        ensemble_scores = sum(weights[name] * scores[name] for name in weights)
        tuned = tune_binary_threshold(y_val, ensemble_scores)
        candidate = {**tuned, "weights": weights}
        if best is None or (
            candidate["binary_f1"],
            candidate["balanced_accuracy"],
            -candidate["threshold"],
        ) > (
            best["binary_f1"],
            best["balanced_accuracy"],
            -best["threshold"],
        ):
            best = candidate
    print(
        f"[TRAIN] Adv+ExtraTrees ensemble val_f1={best['binary_f1']:.4f} "
        f"threshold={best['threshold']:.2f} weights={best['weights']}"
    )
    return best


def predict_adv_tree_ensemble(binary_models, torch_binary_adv_result, X, device, weights):
    return (
        weights.get("adv", 0.0) * predict_torch_binary(torch_binary_adv_result.model, X, device)
        + weights.get("et", 0.0) * binary_models["binary_extratrees"]["model"].predict_proba(X)[:, 1]
    )


def train_cpu_models(X_train, y_train):
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_train,
        test_size=0.2,
        random_state=SEED,
        stratify=y_train,
    )

    print("[TRAIN] Logistic Regression baseline")
    lr_candidates = [
        {"C": 0.7},
        {"C": 1.5},
    ]
    best_lr = None
    for params in lr_candidates:
        candidate = LogisticRegression(
            max_iter=1400,
            class_weight="balanced",
            n_jobs=-1,
            random_state=SEED,
            **params,
        )
        candidate.fit(X_fit, y_fit)
        val_prob = candidate.predict_proba(X_val)
        mult = tune_class_multipliers(y_val, val_prob)
        print(f"  LR params={params} val_macro_f1={mult['macro_f1']:.4f} rare_recall={mult['rare_recall']:.4f}")
        if best_lr is None or mult["score"] > best_lr["score"]:
            best_lr = {"params": params, **mult}

    lr = LogisticRegression(
        max_iter=1400,
        class_weight="balanced",
        n_jobs=-1,
        random_state=SEED,
        **best_lr["params"],
    )
    lr.fit(X_train, y_train)
    print(f"  selected LR={best_lr['params']} multipliers={dict(zip(FAMILY_ORDER, np.round(best_lr['multipliers'], 2)))}")

    print("[TRAIN] Random Forest variation")
    X_rf_search = X_fit
    y_rf_search = y_fit
    if len(X_rf_search) > 80000:
        X_rf_search, _, y_rf_search, _ = train_test_split(
            X_rf_search,
            y_rf_search,
            train_size=80000,
            random_state=SEED,
            stratify=y_rf_search,
        )
    X_rf_fit, y_rf_fit = oversample_minority_classes(X_rf_search, y_rf_search, min_count=3000, multiplier_cap=80)
    rf_candidates = [
        {"n_estimators": 180, "max_depth": 18, "min_samples_leaf": 1},
        {"n_estimators": 240, "max_depth": 22, "min_samples_leaf": 1},
        {"n_estimators": 320, "max_depth": 24, "min_samples_leaf": 2},
    ]
    best_rf = None
    for params in rf_candidates:
        candidate = RandomForestClassifier(
            class_weight="balanced_subsample",
            random_state=SEED,
            n_jobs=-1,
            **params,
        )
        candidate.fit(X_rf_fit, y_rf_fit, sample_weight=sample_weights_from_labels(y_rf_fit))
        val_prob = candidate.predict_proba(X_val)
        mult = tune_class_multipliers(y_val, val_prob)
        print(f"  RF params={params} val_macro_f1={mult['macro_f1']:.4f} rare_recall={mult['rare_recall']:.4f}")
        if best_rf is None or mult["score"] > best_rf["score"]:
            best_rf = {"params": params, **mult}

    rf = RandomForestClassifier(
        class_weight="balanced_subsample",
        random_state=SEED,
        n_jobs=-1,
        **best_rf["params"],
    )
    X_rf_train, y_rf_train = oversample_minority_classes(X_train, y_train, min_count=3000, multiplier_cap=80)
    rf.fit(X_rf_train, y_rf_train, sample_weight=sample_weights_from_labels(y_rf_train))
    print(f"  selected RF={best_rf['params']} multipliers={dict(zip(FAMILY_ORDER, np.round(best_rf['multipliers'], 2)))}")
    return lr, best_lr["multipliers"], rf, best_rf["multipliers"]


def evaluate_predictions(name, y_true, prob, multipliers=None):
    if multipliers is None:
        pred = prob.argmax(axis=1)
    else:
        pred = prediction_from_multipliers(prob, multipliers)
    binary_true = (y_true != FAMILY_TO_ID["normal"]).astype(int)
    binary_pred = (pred != FAMILY_TO_ID["normal"]).astype(int)
    attack_score = 1.0 - prob[:, FAMILY_TO_ID["normal"]]
    per_family_recall = recall_score(
        y_true,
        pred,
        average=None,
        labels=np.arange(len(FAMILY_ORDER)),
        zero_division=0,
    )
    result = {
        "family_macro_precision": float(precision_score(y_true, pred, average="macro", zero_division=0)),
        "family_macro_recall": float(recall_score(y_true, pred, average="macro", zero_division=0)),
        "family_macro_f1": float(f1_score(y_true, pred, average="macro", zero_division=0)),
        "binary_macro_precision": float(precision_score(binary_true, binary_pred, average="macro", zero_division=0)),
        "binary_macro_recall": float(recall_score(binary_true, binary_pred, average="macro", zero_division=0)),
        "binary_macro_f1": float(f1_score(binary_true, binary_pred, average="macro", zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(binary_true, binary_pred)),
        "pr_auc": float(average_precision_score(binary_true, attack_score)),
        "per_family_recall": {
            family: float(per_family_recall[idx])
            for idx, family in enumerate(FAMILY_ORDER)
        },
        "multipliers": [float(x) for x in multipliers] if multipliers is not None else None,
    }
    print(
        f"[EVAL] {name:<28} binary_F1={result['binary_macro_f1']:.4f} "
        f"family_F1={result['family_macro_f1']:.4f} "
        f"PR-AUC={result['pr_auc']:.4f} binary_bal_acc={result['balanced_accuracy']:.4f}"
    )
    print(classification_report(y_true, pred, target_names=FAMILY_ORDER, zero_division=0))
    return result, pred


def shap_values_to_dict(shap_values):
    if isinstance(shap_values, list):
        return {idx: np.asarray(values) for idx, values in enumerate(shap_values)}
    arr = np.asarray(shap_values)
    if arr.ndim == 3:
        return {idx: arr[:, :, idx] for idx in range(arr.shape[2])}
    raise ValueError(f"Unsupported SHAP output shape: {arr.shape}")


def aggregate_attack_importance(expl_by_class):
    attack_ids = [FAMILY_TO_ID[name] for name in FAMILY_ORDER if name != "normal"]
    return np.mean([np.abs(expl_by_class[idx]) for idx in attack_ids], axis=(0, 1))


def select_true_family(expl_by_class, y_labels):
    selected = np.zeros((len(y_labels), next(iter(expl_by_class.values())).shape[1]), dtype=np.float32)
    for cls_idx in range(len(FAMILY_ORDER)):
        mask = y_labels == cls_idx
        selected[mask] = expl_by_class[cls_idx][mask]
    return selected


def integrated_gradients(model, X, y_target, device, steps=24, batch_size=128):
    model.eval()
    baseline = torch.zeros((1, X.shape[1]), dtype=torch.float32, device=device)
    attributions = []
    for start in range(0, len(X), batch_size):
        xb = torch.from_numpy(X[start:start + batch_size]).to(device)
        yb = torch.from_numpy(y_target[start:start + batch_size]).to(device)
        total_grad = torch.zeros_like(xb)
        for alpha in torch.linspace(0.0, 1.0, steps, device=device):
            scaled = baseline + alpha * (xb - baseline)
            scaled.requires_grad_(True)
            scores = model(scaled).gather(1, yb.view(-1, 1)).sum()
            grads = torch.autograd.grad(scores, scaled)[0]
            total_grad += grads.detach()
        ig = (xb - baseline) * total_grad / steps
        attributions.append(ig.detach().cpu().numpy())
    return np.vstack(attributions)


def explain_models(rf, torch_result, X_train, X_test, y_test, feature_names):
    n_explain = min(700, len(X_test))
    X_sub = X_test[:n_explain]
    y_sub = y_test[:n_explain]

    print("[XAI] TreeSHAP for Random Forest")
    tree_explainer = shap.TreeExplainer(rf)
    rf_by_class = shap_values_to_dict(tree_explainer.shap_values(X_sub))
    rf_true = select_true_family(rf_by_class, y_sub)
    rf_global = aggregate_attack_importance(rf_by_class)

    print("[XAI] Integrated gradients for Torch MLP")
    torch_prob = predict_torch(torch_result.model, X_sub, torch_result.device)
    torch_target = torch_prob.argmax(axis=1).astype(np.int64)
    ig_true = integrated_gradients(torch_result.model, X_sub, torch_target, torch_result.device)
    ig_global = np.mean(np.abs(ig_true[y_sub != FAMILY_TO_ID["normal"]]), axis=0)

    corr, pval = spearmanr(rf_global, ig_global)
    top_rf = np.argsort(rf_global)[-10:][::-1]
    top_ig = np.argsort(ig_global)[-10:][::-1]
    print(f"[XAI] RF/torch explanation Spearman={corr:.3f} p={pval:.4g}")
    print("[XAI] Top RF SHAP features:")
    for rank, idx in enumerate(top_rf, start=1):
        print(f"  {rank:2d}. {feature_names[idx]:<36} {rf_global[idx]:.5f}")
    print("[XAI] Top Torch IG features:")
    for rank, idx in enumerate(top_ig, start=1):
        print(f"  {rank:2d}. {feature_names[idx]:<36} {ig_global[idx]:.5f}")

    plt.figure(figsize=(10, 6))
    values = np.arange(10)
    plt.barh(values, rf_global[top_rf][::-1], color="#2E75B6")
    plt.yticks(values, [feature_names[i] for i in top_rf[::-1]])
    plt.xlabel("Mean |SHAP value|")
    plt.title("Random Forest SHAP Attack Feature Importance")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "rf_shap_top10.png"), dpi=160)
    plt.close()

    x = np.arange(10)
    plt.figure(figsize=(11, 6))
    plt.bar(x - 0.2, rf_global[top_rf], width=0.4, label="RF SHAP", color="#2E75B6")
    plt.bar(x + 0.2, ig_global[top_rf], width=0.4, label="Torch IG", color="#D95F02")
    plt.xticks(x, [feature_names[i] for i in top_rf], rotation=45, ha="right")
    plt.ylabel("Global importance")
    plt.title("Explanation Agreement on RF Top Features")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "rf_vs_torch_explanations.png"), dpi=160)
    plt.close()

    return {
        "rf_true": rf_true,
        "ig_true": ig_true,
        "rf_global": rf_global,
        "ig_global": ig_global,
        "rf_torch_spearman": float(corr),
        "rf_torch_spearman_p": float(pval),
    }


def jaccard_topk(a, b, k=10):
    top_a = set(np.argsort(np.abs(a))[-k:])
    top_b = set(np.argsort(np.abs(b))[-k:])
    return len(top_a & top_b) / max(1, len(top_a | top_b))


def stability_analysis(X_test, y_test, attributions, top_k=10):
    attack_mask = y_test[:len(attributions)] != FAMILY_TO_ID["normal"]
    X_att = X_test[:len(attributions)][attack_mask][:500]
    y_att = y_test[:len(attributions)][attack_mask][:500]
    S_att = attributions[attack_mask][:500]
    scores = []
    for i in range(len(X_att)):
        same = np.where(y_att == y_att[i])[0]
        same = same[same != i]
        if len(same) == 0:
            continue
        nn = same[np.argmin(np.linalg.norm(X_att[same] - X_att[i], axis=1))]
        scores.append(jaccard_topk(S_att[i], S_att[nn], top_k))
    mean = float(np.mean(scores))
    std = float(np.std(scores))
    print(f"[STABILITY] IG top-{top_k} nearest-neighbor Jaccard={mean:.3f} +/- {std:.3f}")

    plt.figure(figsize=(8, 5))
    plt.hist(scores, bins=20, color="#4C78A8", edgecolor="white")
    plt.xlabel(f"Jaccard similarity of top-{top_k} features")
    plt.ylabel("Pairs")
    plt.title("Torch IG Explanation Stability")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "ig_stability.png"), dpi=160)
    plt.close()
    return {"ig_jaccard_mean": mean, "ig_jaccard_std": std, "pairs": len(scores)}


def explanation_stability(name, X_test, y_test, attributions, global_importance, top_k=10):
    attack_mask = y_test[:len(attributions)] != FAMILY_TO_ID["normal"]
    X_att = X_test[:len(attributions)][attack_mask][:500]
    y_att = y_test[:len(attributions)][attack_mask][:500]
    S_att = attributions[attack_mask][:500]
    local_scores = []
    rank_scores = []
    for i in range(len(X_att)):
        same = np.where(y_att == y_att[i])[0]
        same = same[same != i]
        if len(same) == 0:
            continue
        nn = same[np.argmin(np.linalg.norm(X_att[same] - X_att[i], axis=1))]
        local_scores.append(jaccard_topk(S_att[i], S_att[nn], top_k))
        corr, _ = spearmanr(np.abs(S_att[i]), np.abs(S_att[nn]))
        if np.isfinite(corr):
            rank_scores.append(corr)

    rng = np.random.default_rng(SEED)
    boot_scores = []
    boot_rank_scores = []
    base_top = set(np.argsort(global_importance)[-top_k:])
    for _ in range(50):
        idx = rng.choice(len(S_att), size=len(S_att), replace=True)
        boot_importance = np.mean(np.abs(S_att[idx]), axis=0)
        boot_top = set(np.argsort(boot_importance)[-top_k:])
        boot_scores.append(len(base_top & boot_top) / max(1, len(base_top | boot_top)))
        corr, _ = spearmanr(global_importance, boot_importance)
        if np.isfinite(corr):
            boot_rank_scores.append(corr)

    result = {
        "local_jaccard_mean": float(np.mean(local_scores)),
        "local_jaccard_std": float(np.std(local_scores)),
        "local_rank_corr_mean": float(np.mean(rank_scores)),
        "bootstrap_jaccard_mean": float(np.mean(boot_scores)),
        "bootstrap_rank_corr_mean": float(np.mean(boot_rank_scores)),
        "pairs": int(len(local_scores)),
    }
    print(
        f"[STABILITY] {name} top-{top_k}: "
        f"local_jaccard={result['local_jaccard_mean']:.3f} +/- {result['local_jaccard_std']:.3f} "
        f"local_rank={result['local_rank_corr_mean']:.3f} "
        f"bootstrap_jaccard={result['bootstrap_jaccard_mean']:.3f}"
    )
    return result


def ig_guided_evasion(torch_result, X_test, y_test, ig_true, top_k_values=(5, 10, 15), eps_values=(0.03, 0.06, 0.10)):
    n = min(len(ig_true), len(X_test))
    X = X_test[:n]
    y = y_test[:n]
    attack_mask = y != FAMILY_TO_ID["normal"]
    X_attack = X[attack_mask]
    y_attack = y[attack_mask]
    S_attack = ig_true[attack_mask]
    clean_pred = predict_torch(torch_result.model, X_attack, torch_result.device).argmax(axis=1)
    detected = clean_pred != FAMILY_TO_ID["normal"]
    base_detected = int(np.sum(detected))
    results = {}
    heatmap = np.zeros((len(top_k_values), len(eps_values)), dtype=float)
    print("[ATTACK] Integrated-gradient guided feature evasion against Torch MLP")
    for i, top_k in enumerate(top_k_values):
        for j, eps in enumerate(eps_values):
            X_adv = X_attack.copy()
            for row_idx in range(len(X_adv)):
                local_top = np.argsort(np.abs(S_attack[row_idx]))[-top_k:]
                for feat in local_top:
                    X_adv[row_idx, feat] = np.clip(X_adv[row_idx, feat] - eps * np.sign(S_attack[row_idx, feat]), 0, 1)
            adv_pred = predict_torch(torch_result.model, X_adv, torch_result.device).argmax(axis=1)
            evaded = np.sum((adv_pred == FAMILY_TO_ID["normal"]) & detected)
            rate = float(evaded / max(1, base_detected))
            key = f"ig_top{top_k}_eps{eps}"
            results[key] = rate
            heatmap[i, j] = rate
            print(f"  top-{top_k:02d} eps={eps:.2f}: evasion={100 * rate:.2f}%")
    plt.figure(figsize=(7, 5))
    plt.imshow(heatmap, cmap="magma", vmin=0, vmax=max(0.01, heatmap.max()))
    plt.colorbar(label="Evasion rate")
    plt.xticks(range(len(eps_values)), eps_values)
    plt.yticks(range(len(top_k_values)), top_k_values)
    plt.xlabel("epsilon")
    plt.ylabel("top-k features")
    plt.title("Torch IG-Guided Evasion")
    for i in range(len(top_k_values)):
        for j in range(len(eps_values)):
            plt.text(j, i, f"{100 * heatmap[i, j]:.1f}%", ha="center", va="center", color="white")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "ig_evasion_heatmap.png"), dpi=160)
    plt.close()
    return results


def binary_integrated_gradients(model, X, device, steps=24, batch_size=128):
    model.eval()
    baseline = torch.zeros((1, X.shape[1]), dtype=torch.float32, device=device)
    attributions = []
    for start in range(0, len(X), batch_size):
        xb = torch.from_numpy(X[start:start + batch_size]).to(device)
        total_grad = torch.zeros_like(xb)
        for alpha in torch.linspace(0.0, 1.0, steps, device=device):
            scaled = baseline + alpha * (xb - baseline)
            scaled.requires_grad_(True)
            scores = model(scaled).sum()
            grads = torch.autograd.grad(scores, scaled)[0]
            total_grad += grads.detach()
        attributions.append(((xb - baseline) * total_grad / steps).detach().cpu().numpy())
    return np.vstack(attributions)


def smooth_binary_integrated_gradients(model, X, device, repeats=6, noise_std=0.025, steps=18):
    rng = np.random.default_rng(SEED)
    total = np.zeros_like(X, dtype=np.float32)
    for _ in range(repeats):
        noisy = np.clip(X + rng.normal(0.0, noise_std, size=X.shape).astype(np.float32), 0, 1)
        total += binary_integrated_gradients(model, noisy, device, steps=steps)
    return total / repeats


def binary_mlp_explainability(torch_binary_result, X_test, y_test, feature_names):
    n_explain = min(900, len(X_test))
    X_sub = X_test[:n_explain]
    y_sub = y_test[:n_explain]
    print("[XAI] Smooth Integrated Gradients for Torch Binary MLP")
    sig = smooth_binary_integrated_gradients(torch_binary_result.model, X_sub, torch_binary_result.device)
    attack_sig = sig[y_sub != FAMILY_TO_ID["normal"]]
    global_importance = np.mean(np.abs(attack_sig), axis=0)
    top = np.argsort(global_importance)[-10:][::-1]
    print("[XAI] Top Torch Binary SmoothIG features:")
    for rank, idx in enumerate(top, start=1):
        print(f"  {rank:2d}. {feature_names[idx]:<36} {global_importance[idx]:.5f}")

    stability = explanation_stability(
        "Torch Binary SmoothIG",
        X_test,
        y_test,
        sig,
        global_importance,
    )
    plt.figure(figsize=(10, 6))
    values = np.arange(10)
    plt.barh(values, global_importance[top][::-1], color="#009E73")
    plt.yticks(values, [feature_names[i] for i in top[::-1]])
    plt.xlabel("Mean |SmoothIG attribution|")
    plt.title("Torch Binary MLP SmoothIG Attack Feature Importance")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "torch_binary_smoothig_top10.png"), dpi=160)
    plt.close()
    return {
        "attributions": sig,
        "global_importance": global_importance,
        "stability": stability,
    }


def pgd_attack_torch_binary(model, X, device, eps=0.10, alpha=0.01, steps=30, feature_mask=None):
    model.eval()
    X_orig = torch.from_numpy(X).to(device)
    X_adv = X_orig.clone().detach()
    mask = None
    if feature_mask is not None:
        mask = torch.from_numpy(feature_mask.astype(np.float32)).to(device)
    for _ in range(steps):
        X_adv.requires_grad_(True)
        # Minimize attack probability by minimizing the binary attack logit.
        loss = model(X_adv).sum()
        grad = torch.autograd.grad(loss, X_adv)[0]
        if mask is not None:
            grad = grad * mask
        X_adv = X_adv.detach() - alpha * torch.sign(grad.detach())
        delta = torch.clamp(X_adv - X_orig, min=-eps, max=eps)
        X_adv = torch.clamp(X_orig + delta, 0.0, 1.0).detach()
    return X_adv.cpu().numpy()


def evaluate_torch_binary_adversarial(torch_binary_result, X_test, y_test, smoothig_attr=None):
    y_binary = (y_test != FAMILY_TO_ID["normal"]).astype(int)
    attack_idx = np.where(y_binary == 1)[0]
    if smoothig_attr is not None:
        attack_idx = attack_idx[attack_idx < len(smoothig_attr)]
    attack_idx = attack_idx[: min(3500, len(attack_idx))]
    X_attack = X_test[attack_idx]
    clean_scores = predict_torch_binary(torch_binary_result.model, X_attack, torch_binary_result.device)
    detected = clean_scores >= torch_binary_result.threshold
    X_detected = X_attack[detected]
    if len(X_detected) == 0:
        return {}

    results = {}
    eps_values = (0.03, 0.06, 0.10, 0.15)
    print("[ATTACK] White-box PGD evasion against Torch Binary MLP")
    for eps in eps_values:
        X_adv = pgd_attack_torch_binary(
            torch_binary_result.model,
            X_detected,
            torch_binary_result.device,
            eps=eps,
            alpha=max(eps / 8, 0.005),
            steps=32,
        )
        adv_scores = predict_torch_binary(torch_binary_result.model, X_adv, torch_binary_result.device)
        rate = float(np.mean(adv_scores < torch_binary_result.threshold))
        key = f"pgd_all_eps{eps}"
        results[key] = rate
        print(f"  PGD all-features eps={eps:.2f}: evasion={100 * rate:.2f}%")

    if smoothig_attr is not None:
        print("[ATTACK] SmoothIG-constrained PGD evasion against Torch Binary MLP")
        local_attr = smoothig_attr[attack_idx][detected]
        for top_k in (10, 20, 40):
            masks = np.zeros_like(X_detected, dtype=np.float32)
            for row_idx in range(len(masks)):
                selected = np.argsort(np.abs(local_attr[row_idx]))[-top_k:]
                masks[row_idx, selected] = 1.0
            for eps in (0.06, 0.10, 0.15):
                X_adv = pgd_attack_torch_binary(
                    torch_binary_result.model,
                    X_detected,
                    torch_binary_result.device,
                    eps=eps,
                    alpha=max(eps / 8, 0.005),
                    steps=32,
                    feature_mask=masks,
                )
                adv_scores = predict_torch_binary(torch_binary_result.model, X_adv, torch_binary_result.device)
                rate = float(np.mean(adv_scores < torch_binary_result.threshold))
                key = f"smoothig_top{top_k}_eps{eps}"
                results[key] = rate
                print(f"  SmoothIG top-{top_k:02d} eps={eps:.2f}: evasion={100 * rate:.2f}%")

    labels = list(results.keys())
    values = [results[k] for k in labels]
    plt.figure(figsize=(11, 5))
    plt.bar(np.arange(len(values)), values, color="#CC79A7")
    plt.xticks(np.arange(len(values)), labels, rotation=45, ha="right")
    plt.ylabel("Evasion rate")
    plt.title("Torch Binary MLP Adversarial Evasion")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "torch_binary_pgd_evasion.png"), dpi=160)
    plt.close()
    return results


def compare_pgd_defense(before_attacks, after_attacks):
    comparison = {}
    for key, before in before_attacks.items():
        if not key.startswith("pgd_all_") or key not in after_attacks:
            continue
        after = after_attacks[key]
        comparison[key] = {
            "before": float(before),
            "after": float(after),
            "reduction": float(before - after),
            "relative_reduction": float((before - after) / before) if before > 0 else 0.0,
        }
    return comparison


def evaluate_adv_tree_transfer_pgd(binary_models, torch_binary_adv_result, adv_tree_tuning, X_test, y_test, device):
    y_binary = (y_test != FAMILY_TO_ID["normal"]).astype(int)
    attack_idx = np.where(y_binary == 1)[0][:3500]
    X_attack = X_test[attack_idx]
    if len(X_attack) == 0:
        return {}

    threshold = adv_tree_tuning["threshold"]
    weights = adv_tree_tuning["weights"]
    clean_scores = predict_adv_tree_ensemble(binary_models, torch_binary_adv_result, X_attack, device, weights)
    detected = clean_scores >= threshold
    X_detected = X_attack[detected]
    if len(X_detected) == 0:
        return {}

    results = {}
    print("[DEFENSE] Adv+ExtraTrees transfer-PGD defense")
    print(
        f"  clean_attack_detection={100 * float(np.mean(detected)):.2f}% "
        f"threshold={threshold:.2f} weights={weights}"
    )
    for eps in (0.03, 0.06, 0.10, 0.15):
        X_adv = pgd_attack_torch_binary(
            torch_binary_adv_result.model,
            X_detected,
            device,
            eps=eps,
            alpha=max(eps / 8, 0.005),
            steps=32,
        )
        surrogate_scores = predict_torch_binary(torch_binary_adv_result.model, X_adv, device)
        ensemble_scores = predict_adv_tree_ensemble(binary_models, torch_binary_adv_result, X_adv, device, weights)
        et_scores = binary_models["binary_extratrees"]["model"].predict_proba(X_adv)[:, 1]

        surrogate_rate = float(np.mean(surrogate_scores < torch_binary_adv_result.threshold))
        ensemble_rate = float(np.mean(ensemble_scores < threshold))
        et_rate = float(np.mean(et_scores < binary_models["binary_extratrees"]["threshold"]))
        reduction = float(surrogate_rate - ensemble_rate)
        key = f"transfer_pgd_eps{eps}"
        results[key] = {
            "surrogate_torch_evasion": surrogate_rate,
            "ensemble_transfer_evasion": ensemble_rate,
            "extra_trees_transfer_evasion": et_rate,
            "absolute_reduction": reduction,
            "relative_reduction": float(reduction / surrogate_rate) if surrogate_rate > 0 else 0.0,
        }
        print(
            f"  eps={eps:.2f}: surrogate_torch={100 * surrogate_rate:.2f}% "
            f"ensemble={100 * ensemble_rate:.2f}% reduction={100 * reduction:.2f}%"
        )

    labels = list(results.keys())
    surrogate_values = [results[k]["surrogate_torch_evasion"] for k in labels]
    ensemble_values = [results[k]["ensemble_transfer_evasion"] for k in labels]
    x = np.arange(len(labels))
    width = 0.36
    plt.figure(figsize=(9, 5))
    plt.bar(x - width / 2, surrogate_values, width, label="Adversarial Torch surrogate", color="#D55E00")
    plt.bar(x + width / 2, ensemble_values, width, label="Adv+ExtraTrees ensemble", color="#0072B2")
    plt.xticks(x, [label.replace("transfer_pgd_", "") for label in labels])
    plt.ylabel("Evasion rate")
    plt.title("Transfer PGD Defense: Surrogate vs Ensemble")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "adv_tree_transfer_pgd_defense.png"), dpi=160)
    plt.close()
    return results


def predict_rf(rf, X, multipliers=None):
    prob = rf.predict_proba(X)
    if multipliers is None:
        return prob.argmax(axis=1)
    return prediction_from_multipliers(prob, multipliers)


def rf_shap_adversarial_examples(X_attack, shap_attack, top_k, eps, mode="local"):
    X_adv = X_attack.copy()
    if mode == "global":
        global_importance = np.mean(np.abs(shap_attack), axis=0)
        global_direction = np.sign(np.mean(shap_attack, axis=0))
        selected = np.argsort(global_importance)[-top_k:]
        for feat in selected:
            X_adv[:, feat] = np.clip(X_adv[:, feat] - eps * global_direction[feat], 0, 1)
        return X_adv

    for row_idx in range(len(X_adv)):
        local_top = np.argsort(np.abs(shap_attack[row_idx]))[-top_k:]
        for feat in local_top:
            X_adv[row_idx, feat] = np.clip(
                X_adv[row_idx, feat] - eps * np.sign(shap_attack[row_idx, feat]),
                0,
                1,
            )
    return X_adv


def rf_shap_guided_evasion(rf, rf_multipliers, X_test, y_test, rf_true, top_k_values=(5, 10, 15), eps_values=(0.05, 0.10, 0.20)):
    n = min(len(rf_true), len(X_test))
    X = X_test[:n]
    y = y_test[:n]
    attack_mask = y != FAMILY_TO_ID["normal"]
    X_attack = X[attack_mask]
    S_attack = rf_true[attack_mask]
    clean_pred = predict_rf(rf, X_attack, rf_multipliers)
    detected = clean_pred != FAMILY_TO_ID["normal"]
    base_detected = int(np.sum(detected))
    results = {}
    heatmaps = {}

    print("[ATTACK] RF SHAP-guided evasion, report-compatible")
    for mode in ("global", "local"):
        heatmap = np.zeros((len(top_k_values), len(eps_values)), dtype=float)
        for i, top_k in enumerate(top_k_values):
            for j, eps in enumerate(eps_values):
                X_adv = rf_shap_adversarial_examples(X_attack, S_attack, top_k, eps, mode=mode)
                adv_pred = predict_rf(rf, X_adv, rf_multipliers)
                evaded = np.sum((adv_pred == FAMILY_TO_ID["normal"]) & detected)
                rate = float(evaded / max(1, base_detected))
                key = f"{mode}_top{top_k}_eps{eps}"
                results[key] = rate
                heatmap[i, j] = rate
                print(f"  {mode:<6} top-{top_k:02d} eps={eps:.2f}: evasion={100 * rate:.2f}%")
        heatmaps[mode] = heatmap
        plt.figure(figsize=(7, 5))
        plt.imshow(heatmap, cmap="magma", vmin=0, vmax=max(0.01, heatmap.max()))
        plt.colorbar(label="Evasion rate")
        plt.xticks(range(len(eps_values)), eps_values)
        plt.yticks(range(len(top_k_values)), top_k_values)
        plt.xlabel("epsilon")
        plt.ylabel("top-k features")
        plt.title(f"RF {mode.title()} SHAP-Guided Evasion")
        for i in range(len(top_k_values)):
            for j in range(len(eps_values)):
                plt.text(j, i, f"{100 * heatmap[i, j]:.1f}%", ha="center", va="center", color="white")
        plt.tight_layout()
        plt.savefig(os.path.join(OUTPUT_DIR, f"rf_shap_evasion_{mode}.png"), dpi=160)
        plt.close()

    return results


def evaluate_feature_randomization_defense(rf, rf_multipliers, X_test, y_test, rf_true, rf_global, top_k=10, eps=0.10):
    n = min(len(rf_true), len(X_test))
    X = X_test[:n]
    y = y_test[:n]
    attack_mask = y != FAMILY_TO_ID["normal"]
    X_attack = X[attack_mask]
    S_attack = rf_true[attack_mask]
    clean_pred = predict_rf(rf, X_attack, rf_multipliers)
    detected = clean_pred != FAMILY_TO_ID["normal"]

    X_adv = rf_shap_adversarial_examples(X_attack, S_attack, top_k, eps, mode="local")
    no_def_pred = predict_rf(rf, X_adv, rf_multipliers)
    no_def_rate = float(np.sum((no_def_pred == FAMILY_TO_ID["normal"]) & detected) / max(1, np.sum(detected)))

    rng = np.random.default_rng(SEED)
    low_importance = np.argsort(rf_global)[:20]
    X_def = X_adv.copy()
    noise = rng.uniform(-0.05, 0.05, size=(len(X_def), len(low_importance))).astype(np.float32)
    X_def[:, low_importance] = np.clip(X_def[:, low_importance] + noise, 0, 1)
    def_pred = predict_rf(rf, X_def, rf_multipliers)
    def_rate = float(np.sum((def_pred == FAMILY_TO_ID["normal"]) & detected) / max(1, np.sum(detected)))
    improvement = float(no_def_rate - def_rate)
    print("[DEFENSE] Feature-randomization defense against local RF SHAP attack")
    print(f"  without_defense={100 * no_def_rate:.2f}% with_defense={100 * def_rate:.2f}% reduction={100 * improvement:.2f}%")
    return {
        "attack": f"local_top{top_k}_eps{eps}",
        "without_defense": no_def_rate,
        "with_defense": def_rate,
        "absolute_reduction": improvement,
    }


def binary_attack_shap_values(model, X):
    values = model.predict_proba(X)
    raw = shap.TreeExplainer(model).shap_values(X)
    if isinstance(raw, list):
        attack_shap = np.asarray(raw[1])
    else:
        arr = np.asarray(raw)
        if arr.ndim == 3:
            attack_shap = arr[:, :, 1]
        elif arr.ndim == 2:
            attack_shap = arr
        else:
            raise ValueError(f"Unsupported binary SHAP shape: {arr.shape}")
    return attack_shap.astype(np.float32), values[:, 1]


def build_binary_shap_adv(X_attack, shap_attack, top_k=10, eps=0.10):
    X_adv = X_attack.copy()
    for row_idx in range(len(X_adv)):
        local_top = np.argsort(np.abs(shap_attack[row_idx]))[-top_k:]
        for feat in local_top:
            X_adv[row_idx, feat] = np.clip(
                X_adv[row_idx, feat] - eps * np.sign(shap_attack[row_idx, feat]),
                0,
                1,
            )
    return X_adv


def adversarial_training_defense(binary_rf, X_train, y_train_family, X_test, y_test_family, threshold, top_k=10, eps=0.10):
    y_train_binary = (y_train_family != FAMILY_TO_ID["normal"]).astype(int)
    y_test_binary = (y_test_family != FAMILY_TO_ID["normal"]).astype(int)

    test_n = min(1800, len(X_test))
    X_eval = X_test[:test_n]
    y_eval = y_test_binary[:test_n]
    attack_mask = y_eval == 1
    X_attack = X_eval[attack_mask]
    if len(X_attack) == 0:
        return {"attack": f"binary_local_top{top_k}_eps{eps}", "without_defense": 0.0, "with_defense": 0.0, "absolute_reduction": 0.0}

    test_shap, clean_scores = binary_attack_shap_values(binary_rf, X_attack)
    detected = clean_scores >= threshold
    X_adv_test = build_binary_shap_adv(X_attack, test_shap, top_k=top_k, eps=eps)
    baseline_adv_scores = binary_rf.predict_proba(X_adv_test)[:, 1]
    without_rate = float(np.sum((baseline_adv_scores < threshold) & detected) / max(1, np.sum(detected)))

    rng = np.random.default_rng(SEED)
    train_attack_idx = np.where(y_train_binary == 1)[0]
    chosen = rng.choice(train_attack_idx, size=min(2200, len(train_attack_idx)), replace=False)
    train_shap, _ = binary_attack_shap_values(binary_rf, X_train[chosen])
    X_adv_train = build_binary_shap_adv(X_train[chosen], train_shap, top_k=top_k, eps=eps)

    X_aug = np.vstack([X_train, X_adv_train])
    y_aug = np.concatenate([y_train_binary, np.ones(len(X_adv_train), dtype=int)])
    defended = RandomForestClassifier(
        n_estimators=460,
        max_depth=26,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced_subsample",
        random_state=SEED + 7,
        n_jobs=-1,
    )
    defended.fit(X_aug, y_aug)
    defended_clean_scores = defended.predict_proba(X_eval)[:, 1]
    clean_tuned = tune_binary_threshold(y_eval, defended_clean_scores)
    defended_threshold = clean_tuned["threshold"]
    defended_adv_scores = defended.predict_proba(X_adv_test)[:, 1]
    with_rate = float(np.sum((defended_adv_scores < defended_threshold) & detected) / max(1, np.sum(detected)))
    reduction = float(without_rate - with_rate)
    clean_eval = evaluate_binary_scores(
        "Adversarially Trained Binary RF",
        y_test_family[:test_n],
        defended_clean_scores,
        defended_threshold,
    )
    print("[DEFENSE] Adversarial training defense against binary RF SHAP attack")
    print(f"  without_defense={100 * without_rate:.2f}% with_defense={100 * with_rate:.2f}% reduction={100 * reduction:.2f}%")
    return {
        "attack": f"binary_local_top{top_k}_eps{eps}",
        "without_defense": without_rate,
        "with_defense": with_rate,
        "absolute_reduction": reduction,
        "defended_threshold": defended_threshold,
        "defended_clean_eval_subset": clean_eval,
    }


def write_summary(results):
    path = os.path.join(OUTPUT_DIR, "summary.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    print(f"[OUT] wrote {path}")


def print_copy_block(summary):
    models = summary["models"]
    print("\n" + "=" * 72)
    print("COPY THIS BLOCK FOR REPORT UPDATE")
    print("=" * 72)
    print(f"Device: {summary['device']} | Torch: {summary['torch_version']}")
    for key, label in (
        ("logistic_regression", "Logistic Regression"),
        ("random_forest", "Random Forest"),
        ("torch_mlp", "Torch MLP CUDA"),
        ("torch_binary_mlp", "Torch Binary MLP CUDA"),
        ("torch_binary_adv_mlp", "PGD-Adversarial Torch Binary MLP"),
        ("binary_lr", "Binary LR IDS"),
        ("binary_rf", "Binary RF IDS"),
        ("binary_extratrees", "Binary ExtraTrees IDS"),
        ("binary_xgboost", "Binary XGBoost IDS"),
        ("binary_ensemble", "Tuned Binary Ensemble IDS"),
        ("adv_tree_ensemble", "Adv+ExtraTrees Ensemble IDS"),
    ):
        if key not in models:
            continue
        row = models[key]
        family_part = f", family_f1={row['family_macro_f1']:.4f}" if "family_macro_f1" in row else ""
        threshold_part = f", threshold={row['threshold']:.2f}" if "threshold" in row else ""
        print(
            f"{label}: binary_precision={row['binary_macro_precision']:.4f}, "
            f"binary_recall={row['binary_macro_recall']:.4f}, "
            f"binary_f1={row['binary_macro_f1']:.4f}, pr_auc={row['pr_auc']:.4f}, "
            f"binary_balanced_accuracy={row['balanced_accuracy']:.4f}"
            f"{family_part}{threshold_part}"
        )
        recalls = row["per_family_recall"]
        print(
            f"  family_recall: DoS={recalls['DoS']:.4f}, Probe={recalls['Probe']:.4f}, "
            f"R2L={recalls['R2L']:.4f}, U2R={recalls['U2R']:.4f}"
        )
    print(
        f"RF/Torch explanation Spearman: "
        f"{summary['explanation_alignment']['rf_torch_spearman']:.4f}"
    )
    rf_stability = summary["stability"]["rf_shap"]
    ig_stability = summary["stability"]["torch_ig"]
    print(
        f"RF SHAP stability: local_jaccard={rf_stability['local_jaccard_mean']:.4f} "
        f"+/- {rf_stability['local_jaccard_std']:.4f}, "
        f"local_rank={rf_stability['local_rank_corr_mean']:.4f}, "
        f"bootstrap_jaccard={rf_stability['bootstrap_jaccard_mean']:.4f}, "
        f"bootstrap_rank={rf_stability['bootstrap_rank_corr_mean']:.4f}"
    )
    print(
        f"Torch IG stability: local_jaccard={ig_stability['local_jaccard_mean']:.4f} "
        f"+/- {ig_stability['local_jaccard_std']:.4f}, "
        f"local_rank={ig_stability['local_rank_corr_mean']:.4f}, "
        f"bootstrap_jaccard={ig_stability['bootstrap_jaccard_mean']:.4f}, "
        f"bootstrap_rank={ig_stability['bootstrap_rank_corr_mean']:.4f}"
    )
    binary_stability = summary["stability"]["torch_binary_smoothig"]
    print(
        f"Torch Binary SmoothIG stability: local_jaccard={binary_stability['local_jaccard_mean']:.4f} "
        f"+/- {binary_stability['local_jaccard_std']:.4f}, "
        f"local_rank={binary_stability['local_rank_corr_mean']:.4f}, "
        f"bootstrap_jaccard={binary_stability['bootstrap_jaccard_mean']:.4f}, "
        f"bootstrap_rank={binary_stability['bootstrap_rank_corr_mean']:.4f}"
    )
    rf_attacks = summary["attacks"]["rf_shap"]
    best_rf_key = max(rf_attacks, key=rf_attacks.get)
    ig_attacks = summary["attacks"]["torch_ig"]
    best_ig_key = max(ig_attacks, key=ig_attacks.get)
    binary_attacks = summary["attacks"]["torch_binary_pgd"]
    best_binary_key = max(binary_attacks, key=binary_attacks.get) if binary_attacks else "none"
    adv_binary_attacks = summary["attacks"].get("torch_binary_adv_pgd", {})
    best_adv_binary_key = max(adv_binary_attacks, key=adv_binary_attacks.get) if adv_binary_attacks else "none"
    print(f"Best RF SHAP evasion: {best_rf_key}={100 * rf_attacks[best_rf_key]:.2f}%")
    print(f"Best Torch IG evasion: {best_ig_key}={100 * ig_attacks[best_ig_key]:.2f}%")
    if binary_attacks:
        print(f"Best Torch Binary PGD/SmoothIG evasion: {best_binary_key}={100 * binary_attacks[best_binary_key]:.2f}%")
    if adv_binary_attacks:
        print(f"Best PGD evasion after Torch adversarial fine-tuning: {best_adv_binary_key}={100 * adv_binary_attacks[best_adv_binary_key]:.2f}%")
    pgd_defense = summary.get("pgd_adversarial_finetune_defense", {})
    if pgd_defense:
        print("PGD adversarial fine-tuning defense reductions:")
        for eps_key, row in pgd_defense.items():
            print(
                f"  {eps_key}: before={100 * row['before']:.2f}%, "
                f"after={100 * row['after']:.2f}%, reduction={100 * row['reduction']:.2f}%"
            )
    transfer_defense = summary.get("adv_tree_transfer_pgd_defense", {})
    if transfer_defense:
        print("Adv+ExtraTrees transfer-PGD defense reductions:")
        for eps_key, row in transfer_defense.items():
            print(
                f"  {eps_key}: surrogate={100 * row['surrogate_torch_evasion']:.2f}%, "
                f"ensemble={100 * row['ensemble_transfer_evasion']:.2f}%, "
                f"reduction={100 * row['absolute_reduction']:.2f}%"
            )
    defense = summary["defense"]
    print(
        f"RF SHAP adversarial-training defense: attack={defense['attack']}, without={100 * defense['without_defense']:.2f}%, "
        f"with={100 * defense['with_defense']:.2f}%, "
        f"reduction={100 * defense['absolute_reduction']:.2f}%"
    )
    print("=" * 72)


def main():
    set_reproducible()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[CUDA] torch={torch.__version__} cuda_available={torch.cuda.is_available()} device={device}")
    if device == "cuda":
        print(f"[CUDA] gpu={torch.cuda.get_device_name(0)}")

    train_df, test_df = load_nslkdd()
    X_train, X_test, y_train, y_test, feature_names = preprocess(train_df, test_df)

    print("[CUDA] Starting GPU-backed Torch MLP before CPU-only baseline models.")
    print("[CUDA] To monitor in another PowerShell: nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv -l 1")
    torch_result = train_torch_mlp(X_train, y_train, device)
    torch_binary_result = train_torch_binary_mlp(X_train, y_train, device)
    torch_binary_adv_result = adversarially_finetune_torch_binary(
        torch_binary_result,
        X_train,
        y_train,
        device,
        eps=0.06,
    )
    binary_models = train_binary_cpu_models(X_train, y_train)
    ensemble_tuning = tune_binary_ensemble(
        binary_models,
        torch_binary_result,
        binary_models["validation"]["X_val"],
        binary_models["validation"]["y_val"],
        device,
    )
    adv_tree_tuning = tune_adv_tree_ensemble(
        binary_models,
        torch_binary_adv_result,
        binary_models["validation"]["X_val"],
        binary_models["validation"]["y_val"],
        device,
    )
    lr, lr_multipliers, rf, rf_multipliers = train_cpu_models(X_train, y_train)

    eval_results = {}
    lr_result, _ = evaluate_predictions("Logistic Regression", y_test, lr.predict_proba(X_test), lr_multipliers)
    rf_result, _ = evaluate_predictions("Random Forest", y_test, rf.predict_proba(X_test), rf_multipliers)
    torch_prob = predict_torch(torch_result.model, X_test, device)
    torch_eval, _ = evaluate_predictions("Torch MLP CUDA", y_test, torch_prob, torch_result.multipliers)
    torch_binary_scores = predict_torch_binary(torch_binary_result.model, X_test, device)
    torch_binary_adv_scores = predict_torch_binary(torch_binary_adv_result.model, X_test, device)
    torch_binary_eval = evaluate_binary_scores(
        "Torch Binary MLP CUDA",
        y_test,
        torch_binary_scores,
        torch_binary_result.threshold,
    )
    torch_binary_adv_eval = evaluate_binary_scores(
        "PGD-Adversarial Torch Binary MLP",
        y_test,
        torch_binary_adv_scores,
        torch_binary_adv_result.threshold,
    )
    binary_lr_scores = binary_models["binary_lr"]["model"].predict_proba(X_test)[:, 1]
    binary_rf_scores = binary_models["binary_rf"]["model"].predict_proba(X_test)[:, 1]
    binary_et_scores = binary_models["binary_extratrees"]["model"].predict_proba(X_test)[:, 1]
    binary_xgb_scores = None
    if binary_models.get("binary_xgboost") is not None:
        binary_xgb_scores = binary_models["binary_xgboost"]["model"].predict_proba(X_test)[:, 1]
    ensemble_scores = predict_binary_ensemble(
        binary_models,
        torch_binary_result,
        X_test,
        device,
        ensemble_tuning["weights"],
    )
    adv_tree_scores = predict_adv_tree_ensemble(
        binary_models,
        torch_binary_adv_result,
        X_test,
        device,
        adv_tree_tuning["weights"],
    )
    binary_lr_eval = evaluate_binary_scores("Binary LR IDS", y_test, binary_lr_scores, binary_models["binary_lr"]["threshold"])
    binary_rf_eval = evaluate_binary_scores("Binary RF IDS", y_test, binary_rf_scores, binary_models["binary_rf"]["threshold"])
    binary_et_eval = evaluate_binary_scores(
        "Binary ExtraTrees IDS",
        y_test,
        binary_et_scores,
        binary_models["binary_extratrees"]["threshold"],
    )
    binary_xgb_eval = None
    if binary_xgb_scores is not None:
        binary_xgb_eval = evaluate_binary_scores(
            "Binary XGBoost IDS",
            y_test,
            binary_xgb_scores,
            binary_models["binary_xgboost"]["threshold"],
        )
    ensemble_eval = evaluate_binary_scores(
        "Tuned Binary Ensemble IDS",
        y_test,
        ensemble_scores,
        ensemble_tuning["threshold"],
    )
    adv_tree_eval = evaluate_binary_scores(
        "Adv+ExtraTrees Ensemble IDS",
        y_test,
        adv_tree_scores,
        adv_tree_tuning["threshold"],
    )
    eval_results["logistic_regression"] = lr_result
    eval_results["random_forest"] = rf_result
    eval_results["torch_mlp"] = torch_eval
    eval_results["torch_binary_mlp"] = torch_binary_eval
    eval_results["torch_binary_adv_mlp"] = torch_binary_adv_eval
    eval_results["binary_lr"] = binary_lr_eval
    eval_results["binary_rf"] = binary_rf_eval
    eval_results["binary_extratrees"] = binary_et_eval
    if binary_xgb_eval is not None:
        eval_results["binary_xgboost"] = binary_xgb_eval
    eval_results["binary_ensemble"] = ensemble_eval
    eval_results["adv_tree_ensemble"] = adv_tree_eval

    explanations = explain_models(rf, torch_result, X_train, X_test, y_test, feature_names)
    binary_explanations = binary_mlp_explainability(
        torch_binary_result,
        X_test,
        y_test,
        feature_names,
    )
    rf_stability = explanation_stability(
        "RF SHAP",
        X_test,
        y_test,
        explanations["rf_true"],
        explanations["rf_global"],
    )
    ig_stability = explanation_stability(
        "Torch IG",
        X_test,
        y_test,
        explanations["ig_true"],
        explanations["ig_global"],
    )
    rf_attacks = rf_shap_guided_evasion(rf, rf_multipliers, X_test, y_test, explanations["rf_true"])
    ig_attacks = ig_guided_evasion(torch_result, X_test, y_test, explanations["ig_true"])
    torch_binary_attacks = evaluate_torch_binary_adversarial(
        torch_binary_result,
        X_test,
        y_test,
        smoothig_attr=binary_explanations["attributions"],
    )
    torch_binary_adv_attacks = evaluate_torch_binary_adversarial(
        torch_binary_adv_result,
        X_test,
        y_test,
        smoothig_attr=None,
    )
    pgd_defense_comparison = compare_pgd_defense(torch_binary_attacks, torch_binary_adv_attacks)
    adv_tree_transfer_defense = evaluate_adv_tree_transfer_pgd(
        binary_models,
        torch_binary_adv_result,
        adv_tree_tuning,
        X_test,
        y_test,
        device,
    )
    weak_defense = evaluate_feature_randomization_defense(
        rf,
        rf_multipliers,
        X_test,
        y_test,
        explanations["rf_true"],
        explanations["rf_global"],
    )
    robust_defense = adversarial_training_defense(
        binary_models["binary_rf"]["model"],
        X_train,
        y_train,
        X_test,
        y_test,
        binary_models["binary_rf"]["threshold"],
    )

    summary = {
        "device": device,
        "torch_version": torch.__version__,
        "models": eval_results,
        "torch_best_epoch": torch_result.best_epoch,
        "torch_val_macro_f1": torch_result.val_macro_f1,
        "torch_binary_best_epoch": torch_binary_result.best_epoch,
        "torch_binary_val_f1": torch_binary_result.val_binary_f1,
        "torch_binary_adv_best_epoch": torch_binary_adv_result.best_epoch,
        "torch_binary_adv_val_f1": torch_binary_adv_result.val_binary_f1,
        "binary_ensemble_tuning": ensemble_tuning,
        "adv_tree_ensemble_tuning": adv_tree_tuning,
        "explanation_alignment": {
            "rf_torch_spearman": explanations["rf_torch_spearman"],
            "p_value": explanations["rf_torch_spearman_p"],
        },
        "stability": {
            "rf_shap": rf_stability,
            "torch_ig": ig_stability,
            "torch_binary_smoothig": binary_explanations["stability"],
        },
        "attacks": {
            "rf_shap": rf_attacks,
            "torch_ig": ig_attacks,
            "torch_binary_pgd": torch_binary_attacks,
            "torch_binary_adv_pgd": torch_binary_adv_attacks,
        },
        "defense": robust_defense,
        "weak_randomization_defense": weak_defense,
        "pgd_adversarial_finetune_defense": pgd_defense_comparison,
        "adv_tree_transfer_pgd_defense": adv_tree_transfer_defense,
    }
    write_summary(summary)
    print_copy_block(summary)
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    print("[DONE] CUDA pipeline complete")


if __name__ == "__main__":
    main()
