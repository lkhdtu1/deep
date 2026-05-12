"""
Project 5 — Explainable IDS
ICCN-INE2 | NSL-KDD Dataset

Main pipeline: preprocessing → training → evaluation → explainability → adversarial analysis
Run: python pipeline.py

Requirements: pip install -r requirements.txt
"""

import os
os.environ.setdefault("MPLCONFIGDIR", os.path.join(os.getcwd(), "outputs", ".matplotlib"))

import base64
import gc
import json
import warnings

import lime
import lime.lime_tabular
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

from scipy.stats import spearmanr
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    auc,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
)
from sklearn.model_selection import ParameterGrid, train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import MinMaxScaler

warnings.filterwarnings("ignore")

# ─── REPRODUCIBILITY ──────────────────────────────────────────────────────────
SEED = 42
np.random.seed(SEED)
os.makedirs("outputs", exist_ok=True)
RF_N_JOBS = 1

# ─── LABELS / COLUMN NAMES ────────────────────────────────────────────────────
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
RARE_FAMILIES = {"R2L", "U2R"}
ATTACK_FAMILY_MAP = {
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS", "processtable": "DoS", "udpstorm": "DoS",
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe", "mscan": "Probe", "saint": "Probe",
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L", "phf": "R2L",
    "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L", "sendmail": "R2L",
    "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L", "xlock": "R2L",
    "xsnoop": "R2L", "worm": "R2L", "httptunnel": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
    "normal": "normal",
}

# ─── DATA LOADING ─────────────────────────────────────────────────────────────

def _download_file(url, destination):
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": "pipeline.py"})
    with urllib.request.urlopen(request) as response, open(destination, "wb") as handle:
        handle.write(response.read())


def _download_nslkdd_via_github_api(destination_names):
    import urllib.request

    repo_api = "https://api.github.com/repos/Jehuty4949/NSL_KDD"
    request = urllib.request.Request(
        f"{repo_api}/git/trees/master?recursive=1",
        headers={"User-Agent": "pipeline.py"},
    )
    with urllib.request.urlopen(request) as response:
        tree = json.load(response)["tree"]

    blob_by_name = {
        item["path"]: item["sha"]
        for item in tree
        if item.get("type") == "blob" and item["path"] in destination_names
    }
    missing = [name for name in destination_names if name not in blob_by_name]
    if missing:
        raise FileNotFoundError(f"Could not locate dataset files in GitHub API tree: {missing}")

    for filename in destination_names:
        blob_request = urllib.request.Request(
            f"{repo_api}/git/blobs/{blob_by_name[filename]}",
            headers={"User-Agent": "pipeline.py"},
        )
        with urllib.request.urlopen(blob_request) as response:
            blob = json.load(response)
        with open(filename, "wb") as handle:
            handle.write(base64.b64decode(blob["content"]))


def load_nslkdd(train_path="KDDTrain+.txt", test_path="KDDTest+.txt"):
    """Load NSL-KDD dataset. Download if missing and network is available."""
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("[INFO] Dataset files not found. Downloading NSL-KDD...")
        import urllib.error

        base = "https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/master/"
        try:
            _download_file(base + "KDDTrain+.txt", train_path)
            _download_file(base + "KDDTest+.txt", test_path)
        except (urllib.error.URLError, OSError):
            print("[INFO] Raw GitHub download failed, retrying via GitHub API...")
            try:
                _download_nslkdd_via_github_api([train_path, test_path])
            except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, ValueError) as api_exc:
                error = FileNotFoundError(
                    "NSL-KDD dataset files are missing and automatic download failed. "
                    f"Place 'KDDTrain+.txt' and 'KDDTest+.txt' in '{os.getcwd()}' "
                    "or rerun with working network access."
                )
                raise error from api_exc
        print("[INFO] Download complete.")

    train = pd.read_csv(train_path, header=None, names=COL_NAMES)
    test = pd.read_csv(test_path, header=None, names=COL_NAMES)
    train.drop("difficulty", axis=1, inplace=True)
    test.drop("difficulty", axis=1, inplace=True)

    print(f"[DATA] Train: {len(train)} rows | Test: {len(test)} rows")
    print(f"[DATA] Raw train label dist (top 10):\n{train['label'].value_counts().head(10)}\n")
    return train, test


# ─── PREPROCESSING / FEATURE ENGINEERING ─────────────────────────────────────

def clean_label(raw_label):
    return str(raw_label).strip().rstrip(".")


def map_attack_family(raw_label):
    label = clean_label(raw_label)
    return ATTACK_FAMILY_MAP.get(label, "normal")


def add_engineered_features(df):
    """Compact family-sensitive features to help subtle R2L/U2R patterns."""
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
    """Family labels + engineered features + OHE categoricals + MinMax scaling."""
    train_df = add_engineered_features(train_df)
    test_df = add_engineered_features(test_df)

    train_df["family"] = train_df["label"].map(map_attack_family)
    test_df["family"] = test_df["label"].map(map_attack_family)

    train_df["binary_label"] = (train_df["family"] != "normal").astype(int)
    test_df["binary_label"] = (test_df["family"] != "normal").astype(int)

    cat_cols = ["protocol_type", "service", "flag", "service_flag"]
    combined = pd.concat([train_df, test_df], axis=0, ignore_index=True)
    combined = pd.get_dummies(combined, columns=cat_cols)

    n_train = len(train_df)
    train_enc = combined.iloc[:n_train].copy()
    test_enc = combined.iloc[n_train:].copy()

    drop_cols = {"label", "family", "binary_label"}
    feature_cols = [c for c in train_enc.columns if c not in drop_cols]

    X_train = train_enc[feature_cols].to_numpy(dtype=np.float32)
    X_test = test_enc[feature_cols].to_numpy(dtype=np.float32)
    y_train_family = train_enc["family"].map(FAMILY_TO_ID).to_numpy()
    y_test_family = test_enc["family"].map(FAMILY_TO_ID).to_numpy()
    y_train_binary = train_enc["binary_label"].to_numpy()
    y_test_binary = test_enc["binary_label"].to_numpy()

    scaler = MinMaxScaler()
    X_train_sc = scaler.fit_transform(X_train).astype(np.float32, copy=False)
    X_test_sc = scaler.transform(X_test).astype(np.float32, copy=False)

    print(f"[PREP] Features: {len(feature_cols)} | Train: {X_train_sc.shape} | Test: {X_test_sc.shape}")
    print("[PREP] Train family distribution:")
    for family in FAMILY_ORDER:
        count = int(np.sum(y_train_family == FAMILY_TO_ID[family]))
        print(f"  {family:<6} {count}")

    return {
        "X_train": X_train_sc,
        "X_test": X_test_sc,
        "y_train_family": y_train_family,
        "y_test_family": y_test_family,
        "y_train_binary": y_train_binary,
        "y_test_binary": y_test_binary,
        "feature_names": feature_cols,
        "raw_test_labels": test_df["label"].astype(str).tolist(),
        "test_family_names": test_df["family"].tolist(),
        "scaler": scaler,
    }


# ─── SAMPLING / COST-SENSITIVE HELPERS ───────────────────────────────────────

def class_weights_from_labels(y):
    counts = pd.Series(y).value_counts().to_dict()
    n_classes = len(np.unique(y))
    total = len(y)
    return {cls: total / (n_classes * count) for cls, count in counts.items()}


def sample_weights_from_labels(y):
    weights = class_weights_from_labels(y)
    return np.array([weights[label] for label in y], dtype=float)


def oversample_minority_classes(X, y, min_count=1200, multiplier_cap=40):
    """Simple bootstrap oversampling without extra dependencies."""
    rng = np.random.RandomState(SEED)
    X_parts = [X]
    y_parts = [y]

    counts = pd.Series(y).value_counts().to_dict()
    for cls in sorted(counts):
        count = counts[cls]
        if count >= min_count:
            continue
        target = min(min_count, count * multiplier_cap)
        extra = target - count
        if extra <= 0:
            continue
        cls_idx = np.where(y == cls)[0]
        extra_idx = rng.choice(cls_idx, size=extra, replace=True)
        X_parts.append(X[extra_idx])
        y_parts.append(y[extra_idx])

    X_bal = np.vstack(X_parts)
    y_bal = np.concatenate(y_parts)
    shuffle_idx = rng.permutation(len(y_bal))
    return X_bal[shuffle_idx], y_bal[shuffle_idx]


def prediction_from_multipliers(probabilities, multipliers):
    adjusted = probabilities * np.asarray(multipliers, dtype=float)
    return np.argmax(adjusted, axis=1)


def tune_class_multipliers(y_true, probabilities):
    """Bias rare family probabilities upward when validation data supports it."""
    search_grid = {
        "DoS": [1.00, 1.05, 1.10],
        "Probe": [1.00, 1.15, 1.30],
        "R2L": [1.00, 1.75, 2.50, 3.50, 5.00],
        "U2R": [1.00, 2.00, 3.50, 5.00, 7.00],
    }

    best = None
    for params in ParameterGrid(search_grid):
        multipliers = np.ones(len(FAMILY_ORDER), dtype=float)
        for family, value in params.items():
            multipliers[FAMILY_TO_ID[family]] = value

        y_pred = prediction_from_multipliers(probabilities, multipliers)
        macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
        recalls = recall_score(y_true, y_pred, average=None, labels=np.arange(len(FAMILY_ORDER)), zero_division=0)
        rare_recall = float(np.mean([recalls[FAMILY_TO_ID["R2L"]], recalls[FAMILY_TO_ID["U2R"]]]))
        binary_pred = (y_pred != FAMILY_TO_ID["normal"]).astype(int)
        binary_true = (y_true != FAMILY_TO_ID["normal"]).astype(int)
        binary_f1 = f1_score(binary_true, binary_pred, average="macro", zero_division=0)

        combined_score = 0.50 * macro_f1 + 0.35 * rare_recall + 0.15 * binary_f1
        candidate = {
            "multipliers": multipliers,
            "combined_score": float(combined_score),
            "macro_f1": float(macro_f1),
            "rare_recall": rare_recall,
            "binary_f1": float(binary_f1),
        }
        if best is None or (
            candidate["combined_score"],
            candidate["macro_f1"],
            candidate["rare_recall"],
            candidate["binary_f1"],
        ) > (
            best["combined_score"],
            best["macro_f1"],
            best["rare_recall"],
            best["binary_f1"],
        ):
            best = candidate

    return best


# ─── TRAINING & EVALUATION ────────────────────────────────────────────────────

MODEL_GRIDS = {
    "Logistic Regression (baseline)": {
        "class": LogisticRegression,
        "params": [
            {"C": 0.7, "class_weight": "balanced"},
            {"C": 1.5, "class_weight": "balanced"},
        ],
    },
    "Random Forest": {
        "class": RandomForestClassifier,
        "params": [
            {"n_estimators": 180, "max_depth": 18, "min_samples_leaf": 1, "class_weight": "balanced_subsample"},
            {"n_estimators": 240, "max_depth": 22, "min_samples_leaf": 1, "class_weight": "balanced_subsample"},
        ],
    },
    "MLP": {
        "class": MLPClassifier,
        "params": [
            {"hidden_layer_sizes": (128, 64), "alpha": 1e-3, "learning_rate_init": 8e-4},
        ],
    },
}


def build_model(name, params):
    if name == "Logistic Regression (baseline)":
        return LogisticRegression(
            max_iter=1200,
            random_state=SEED,
            n_jobs=-1,
            **params,
        )
    if name == "Random Forest":
        return RandomForestClassifier(
            random_state=SEED,
            n_jobs=RF_N_JOBS,
            **params,
        )
    if name == "MLP":
        return MLPClassifier(
            activation="relu",
            solver="adam",
            max_iter=90,
            random_state=SEED,
            early_stopping=True,
            validation_fraction=0.1,
            **params,
        )
    raise ValueError(f"Unknown model name: {name}")


def split_train_validation(X_train, y_train):
    return train_test_split(
        X_train,
        y_train,
        test_size=0.2,
        random_state=SEED,
        stratify=y_train,
    )


def fit_model(name, params, X_fit, y_fit):
    model = build_model(name, params)
    if name == "MLP":
        X_model, y_model = oversample_minority_classes(X_fit, y_fit, min_count=1500, multiplier_cap=50)
        if len(X_model) > 40000:
            X_model, _, y_model, _ = train_test_split(
                X_model,
                y_model,
                train_size=40000,
                random_state=SEED,
                stratify=y_model,
            )
        model.fit(X_model, y_model)
        return model

    if name == "Random Forest":
        X_model, y_model = oversample_minority_classes(X_fit, y_fit, min_count=3000, multiplier_cap=80)
        weights = sample_weights_from_labels(y_model)
        model.fit(X_model, y_model, sample_weight=weights)
        return model

    weights = sample_weights_from_labels(y_fit)
    model.fit(X_fit, y_fit, sample_weight=weights)
    return model


def tune_and_train_models(X_train, y_train):
    print("\n[TRAIN] Validation split, hyperparameter search, and family-aware threshold tuning...")
    X_fit, X_val, y_fit, y_val = split_train_validation(X_train, y_train)

    trained = {}
    tuning_summary = {}
    for name, spec in MODEL_GRIDS.items():
        print(f"\n  → {name}")
        best = None
        X_search = X_fit
        y_search = y_fit
        if name == "Logistic Regression (baseline)" and len(X_fit) > 70000:
            X_search, _, y_search, _ = train_test_split(
                X_fit,
                y_fit,
                train_size=70000,
                random_state=SEED,
                stratify=y_fit,
            )
        if name == "Random Forest" and len(X_fit) > 80000:
            X_search, _, y_search, _ = train_test_split(
                X_fit,
                y_fit,
                train_size=80000,
                random_state=SEED,
                stratify=y_fit,
            )

        for idx, params in enumerate(spec["params"], start=1):
            print(f"     [{idx}/{len(spec['params'])}] params={params}", end=" ", flush=True)
            model = fit_model(name, params, X_search, y_search)
            val_prob = model.predict_proba(X_val)
            multiplier_result = tune_class_multipliers(y_val, val_prob)
            y_val_pred = prediction_from_multipliers(val_prob, multiplier_result["multipliers"])

            val_macro_f1 = f1_score(y_val, y_val_pred, average="macro", zero_division=0)
            val_rare_recall = multiplier_result["rare_recall"]
            val_binary_true = (y_val != FAMILY_TO_ID["normal"]).astype(int)
            val_binary_pred = (y_val_pred != FAMILY_TO_ID["normal"]).astype(int)
            val_binary_f1 = f1_score(val_binary_true, val_binary_pred, average="macro", zero_division=0)

            print(
                f"val_macro_F1={val_macro_f1:.4f} "
                f"val_rare_recall={val_rare_recall:.4f} "
                f"val_binary_F1={val_binary_f1:.4f}"
            )

            candidate = {
                "params": params,
                "multipliers": multiplier_result["multipliers"],
                "val_f1_macro": float(val_macro_f1),
                "val_rare_recall": float(val_rare_recall),
                "val_binary_f1": float(val_binary_f1),
            }
            if best is None or (
                candidate["val_f1_macro"],
                candidate["val_rare_recall"],
                candidate["val_binary_f1"],
            ) > (
                best["val_f1_macro"],
                best["val_rare_recall"],
                best["val_binary_f1"],
            ):
                best = candidate

            del model, val_prob, multiplier_result, y_val_pred
            gc.collect()

        print(f"     selected params={best['params']}")
        print(f"     class multipliers={dict(zip(FAMILY_ORDER, np.round(best['multipliers'], 2)))}")
        final_model = fit_model(name, best["params"], X_train, y_train)
        trained[name] = final_model
        tuning_summary[name] = best

    return trained, tuning_summary


def _family_rows(y_true, y_pred):
    rows = []
    recalls = recall_score(y_true, y_pred, average=None, labels=np.arange(len(FAMILY_ORDER)), zero_division=0)
    f1s = f1_score(y_true, y_pred, average=None, labels=np.arange(len(FAMILY_ORDER)), zero_division=0)
    for idx, family in enumerate(FAMILY_ORDER):
        rows.append({
            "family": family,
            "support": int(np.sum(y_true == idx)),
            "recall": float(recalls[idx]),
            "f1": float(f1s[idx]),
        })
    return rows


def evaluate_models(models, tuning_summary, X_test, y_test_family, y_test_binary):
    results = {}
    print("\n[EVAL] Classification Results")
    print("=" * 70)

    for name, model in models.items():
        probabilities = model.predict_proba(X_test)
        multipliers = tuning_summary[name]["multipliers"]
        y_pred_family = prediction_from_multipliers(probabilities, multipliers)
        y_pred_binary = (y_pred_family != FAMILY_TO_ID["normal"]).astype(int)
        y_prob_attack = 1.0 - probabilities[:, FAMILY_TO_ID["normal"]]

        precision_curve, recall_curve, _ = precision_recall_curve(y_test_binary, y_prob_attack)
        pr_auc = auc(recall_curve, precision_curve)
        family_macro_f1 = f1_score(y_test_family, y_pred_family, average="macro", zero_division=0)
        binary_macro_f1 = f1_score(y_test_binary, y_pred_binary, average="macro", zero_division=0)
        binary_macro_precision = precision_score(y_test_binary, y_pred_binary, average="macro", zero_division=0)
        binary_macro_recall = recall_score(y_test_binary, y_pred_binary, average="macro", zero_division=0)
        balanced_acc = balanced_accuracy_score(y_test_binary, y_pred_binary)
        family_metrics = _family_rows(y_test_family, y_pred_family)

        results[name] = {
            "family_f1_macro": float(family_macro_f1),
            "binary_f1_macro": float(binary_macro_f1),
            "pr_auc": float(pr_auc),
            "binary_macro_precision": float(binary_macro_precision),
            "binary_macro_recall": float(binary_macro_recall),
            "balanced_accuracy": float(balanced_acc),
            "y_pred_family": y_pred_family,
            "y_pred_binary": y_pred_binary,
            "y_prob_attack": y_prob_attack,
            "family_probabilities": probabilities,
            "confusion_matrix_family": confusion_matrix(y_test_family, y_pred_family, labels=np.arange(len(FAMILY_ORDER))),
            "family_metrics": family_metrics,
        }

        print(f"\n{name}")
        print("  Family-level classification report:")
        print(classification_report(y_test_family, y_pred_family, target_names=FAMILY_ORDER, zero_division=0))
        print(
            f"  Binary IDS view: macro_F1={binary_macro_f1:.4f} "
            f"PR-AUC={pr_auc:.4f} balanced_acc={balanced_acc:.4f}"
        )
        print("  Family recall / F1:")
        for row in family_metrics:
            print(f"    {row['family']:<6} support={row['support']:<5d} recall={row['recall']:.3f} f1={row['f1']:.3f}")

    return results


# ─── SHAP ANALYSIS ────────────────────────────────────────────────────────────

def shap_values_to_dict(shap_values):
    if isinstance(shap_values, list):
        return {idx: np.asarray(values) for idx, values in enumerate(shap_values)}
    if isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        return {idx: shap_values[:, :, idx] for idx in range(shap_values.shape[2])}
    raise ValueError(f"Unsupported SHAP output type: {type(shap_values)}")


def aggregate_attack_importance(shap_by_class):
    attack_ids = [FAMILY_TO_ID[name] for name in FAMILY_ORDER if name != "normal"]
    attack_arrays = [np.abs(shap_by_class[idx]) for idx in attack_ids]
    return np.mean(np.stack(attack_arrays, axis=0), axis=(0, 1))


def select_true_family_shap(shap_by_class, y_labels):
    selected = np.zeros((len(y_labels), next(iter(shap_by_class.values())).shape[1]))
    for cls_idx in range(len(FAMILY_ORDER)):
        mask = y_labels == cls_idx
        if np.any(mask):
            selected[mask] = shap_by_class[cls_idx][mask]
    return selected


def model_probability_function(model):
    return lambda X: model.predict_proba(X)


def shap_analysis(rf_model, mlp_model, X_train, X_test, y_test_family, feature_names):
    """TreeSHAP for multiclass RF, KernelSHAP for sklearn MLP, family-aware aggregation."""
    print("\n[SHAP] Computing SHAP values...")

    print("  → TreeSHAP (RF multiclass)...", end=" ", flush=True)
    tree_explainer = shap.TreeExplainer(rf_model)
    X_sub = X_test[:900]
    y_sub = y_test_family[:900]
    rf_shap_values = shap_values_to_dict(tree_explainer.shap_values(X_sub))
    rf_true_family_shap = select_true_family_shap(rf_shap_values, y_sub)
    rf_attack_importance = aggregate_attack_importance(rf_shap_values)
    print("done")

    top10_rf = np.argsort(rf_attack_importance)[-10:][::-1]
    print("\n  Top 10 features (RF SHAP, aggregated across attack families):")
    for rank, idx in enumerate(top10_rf, start=1):
        print(f"    {rank:2d}. {feature_names[idx]:<35} {rf_attack_importance[idx]:.4f}")

    print("\n  → KernelSHAP (MLP multiclass, subset 40 bg + 40 samples)...", end=" ", flush=True)
    background = shap.sample(X_train, 40, random_state=SEED)
    kernel_explainer = shap.KernelExplainer(model_probability_function(mlp_model), background)
    X_explain = X_test[:40]
    mlp_shap_values = shap_values_to_dict(kernel_explainer.shap_values(X_explain, nsamples=80))
    mlp_attack_importance = aggregate_attack_importance(mlp_shap_values)
    print("done")
    print("  Note: DeepSHAP is not a drop-in option for sklearn MLPClassifier, so this remains KernelSHAP.")

    corr, pval = spearmanr(rf_attack_importance, mlp_attack_importance)
    print(f"\n  SHAP Spearman rank correlation (RF vs MLP attack importance): {corr:.3f} (p={pval:.4f})")

    print("\n  → Saving SHAP beeswarm plot...", end=" ", flush=True)
    attack_only = y_sub != FAMILY_TO_ID["normal"]
    attack_feature_values = X_sub[attack_only]
    attack_explanations = rf_true_family_shap[attack_only]
    plt.figure(figsize=(10, 7))
    shap.summary_plot(
        attack_explanations,
        attack_feature_values,
        feature_names=feature_names,
        max_display=15,
        show=False,
    )
    plt.tight_layout()
    plt.savefig("outputs/shap_beeswarm_rf.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("saved to outputs/shap_beeswarm_rf.png")

    plot_importance_comparison(rf_attack_importance, mlp_attack_importance, feature_names, top10_rf)
    return {
        "rf_shap_by_class": rf_shap_values,
        "rf_true_family_shap": rf_true_family_shap,
        "rf_importance": rf_attack_importance,
        "mlp_importance": mlp_attack_importance,
        "top10_rf": top10_rf,
        "X_sub": X_sub,
        "y_sub": y_sub,
        "tree_explainer": tree_explainer,
        "rf_mlp_spearman": float(corr),
    }


def plot_importance_comparison(imp_rf, imp_mlp, feature_names, top_rf):
    top_feats = top_rf[:15]
    labels = [feature_names[i][:24] for i in top_feats]
    vals_rf = imp_rf[top_feats]
    vals_mlp = imp_mlp[top_feats]

    x = np.arange(len(labels))
    width = 0.35
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(x - width / 2, vals_rf, width, label="RF SHAP", color="#2E75B6", alpha=0.85)
    ax.bar(x + width / 2, vals_mlp, width, label="MLP SHAP", color="#E8A000", alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=9)
    ax.set_ylabel("Mean |SHAP value|")
    ax.set_title("Attack-Family Importance: RF vs MLP")
    ax.legend()
    plt.tight_layout()
    plt.savefig("outputs/shap_comparison.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → Saved outputs/shap_comparison.png")


# ─── LIME ANALYSIS ────────────────────────────────────────────────────────────

def lime_analysis(rf_model, X_train, X_test, y_test_family, rf_test_pred_family, feature_names, n_explain=80):
    print(f"\n[LIME] Computing LIME explanations for {n_explain} attack instances...")

    explainer = lime.lime_tabular.LimeTabularExplainer(
        X_train,
        feature_names=feature_names,
        class_names=FAMILY_ORDER,
        mode="classification",
        random_state=SEED,
    )

    attack_idx = np.where(y_test_family != FAMILY_TO_ID["normal"])[0][:n_explain]
    lime_importances = np.zeros((len(attack_idx), len(feature_names)))
    fidelities = []
    correctness = []

    for i, idx in enumerate(attack_idx):
        exp = explainer.explain_instance(
            X_test[idx], rf_model.predict_proba, num_features=len(feature_names)
        )
        target_class = int(rf_test_pred_family[idx])
        fidelities.append(float(getattr(exp, "score", np.nan)))
        correctness.append(int(rf_test_pred_family[idx] == y_test_family[idx]))
        for feat_idx, weight in exp.local_exp.get(target_class, []):
            lime_importances[i, feat_idx] = abs(weight)

    lime_global = np.mean(lime_importances, axis=0)
    top10_lime = np.argsort(lime_global)[-10:][::-1]
    correct_mask = np.array(correctness, dtype=bool)
    incorrect_mask = ~correct_mask

    correct_importance = np.mean(lime_importances[correct_mask], axis=0) if np.any(correct_mask) else np.zeros(len(feature_names))
    incorrect_importance = np.mean(lime_importances[incorrect_mask], axis=0) if np.any(incorrect_mask) else np.zeros(len(feature_names))

    print("\n  Top 10 features (LIME, predicted family explanations):")
    for rank, idx in enumerate(top10_lime, start=1):
        print(f"    {rank:2d}. {feature_names[idx]:<35} {lime_global[idx]:.4f}")

    mean_fidelity = float(np.nanmean(fidelities)) if fidelities else float("nan")
    print(f"  Mean local fidelity: {mean_fidelity:.3f}")
    print(f"  Explained attack samples: total={len(attack_idx)} correct={int(np.sum(correct_mask))} incorrect={int(np.sum(incorrect_mask))}")

    return {
        "global_importance": lime_global,
        "top10_lime": top10_lime,
        "mean_fidelity": mean_fidelity,
        "correct_importance": correct_importance,
        "incorrect_importance": incorrect_importance,
    }


# ─── STABILITY ANALYSIS ───────────────────────────────────────────────────────

def stability_analysis(X_test, y_test_family, shap_rf_true_family, top_k=10):
    print("\n[STABILITY] Explanation stability analysis...")

    attack_mask = y_test_family[:len(shap_rf_true_family)] != FAMILY_TO_ID["normal"]
    X_att = X_test[:len(shap_rf_true_family)][attack_mask][:500]
    y_att = y_test_family[:len(shap_rf_true_family)][attack_mask][:500]
    S_att = shap_rf_true_family[attack_mask][:500]

    from sklearn.metrics.pairwise import cosine_similarity

    cos_sim = cosine_similarity(X_att)
    np.fill_diagonal(cos_sim, -1.0)

    pairs = []
    for i in range(len(cos_sim)):
        candidate_order = np.argsort(cos_sim[i])[::-1]
        for j in candidate_order:
            if y_att[i] == y_att[j] and cos_sim[i, j] >= 0.88:
                if i < j:
                    pairs.append((i, j))
                break

    jaccard_scores = []
    rank_corrs = []
    for a, b in pairs[:220]:
        top_a = set(np.argsort(np.abs(S_att[a]))[-top_k:])
        top_b = set(np.argsort(np.abs(S_att[b]))[-top_k:])
        jaccard_scores.append(len(top_a & top_b) / len(top_a | top_b))
        corr, _ = spearmanr(np.abs(S_att[a]), np.abs(S_att[b]))
        if np.isfinite(corr):
            rank_corrs.append(corr)

    if not jaccard_scores:
        print("  No comparable same-family attack pairs found.")
        return {
            "local_jaccard_mean": 0.0,
            "local_rank_corr_mean": 0.0,
            "bootstrap_jaccard_mean": 0.0,
            "bootstrap_rank_corr_mean": 0.0,
        }

    mean_j = float(np.mean(jaccard_scores))
    std_j = float(np.std(jaccard_scores))
    mean_rank = float(np.mean(rank_corrs)) if rank_corrs else 0.0
    print(f"  Same-family nearest-neighbor attack pairs evaluated: {len(jaccard_scores)}")
    print(f"  SHAP Jaccard stability (top-{top_k}): {mean_j:.3f} ± {std_j:.3f}")
    print(f"  SHAP rank-correlation stability: {mean_rank:.3f}")

    rng = np.random.RandomState(SEED)
    global_imp = np.abs(S_att)
    boot_jaccards = []
    boot_corrs = []
    for _ in range(20):
        idx_a = rng.choice(len(global_imp), size=min(300, len(global_imp)), replace=True)
        idx_b = rng.choice(len(global_imp), size=min(300, len(global_imp)), replace=True)
        imp_a = np.mean(global_imp[idx_a], axis=0)
        imp_b = np.mean(global_imp[idx_b], axis=0)
        top_a = set(np.argsort(imp_a)[-top_k:])
        top_b = set(np.argsort(imp_b)[-top_k:])
        boot_jaccards.append(len(top_a & top_b) / len(top_a | top_b))
        corr, _ = spearmanr(imp_a, imp_b)
        if np.isfinite(corr):
            boot_corrs.append(corr)

    mean_boot_j = float(np.mean(boot_jaccards)) if boot_jaccards else 0.0
    mean_boot_corr = float(np.mean(boot_corrs)) if boot_corrs else 0.0
    print(f"  Bootstrap top-{top_k} Jaccard stability: {mean_boot_j:.3f}")
    print(f"  Bootstrap rank-correlation stability: {mean_boot_corr:.3f}")

    plt.figure(figsize=(8, 4))
    plt.hist(jaccard_scores, bins=20, color="#2E75B6", alpha=0.8, edgecolor="white")
    plt.axvline(mean_j, color="red", linestyle="--", label=f"Mean = {mean_j:.2f}")
    plt.xlabel(f"Jaccard Similarity of Top-{top_k} SHAP Features")
    plt.ylabel("Frequency")
    plt.title("SHAP Stability Across Similar Same-Family Attack Samples")
    plt.legend()
    plt.tight_layout()
    plt.savefig("outputs/shap_stability.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("  → Saved outputs/shap_stability.png")

    return {
        "local_jaccard_mean": mean_j,
        "local_rank_corr_mean": mean_rank,
        "bootstrap_jaccard_mean": mean_boot_j,
        "bootstrap_rank_corr_mean": mean_boot_corr,
    }


# ─── ADVERSARIAL ATTACK / DEFENSE ────────────────────────────────────────────

def build_local_adversarial_examples(X_attack, shap_attack, top_k, eps):
    X_adv = X_attack.copy()
    for row_idx in range(len(X_adv)):
        local_top = np.argsort(np.abs(shap_attack[row_idx]))[-top_k:]
        for feat in local_top:
            direction = -np.sign(shap_attack[row_idx, feat])
            X_adv[row_idx, feat] = np.clip(X_adv[row_idx, feat] + direction * eps, 0.0, 1.0)
    return X_adv


def build_global_adversarial_examples(X_attack, shap_attack, top_k, eps):
    X_adv = X_attack.copy()
    global_importance = np.mean(np.abs(shap_attack), axis=0)
    top_feats = np.argsort(global_importance)[-top_k:]
    for feat in top_feats:
        direction = -np.sign(np.mean(shap_attack[:, feat]))
        X_adv[:, feat] = np.clip(X_adv[:, feat] + direction * eps, 0.0, 1.0)
    return X_adv


def predict_family(model, tuning_summary, X):
    probabilities = model.predict_proba(X)
    return prediction_from_multipliers(probabilities, tuning_summary["multipliers"])


def shap_guided_attack(rf_model, rf_tuning_summary, X_test, y_test_family, shap_rf_true_family, epsilons=None):
    if epsilons is None:
        epsilons = [0.03, 0.05, 0.10]

    print("\n[ATTACK] SHAP-guided adversarial evasion attack...")

    n = min(len(shap_rf_true_family), len(X_test))
    mask = y_test_family[:n] != FAMILY_TO_ID["normal"]
    X_att = X_test[:n][mask].copy()
    S_att = shap_rf_true_family[mask]

    if len(X_att) == 0:
        print("  No attack samples available for adversarial evaluation.")
        return {}

    results = {}
    for mode in ["global", "local"]:
        for top_k in [5, 10, 15]:
            for eps in epsilons:
                if mode == "global":
                    X_adv = build_global_adversarial_examples(X_att, S_att, top_k, eps)
                else:
                    X_adv = build_local_adversarial_examples(X_att, S_att, top_k, eps)

                preds = predict_family(rf_model, rf_tuning_summary, X_adv)
                evasion = np.mean(preds == FAMILY_TO_ID["normal"])
                key = f"{mode}_top{top_k}_eps{eps}"
                results[key] = float(evasion)
                print(f"  {mode:>6} top-{top_k}, eps={eps:.2f}: evasion to normal = {evasion:.2%}")

    plot_evasion_heatmap(results, epsilons, mode="global")
    plot_evasion_heatmap(results, epsilons, mode="local", filename="outputs/evasion_heatmap_local.png")
    return results


def plot_evasion_heatmap(results, epsilons, mode="global", filename="outputs/evasion_heatmap.png"):
    top_ks = [5, 10, 15]
    matrix = np.array([[results[f"{mode}_top{k}_eps{e}"] for e in epsilons] for k in top_ks])

    fig, ax = plt.subplots(figsize=(7, 4))
    im = ax.imshow(matrix, cmap="Reds", vmin=0, vmax=1)
    ax.set_xticks(range(len(epsilons)))
    ax.set_yticks(range(len(top_ks)))
    ax.set_xticklabels([f"eps={e}" for e in epsilons])
    ax.set_yticklabels([f"Top-{k}" for k in top_ks])
    ax.set_xlabel("Perturbation Magnitude")
    ax.set_ylabel("Features Perturbed")
    ax.set_title(f"Evasion Rate — {mode.title()} SHAP-Guided Attack")
    for i in range(len(top_ks)):
        for j in range(len(epsilons)):
            ax.text(
                j,
                i,
                f"{matrix[i, j]:.0%}",
                ha="center",
                va="center",
                color="white" if matrix[i, j] > 0.5 else "black",
                fontsize=12,
            )
    plt.colorbar(im, ax=ax, label="Evasion Rate")
    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  → Saved {filename}")


def train_adversarial_defense(base_model_params, X_train, y_train_family, teacher_model, teacher_explainer, top_k=10, eps=0.05):
    """Augment training attacks with SHAP-guided perturbations and retrain RF."""
    attack_idx = np.where(y_train_family != FAMILY_TO_ID["normal"])[0]
    subset_size = min(18000, len(attack_idx))
    subset_idx = attack_idx[:subset_size]
    X_attack = X_train[subset_idx]
    y_attack = y_train_family[subset_idx]

    teacher_shap = shap_values_to_dict(teacher_explainer.shap_values(X_attack))
    local_teacher_shap = select_true_family_shap(teacher_shap, y_attack)
    X_adv = build_local_adversarial_examples(X_attack, local_teacher_shap, top_k=top_k, eps=eps)

    X_aug = np.vstack([X_train, X_adv])
    y_aug = np.concatenate([y_train_family, y_attack])
    X_aug, y_aug = oversample_minority_classes(X_aug, y_aug, min_count=1800, multiplier_cap=50)

    rf_params = {
        key: base_model_params[key]
        for key in ["n_estimators", "max_depth", "min_samples_leaf", "class_weight"]
    }
    robust_rf = build_model("Random Forest", rf_params)
    robust_rf.fit(X_aug, y_aug, sample_weight=sample_weights_from_labels(y_aug))
    return robust_rf


def evaluate_defense(rf_model, rf_tuning_summary, X_train, y_train_family, X_test, y_test_family, shap_results, top_k=10, eps=0.05):
    print("\n[DEFENSE] Evaluating SHAP-guided adversarial training defense...")

    robust_rf = train_adversarial_defense(
        base_model_params=rf_model.get_params(deep=False),
        X_train=X_train,
        y_train_family=y_train_family,
        teacher_model=rf_model,
        teacher_explainer=shap_results["tree_explainer"],
        top_k=top_k,
        eps=eps,
    )

    n = min(len(shap_results["rf_true_family_shap"]), len(X_test))
    mask = y_test_family[:n] != FAMILY_TO_ID["normal"]
    X_att = X_test[:n][mask].copy()
    S_att = shap_results["rf_true_family_shap"][mask]
    X_adv = build_local_adversarial_examples(X_att, S_att, top_k=top_k, eps=eps)

    preds_base = predict_family(rf_model, rf_tuning_summary, X_adv)
    preds_robust = predict_family(
        robust_rf,
        {"multipliers": rf_tuning_summary["multipliers"]},
        X_adv,
    )

    er_base = float(np.mean(preds_base == FAMILY_TO_ID["normal"]))
    er_robust = float(np.mean(preds_robust == FAMILY_TO_ID["normal"]))
    reduction = float((er_base - er_robust) / max(er_base, 1e-9))

    print(f"  Evasion rate WITHOUT defense: {er_base:.2%}")
    print(f"  Evasion rate WITH defense:    {er_robust:.2%}")
    print(f"  Defense effectiveness:       {reduction:.1%} reduction in evasion")

    return {
        "evasion_without_defense": er_base,
        "evasion_with_defense": er_robust,
        "reduction": reduction,
        "robust_model": robust_rf,
    }


# ─── SUMMARY REPORT ───────────────────────────────────────────────────────────

def print_summary(eval_results, shap_results, lime_results, stability_results, attack_results, defense_results):
    print("\n" + "=" * 70)
    print("FINAL SUMMARY — Project 5: Explainable IDS")
    print("=" * 70)

    print("\n── Model Performance ──")
    for name, res in eval_results.items():
        print(
            f"  {name:<32} family_macro_F1={res['family_f1_macro']:.4f}  "
            f"binary_macro_F1={res['binary_f1_macro']:.4f}  PR-AUC={res['pr_auc']:.4f}"
        )
        family_line = ", ".join(
            f"{row['family']} recall={row['recall']:.3f}" for row in res["family_metrics"] if row["family"] != "normal"
        )
        print(f"    {family_line}")

    print("\n── Explanation Stability ──")
    print(f"  Local SHAP Jaccard: {stability_results['local_jaccard_mean']:.3f}")
    print(f"  Local SHAP rank correlation: {stability_results['local_rank_corr_mean']:.3f}")
    print(f"  Bootstrap SHAP Jaccard: {stability_results['bootstrap_jaccard_mean']:.3f}")
    print(f"  Bootstrap SHAP rank correlation: {stability_results['bootstrap_rank_corr_mean']:.3f}")

    print("\n── Explainability Quality ──")
    print(f"  RF/MLP SHAP Spearman alignment: {shap_results['rf_mlp_spearman']:.3f}")
    print(f"  LIME mean local fidelity: {lime_results['mean_fidelity']:.3f}")

    print("\n── Adversarial Attack ──")
    if attack_results:
        for key, value in sorted(attack_results.items()):
            print(f"  {key:<24}: evasion={value:.2%}")
    else:
        print("  No adversarial results were produced.")

    print("\n── Defense ──")
    print(f"  Without defense: {defense_results['evasion_without_defense']:.2%}")
    print(f"  With defense:    {defense_results['evasion_with_defense']:.2%}")
    print(f"  Reduction:       {defense_results['reduction']:.1%}")

    print("\nOutputs saved to ./outputs/")
    print("=" * 70)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("Project 5: Explainable IDS — Family-Aware Pipeline")
    print("=" * 70)

    train_df, test_df = load_nslkdd()
    prep = preprocess(train_df, test_df)

    models, tuning_summary = tune_and_train_models(
        prep["X_train"],
        prep["y_train_family"],
    )

    eval_results = evaluate_models(
        models,
        tuning_summary,
        prep["X_test"],
        prep["y_test_family"],
        prep["y_test_binary"],
    )

    rf = models["Random Forest"]
    mlp = models["MLP"]
    shap_results = shap_analysis(
        rf,
        mlp,
        prep["X_train"],
        prep["X_test"],
        prep["y_test_family"],
        prep["feature_names"],
    )

    lime_results = lime_analysis(
        rf,
        prep["X_train"],
        prep["X_test"],
        prep["y_test_family"],
        eval_results["Random Forest"]["y_pred_family"],
        prep["feature_names"],
    )

    stability_results = stability_analysis(
        prep["X_test"],
        prep["y_test_family"],
        shap_results["rf_true_family_shap"],
    )

    attack_results = shap_guided_attack(
        rf,
        tuning_summary["Random Forest"],
        prep["X_test"],
        prep["y_test_family"],
        shap_results["rf_true_family_shap"],
    )

    defense_results = evaluate_defense(
        rf,
        tuning_summary["Random Forest"],
        prep["X_train"],
        prep["y_train_family"],
        prep["X_test"],
        prep["y_test_family"],
        shap_results,
    )

    print_summary(
        eval_results,
        shap_results,
        lime_results,
        stability_results,
        attack_results,
        defense_results,
    )


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
