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
import json
import numpy as np
import pandas as pd
import shap
import lime
import lime.lime_tabular
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.preprocessing import MinMaxScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import ParameterGrid, train_test_split
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
from scipy.stats import spearmanr

import warnings
warnings.filterwarnings('ignore')

# ─── REPRODUCIBILITY ──────────────────────────────────────────────────────────
SEED = 42
np.random.seed(SEED)
os.makedirs('outputs', exist_ok=True)

# ─── COLUMN NAMES ─────────────────────────────────────────────────────────────
COL_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_hot_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# ─── DATA LOADING ─────────────────────────────────────────────────────────────

def _download_file(url, destination):
    """Download a file with a basic User-Agent for GitHub endpoints."""
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": "pipeline.py"})
    with urllib.request.urlopen(request) as response, open(destination, "wb") as handle:
        handle.write(response.read())


def _download_nslkdd_via_github_api(destination_names):
    """Fallback download path that avoids raw.githubusercontent.com."""
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


def load_nslkdd(train_path='KDDTrain+.txt', test_path='KDDTest+.txt'):
    """Load NSL-KDD dataset. Download if missing and network is available."""
    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print("[INFO] Dataset files not found. Downloading NSL-KDD...")
        import urllib.error
        base = "https://raw.githubusercontent.com/Jehuty4949/NSL_KDD/master/"
        try:
            _download_file(base + "KDDTrain+.txt", train_path)
            _download_file(base + "KDDTest+.txt", test_path)
        except (urllib.error.URLError, OSError) as exc:
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
    test  = pd.read_csv(test_path,  header=None, names=COL_NAMES)

    # Drop difficulty column
    train.drop('difficulty', axis=1, inplace=True)
    test.drop('difficulty',  axis=1, inplace=True)

    print(f"[DATA] Train: {len(train)} rows | Test: {len(test)} rows")
    print(f"[DATA] Train label dist:\n{train['label'].value_counts().head(10)}\n")
    return train, test


# ─── PREPROCESSING ─────────────────────────────────────────────────────────────

def preprocess(train_df, test_df):
    """Binary label + OHE categoricals + MinMax scaling."""
    for df in [train_df, test_df]:
        df['label'] = df['label'].astype(str).str.strip().apply(
            lambda x: 0 if x.rstrip('.') == 'normal' else 1
        )

    # One-hot encode categorical columns
    cat_cols = ['protocol_type', 'service', 'flag']
    combined = pd.concat([train_df, test_df], axis=0)
    combined = pd.get_dummies(combined, columns=cat_cols)

    n_train = len(train_df)
    train_enc = combined.iloc[:n_train].copy()
    test_enc  = combined.iloc[n_train:].copy()

    feature_cols = [c for c in train_enc.columns if c != 'label']
    X_train = train_enc[feature_cols].values.astype(float)
    y_train = train_enc['label'].values
    X_test  = test_enc[feature_cols].values.astype(float)
    y_test  = test_enc['label'].values

    # Normalize
    scaler = MinMaxScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    print(f"[PREP] Features: {len(feature_cols)} | Train: {X_train_sc.shape} | Test: {X_test_sc.shape}")
    return X_train_sc, y_train, X_test_sc, y_test, feature_cols, scaler


# ─── TRAINING & EVALUATION ────────────────────────────────────────────────────

MODEL_GRIDS = {
    'Logistic Regression (baseline)': {
        'class': LogisticRegression,
        'params': [
            {'C': 0.5, 'class_weight': None},
            {'C': 1.0, 'class_weight': None},
            {'C': 1.0, 'class_weight': 'balanced'},
            {'C': 2.0, 'class_weight': 'balanced'},
        ],
    },
    'Random Forest': {
        'class': RandomForestClassifier,
        'params': [
            {'n_estimators': 150, 'max_depth': 15, 'min_samples_leaf': 1, 'class_weight': None},
            {'n_estimators': 200, 'max_depth': 20, 'min_samples_leaf': 1, 'class_weight': None},
            {'n_estimators': 200, 'max_depth': 20, 'min_samples_leaf': 2, 'class_weight': 'balanced_subsample'},
        ],
    },
    'MLP': {
        'class': MLPClassifier,
        'params': [
            {'hidden_layer_sizes': (64, 32), 'alpha': 1e-4, 'learning_rate_init': 1e-3},
            {'hidden_layer_sizes': (128, 64), 'alpha': 1e-3, 'learning_rate_init': 1e-3},
        ],
    },
}


def build_model(name, params):
    """Create a model instance from a tuned parameter set."""
    if name == 'Logistic Regression (baseline)':
        return LogisticRegression(
            max_iter=1000,
            random_state=SEED,
            n_jobs=-1,
            **params,
        )
    if name == 'Random Forest':
        return RandomForestClassifier(
            random_state=SEED,
            n_jobs=-1,
            **params,
        )
    if name == 'MLP':
        return MLPClassifier(
            activation='relu',
            max_iter=80,
            random_state=SEED,
            early_stopping=True,
            validation_fraction=0.1,
            **params,
        )
    raise ValueError(f"Unknown model name: {name}")


def split_train_validation(X_train, y_train):
    """Create a validation split for model/threshold selection."""
    return train_test_split(
        X_train,
        y_train,
        test_size=0.2,
        random_state=SEED,
        stratify=y_train,
    )


def find_best_threshold(y_true, y_prob):
    """Choose threshold that maximizes macro F1 on validation data."""
    thresholds = np.linspace(0.05, 0.95, 37)
    best_threshold = 0.5
    best_score = -1.0
    for threshold in thresholds:
        y_pred = (y_prob >= threshold).astype(int)
        score = f1_score(y_true, y_pred, average='macro')
        if score > best_score:
            best_score = score
            best_threshold = float(threshold)
    return best_threshold, best_score


def tune_and_train_models(X_train, y_train):
    """Tune each model on a validation split, then refit on the full training data."""
    print("\n[TRAIN] Validation split, hyperparameter search, and threshold tuning...")
    X_fit, X_val, y_fit, y_val = split_train_validation(X_train, y_train)

    trained = {}
    tuning_summary = {}
    for name, spec in MODEL_GRIDS.items():
        print(f"\n  → {name}")
        X_fit_model, y_fit_model = X_fit, y_fit
        X_train_model, y_train_model = X_train, y_train
        if name == 'MLP' and len(X_fit) > 40000:
            X_fit_model, _, y_fit_model, _ = train_test_split(
                X_fit,
                y_fit,
                train_size=40000,
                random_state=SEED,
                stratify=y_fit,
            )
            X_train_model, _, y_train_model, _ = train_test_split(
                X_train,
                y_train,
                train_size=50000,
                random_state=SEED,
                stratify=y_train,
            )
            print(f"     using stratified subset for MLP: tune={len(X_fit_model)} train={len(X_train_model)}")

        best = None
        for idx, params in enumerate(spec['params'], start=1):
            model = build_model(name, params)
            print(f"     [{idx}/{len(spec['params'])}] params={params}", end=' ', flush=True)
            model.fit(X_fit_model, y_fit_model)
            y_val_prob = model.predict_proba(X_val)[:, 1]
            threshold, val_f1 = find_best_threshold(y_val, y_val_prob)
            val_pr_auc = average_precision_score(y_val, y_val_prob)
            print(f"val_macro_F1={val_f1:.4f} val_PR-AUC={val_pr_auc:.4f} thr={threshold:.2f}")

            candidate = {
                'params': params,
                'threshold': threshold,
                'val_f1_macro': val_f1,
                'val_pr_auc': val_pr_auc,
            }
            if best is None or (val_f1, val_pr_auc) > (best['val_f1_macro'], best['val_pr_auc']):
                best = candidate

        final_model = build_model(name, best['params'])
        print(f"     selected params={best['params']} | threshold={best['threshold']:.2f}")
        final_model.fit(X_train_model, y_train_model)
        trained[name] = final_model
        tuning_summary[name] = best

    return trained, tuning_summary


def _extract_attack_family_metrics(raw_labels, y_true, y_pred):
    """Summarize attack recall by original attack family."""
    cleaned = pd.Series(raw_labels).astype(str).str.strip().str.rstrip('.')
    family_map = {
        'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS', 'smurf': 'DoS',
        'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 'processtable': 'DoS', 'udpstorm': 'DoS',
        'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe', 'mscan': 'Probe', 'saint': 'Probe',
        'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L', 'phf': 'R2L',
        'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L', 'sendmail': 'R2L',
        'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'xlock': 'R2L',
        'xsnoop': 'R2L', 'worm': 'R2L', 'httptunnel': 'R2L',
        'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
        'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
        'normal': 'normal',
    }

    rows = []
    for family in ['DoS', 'Probe', 'R2L', 'U2R']:
        mask = cleaned.map(family_map).eq(family).values
        if np.sum(mask) == 0:
            continue
        family_true = y_true[mask]
        family_pred = y_pred[mask]
        rows.append({
            'family': family,
            'support': int(np.sum(mask)),
            'attack_recall': float(np.mean(family_pred == family_true)),
        })
    return rows


def evaluate_models(models, tuning_summary, X_test, y_test, raw_test_labels):
    """Evaluate tuned models with threshold-aware predictions and richer metrics."""
    results = {}
    print("\n[EVAL] Classification Results")
    print("=" * 60)

    for name, model in models.items():
        threshold = tuning_summary[name]['threshold']
        y_prob = model.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= threshold).astype(int)

        precision_curve, recall_curve, _ = precision_recall_curve(y_test, y_prob)
        pr_auc = auc(recall_curve, precision_curve)
        f1 = f1_score(y_test, y_pred, average='macro')
        cm = confusion_matrix(y_test, y_pred)
        macro_precision = precision_score(y_test, y_pred, average='macro', zero_division=0)
        macro_recall = recall_score(y_test, y_pred, average='macro', zero_division=0)
        balanced_acc = balanced_accuracy_score(y_test, y_pred)
        family_metrics = _extract_attack_family_metrics(raw_test_labels, y_test, y_pred)

        results[name] = {
            'f1_macro': f1,
            'pr_auc': pr_auc,
            'macro_precision': macro_precision,
            'macro_recall': macro_recall,
            'balanced_accuracy': balanced_acc,
            'threshold': threshold,
            'y_pred': y_pred,
            'y_prob': y_prob,
            'confusion_matrix': cm,
            'family_metrics': family_metrics,
        }

        print(f"\n{name}")
        print(f"  Tuned threshold: {threshold:.2f}")
        print(classification_report(y_test, y_pred, target_names=['normal', 'attack']))
        print(f"  PR-AUC: {pr_auc:.4f}")
        print(f"  Balanced Accuracy: {balanced_acc:.4f}")
        if family_metrics:
            print("  Attack-family recall breakdown:")
            for row in family_metrics:
                print(f"    {row['family']:<5} support={row['support']:<5d} recall={row['attack_recall']:.3f}")

    return results


# ─── SHAP ANALYSIS ────────────────────────────────────────────────────────────

def _select_positive_class_shap(shap_values):
    """Normalize SHAP output across list and ndarray APIs for binary classification."""
    if isinstance(shap_values, list):
        return shap_values[1] if len(shap_values) > 1 else shap_values[0]
    if isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
        return shap_values[:, :, 1] if shap_values.shape[-1] > 1 else shap_values[:, :, 0]
    return shap_values

def shap_analysis(rf_model, mlp_model, X_train, X_test, feature_names):
    """SHAP explanations for RF (TreeSHAP) and MLP (KernelSHAP)."""
    print("\n[SHAP] Computing SHAP values...")

    # --- TreeSHAP for Random Forest ---
    print("  → TreeSHAP (RF)...", end=' ', flush=True)
    tree_explainer = shap.TreeExplainer(rf_model)
    # Use subset for speed and reproducibility.
    X_sub = X_test[:2500]
    shap_vals_rf = tree_explainer.shap_values(X_sub)
    shap_attack = _select_positive_class_shap(shap_vals_rf)
    print("done")

    rf_global_importance = np.mean(np.abs(shap_attack), axis=0)
    top10_rf = np.argsort(rf_global_importance)[-10:][::-1]

    print("\n  Top 10 features (RF SHAP):")
    for rank, idx in enumerate(top10_rf):
        print(f"    {rank+1:2d}. {feature_names[idx]:<35} {rf_global_importance[idx]:.4f}")

    # --- KernelSHAP for MLP ---
    print("\n  → KernelSHAP (MLP, subset 100 bg + 120 samples)...", end=' ', flush=True)
    background = shap.sample(X_train, 100, random_state=SEED)
    kernel_explainer = shap.KernelExplainer(mlp_model.predict_proba, background)
    X_explain = X_test[:120]
    shap_vals_mlp = kernel_explainer.shap_values(X_explain, nsamples=200)
    shap_mlp_attack = _select_positive_class_shap(shap_vals_mlp)
    print("done")

    mlp_global_importance = np.mean(np.abs(shap_mlp_attack), axis=0)
    top10_mlp = np.argsort(mlp_global_importance)[-10:][::-1]

    # Spearman rank correlation between RF and MLP explanations
    # Align on same feature subset
    n_feats = min(len(rf_global_importance), len(mlp_global_importance))
    corr, pval = spearmanr(rf_global_importance[:n_feats], mlp_global_importance[:n_feats])
    print(f"\n  SHAP Spearman rank correlation (RF vs MLP): {corr:.3f} (p={pval:.4f})")

    # Plot beeswarm for RF
    print("\n  → Saving SHAP beeswarm plot...", end=' ', flush=True)
    plt.figure(figsize=(10, 7))
    shap.summary_plot(shap_attack, X_sub,
                      feature_names=feature_names,
                      max_display=15, show=False)
    plt.tight_layout()
    plt.savefig('outputs/shap_beeswarm_rf.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("saved to outputs/shap_beeswarm_rf.png")

    # Bar importance comparison
    _plot_importance_comparison(rf_global_importance, mlp_global_importance,
                                 feature_names, top10_rf)

    return {
        'shap_rf': shap_attack,
        'shap_mlp': shap_mlp_attack,
        'rf_importance': rf_global_importance,
        'mlp_importance': mlp_global_importance,
        'top10_rf': top10_rf,
        'X_sub': X_sub,
        'tree_explainer': tree_explainer,
    }


def _plot_importance_comparison(imp_rf, imp_mlp, feature_names, top10_rf):
    """Bar chart: RF SHAP vs MLP SHAP top-15."""
    top_feats = top10_rf[:15]
    labels = [feature_names[i][:20] for i in top_feats]
    vals_rf  = imp_rf[top_feats]
    # Align MLP to same features
    vals_mlp = imp_mlp[top_feats] if len(imp_mlp) > max(top_feats) else np.zeros(len(top_feats))

    x = np.arange(len(labels))
    w = 0.35
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.bar(x - w/2, vals_rf,  w, label='RF SHAP',  color='#2E75B6', alpha=0.85)
    ax.bar(x + w/2, vals_mlp, w, label='MLP SHAP', color='#E8A000', alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
    ax.set_ylabel('Mean |SHAP value|')
    ax.set_title('Feature Importance: RF vs MLP (SHAP)')
    ax.legend()
    plt.tight_layout()
    plt.savefig('outputs/shap_comparison.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("  → Saved outputs/shap_comparison.png")


# ─── LIME ANALYSIS ────────────────────────────────────────────────────────────

def lime_analysis(rf_model, X_train, X_test, y_test, rf_test_pred, feature_names, n_explain=80):
    """LIME explanations with global aggregation and local fidelity diagnostics."""
    print(f"\n[LIME] Computing LIME explanations for {n_explain} instances...")

    explainer = lime.lime_tabular.LimeTabularExplainer(
        X_train,
        feature_names=feature_names,
        class_names=['normal', 'attack'],
        mode='classification',
        random_state=SEED
    )

    attack_idx = np.where(y_test == 1)[0]
    selected_idx = attack_idx[:n_explain]
    lime_importances = np.zeros((len(selected_idx), len(feature_names)))
    fidelities = []
    correctness = []

    for i, idx in enumerate(selected_idx):
        exp = explainer.explain_instance(
            X_test[idx], rf_model.predict_proba, num_features=len(feature_names)
        )
        fidelities.append(float(getattr(exp, 'score', np.nan)))
        correctness.append(int(rf_test_pred[idx] == y_test[idx]))
        for feat_idx, weight in exp.local_exp[1]:
            lime_importances[i, feat_idx] = abs(weight)

    lime_global = np.mean(lime_importances, axis=0)
    top10_lime = np.argsort(lime_global)[-10:][::-1]
    correct_mask = np.array(correctness, dtype=bool)
    incorrect_mask = ~correct_mask

    correct_importance = np.mean(lime_importances[correct_mask], axis=0) if np.any(correct_mask) else np.zeros(len(feature_names))
    incorrect_importance = np.mean(lime_importances[incorrect_mask], axis=0) if np.any(incorrect_mask) else np.zeros(len(feature_names))

    print("\n  Top 10 features (LIME):")
    for rank, idx in enumerate(top10_lime):
        print(f"    {rank+1:2d}. {feature_names[idx]:<35} {lime_global[idx]:.4f}")

    mean_fidelity = float(np.nanmean(fidelities)) if fidelities else float('nan')
    print(f"  Mean local fidelity (R^2-style surrogate score): {mean_fidelity:.3f}")
    print(f"  Explained attack samples: total={len(selected_idx)} correct={int(np.sum(correct_mask))} incorrect={int(np.sum(incorrect_mask))}")

    return {
        'global_importance': lime_global,
        'top10_lime': top10_lime,
        'mean_fidelity': mean_fidelity,
        'correct_importance': correct_importance,
        'incorrect_importance': incorrect_importance,
    }


# ─── STABILITY ANALYSIS ───────────────────────────────────────────────────────

def stability_analysis(X_test, y_test, shap_rf, feature_names, top_k=10):
    """Measure local and bootstrap stability of RF SHAP explanations."""
    print("\n[STABILITY] Explanation stability analysis...")

    attack_mask = y_test[:len(shap_rf)] == 1
    X_att = X_test[:len(shap_rf)][attack_mask][:400]
    S_att = shap_rf[attack_mask][:400]

    from sklearn.metrics.pairwise import cosine_similarity
    cos_sim = cosine_similarity(X_att)
    np.fill_diagonal(cos_sim, -1.0)

    pairs = []
    for i in range(len(cos_sim)):
        j = int(np.argmax(cos_sim[i]))
        if cos_sim[i, j] >= 0.90 and i < j:
            pairs.append((i, j))

    jaccard_scores = []
    rank_corrs = []
    for a, b in pairs[:200]:
        top_a = set(np.argsort(np.abs(S_att[a]))[-top_k:])
        top_b = set(np.argsort(np.abs(S_att[b]))[-top_k:])
        j = len(top_a & top_b) / len(top_a | top_b)
        jaccard_scores.append(j)
        corr, _ = spearmanr(np.abs(S_att[a]), np.abs(S_att[b]))
        if np.isfinite(corr):
            rank_corrs.append(corr)

    if not jaccard_scores:
        print("  No comparable pairs found after thresholding.")
        return {
            'local_jaccard_mean': 0.0,
            'local_jaccard_scores': [],
            'local_rank_corr_mean': 0.0,
            'bootstrap_jaccard_mean': 0.0,
            'bootstrap_rank_corr_mean': 0.0,
        }

    mean_j = np.mean(jaccard_scores)
    std_j  = np.std(jaccard_scores)
    mean_rank = float(np.mean(rank_corrs)) if rank_corrs else 0.0
    print(f"  Nearest-neighbor attack pairs evaluated: {len(jaccard_scores)}")
    print(f"  SHAP Jaccard stability (top-{top_k}): {mean_j:.3f} ± {std_j:.3f}")
    print(f"  SHAP rank-correlation stability: {mean_rank:.3f}")

    rng = np.random.RandomState(SEED)
    global_imp = np.abs(S_att)
    boot_jaccards = []
    boot_corrs = []
    for _ in range(20):
        idx_a = rng.choice(len(global_imp), size=min(250, len(global_imp)), replace=True)
        idx_b = rng.choice(len(global_imp), size=min(250, len(global_imp)), replace=True)
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
    plt.hist(jaccard_scores, bins=20, color='#2E75B6', alpha=0.8, edgecolor='white')
    plt.axvline(mean_j, color='red', linestyle='--', label=f'Mean = {mean_j:.2f}')
    plt.xlabel('Jaccard Similarity of Top-10 SHAP Features')
    plt.ylabel('Frequency')
    plt.title('SHAP Explanation Stability Across Similar Attack Samples')
    plt.legend()
    plt.tight_layout()
    plt.savefig('outputs/shap_stability.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("  → Saved outputs/shap_stability.png")

    return {
        'local_jaccard_mean': float(mean_j),
        'local_jaccard_scores': jaccard_scores,
        'local_rank_corr_mean': mean_rank,
        'bootstrap_jaccard_mean': mean_boot_j,
        'bootstrap_rank_corr_mean': mean_boot_corr,
    }


# ─── ADVERSARIAL ATTACK ───────────────────────────────────────────────────────

def shap_guided_attack(rf_model, X_test, y_test, shap_rf, epsilons=None):
    """Compare global and instance-specific SHAP-guided evasion attacks."""
    if epsilons is None:
        epsilons = [0.05, 0.10, 0.20]

    print("\n[ATTACK] SHAP-guided adversarial evasion attack...")

    n = min(len(shap_rf), len(X_test))
    mask = y_test[:n] == 1
    X_att = X_test[:n][mask].copy()
    S_att = shap_rf[mask]

    if len(X_att) == 0:
        print("  No attack samples available for adversarial evaluation.")
        return {}

    global_importance = np.mean(np.abs(S_att), axis=0)

    results = {}
    top_ks = [5, 10, 15]
    for mode in ['global', 'local']:
        for top_k in top_ks:
            top_feats = np.argsort(global_importance)[-top_k:]
            for eps in epsilons:
                X_adv = X_att.copy()
                if mode == 'global':
                    for feat in top_feats:
                        direction = -np.sign(np.mean(S_att[:, feat]))
                        X_adv[:, feat] = np.clip(X_adv[:, feat] + direction * eps, 0.0, 1.0)
                else:
                    for row_idx in range(len(X_adv)):
                        local_top = np.argsort(np.abs(S_att[row_idx]))[-top_k:]
                        for feat in local_top:
                            direction = -np.sign(S_att[row_idx, feat])
                            X_adv[row_idx, feat] = np.clip(X_adv[row_idx, feat] + direction * eps, 0.0, 1.0)

                preds = rf_model.predict(X_adv)
                evasion = np.mean(preds == 0)
                key = f"{mode}_top{top_k}_eps{eps}"
                results[key] = evasion
                print(f"  {mode:>6} top-{top_k}, ε={eps}: Evasion Rate = {evasion:.2%}")

    _plot_evasion_heatmap(results, epsilons, mode='global')
    _plot_evasion_heatmap(results, epsilons, mode='local', filename='outputs/evasion_heatmap_local.png')

    return results


def _plot_evasion_heatmap(results, epsilons, mode='global', filename='outputs/evasion_heatmap.png'):
    top_ks = [5, 10, 15]
    matrix = np.array([[results[f"{mode}_top{k}_eps{e}"] for e in epsilons] for k in top_ks])

    fig, ax = plt.subplots(figsize=(7, 4))
    im = ax.imshow(matrix, cmap='Reds', vmin=0, vmax=1)
    ax.set_xticks(range(len(epsilons)))
    ax.set_yticks(range(len(top_ks)))
    ax.set_xticklabels([f'ε={e}' for e in epsilons])
    ax.set_yticklabels([f'Top-{k}' for k in top_ks])
    ax.set_xlabel('Perturbation Magnitude (ε)')
    ax.set_ylabel('Features Perturbed')
    ax.set_title(f'Evasion Rate — {mode.title()} SHAP-Guided Attack')
    for i in range(len(top_ks)):
        for j in range(len(epsilons)):
            ax.text(j, i, f'{matrix[i,j]:.0%}', ha='center', va='center',
                    color='white' if matrix[i,j] > 0.5 else 'black', fontsize=12)
    plt.colorbar(im, ax=ax, label='Evasion Rate')
    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  → Saved {filename}")


# ─── DEFENSE ──────────────────────────────────────────────────────────────────

def evaluate_defense(rf_model, X_test, y_test, shap_rf, top_k=10, eps=0.10):
    """Evaluate a simple defense against the stronger local SHAP attack."""
    print("\n[DEFENSE] Evaluating feature randomization defense...")

    n = min(len(shap_rf), len(X_test))
    mask = y_test[:n] == 1
    X_att = X_test[:n][mask].copy()
    S_att = shap_rf[mask]

    if len(X_att) == 0:
        print("  No attack samples available for defense evaluation.")
        return 0.0, 0.0

    X_adv = X_att.copy()
    for row_idx in range(len(X_adv)):
        local_top = np.argsort(np.abs(S_att[row_idx]))[-top_k:]
        for feat in local_top:
            direction = -np.sign(S_att[row_idx, feat])
            X_adv[row_idx, feat] = np.clip(X_adv[row_idx, feat] + direction * eps, 0.0, 1.0)

    global_importance = np.mean(np.abs(S_att), axis=0)
    low_feats = np.argsort(global_importance)[:20]
    X_defended = X_adv.copy()
    noise = np.random.RandomState(SEED).uniform(-0.05, 0.05, size=(len(X_defended), len(low_feats)))
    X_defended[:, low_feats] = np.clip(X_defended[:, low_feats] + noise, 0.0, 1.0)

    preds_no_defense  = rf_model.predict(X_adv)
    preds_with_defense = rf_model.predict(X_defended)

    er_no_def  = np.mean(preds_no_defense  == 0)
    er_with_def = np.mean(preds_with_defense == 0)

    print(f"  Evasion rate WITHOUT defense: {er_no_def:.2%}")
    print(f"  Evasion rate WITH defense:    {er_with_def:.2%}")
    print(f"  Defense effectiveness: {(er_no_def - er_with_def)/max(er_no_def,1e-9):.1%} reduction in evasion")

    return {
        'evasion_without_defense': float(er_no_def),
        'evasion_with_defense': float(er_with_def),
        'reduction': float((er_no_def - er_with_def) / max(er_no_def, 1e-9)),
    }


# ─── SUMMARY REPORT ───────────────────────────────────────────────────────────

def print_summary(tuning_summary, eval_results, shap_results, lime_results, stability_results, attack_results, defense_results):
    print("\n" + "=" * 60)
    print("FINAL SUMMARY — Project 5: Explainable IDS")
    print("=" * 60)

    print("\n── Model Performance ──")
    for name, res in eval_results.items():
        print(
            f"  {name:<40} F1={res['f1_macro']:.4f}  PR-AUC={res['pr_auc']:.4f}  "
            f"Threshold={res['threshold']:.2f}"
        )

    print(f"\n── Explanation Stability ──")
    print(f"  Local SHAP Jaccard (top-10, nearest-neighbor attacks): {stability_results['local_jaccard_mean']:.3f}")
    print(f"  Local SHAP rank correlation: {stability_results['local_rank_corr_mean']:.3f}")
    print(f"  Bootstrap SHAP Jaccard: {stability_results['bootstrap_jaccard_mean']:.3f}")
    print(f"  Bootstrap SHAP rank correlation: {stability_results['bootstrap_rank_corr_mean']:.3f}")

    print(f"\n── Explainability Quality ──")
    print(f"  RF/MLP SHAP Spearman alignment: {shap_results['rf_mlp_spearman']:.3f}")
    print(f"  LIME mean local fidelity: {lime_results['mean_fidelity']:.3f}")

    print(f"\n── Adversarial Attack ──")
    if attack_results:
        for k, v in sorted(attack_results.items()):
            print(f"  {k:<25}: Evasion = {v:.2%}")
    else:
        print("  No adversarial results were produced.")

    print(f"\n── Defense ──")
    print(f"  Without defense: {defense_results['evasion_without_defense']:.2%}")
    print(f"  With defense:    {defense_results['evasion_with_defense']:.2%}")
    print(f"  Reduction:       {defense_results['reduction']:.1%}")

    print("\nOutputs saved to ./outputs/")
    print("=" * 60)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("Project 5: Explainable IDS — Full Pipeline")
    print("=" * 60)

    # 1. Load data
    train_df, test_df = load_nslkdd()
    raw_test_labels = test_df['label'].astype(str).str.strip().str.rstrip('.').values

    # 2. Preprocess
    X_train, y_train, X_test, y_test, feature_names, scaler = preprocess(train_df, test_df)

    # 3. Tune and train
    models, tuning_summary = tune_and_train_models(X_train, y_train)

    # 4. Evaluate
    eval_results = evaluate_models(models, tuning_summary, X_test, y_test, raw_test_labels)

    # 5. SHAP
    rf  = models['Random Forest']
    mlp = models['MLP']
    shap_results = shap_analysis(rf, mlp, X_train, X_test, feature_names)
    shap_results['rf_mlp_spearman'] = float(
        spearmanr(shap_results['rf_importance'], shap_results['mlp_importance'])[0]
    )

    # 6. LIME
    lime_results = lime_analysis(
        rf, X_train, X_test, y_test, eval_results['Random Forest']['y_pred'], feature_names
    )

    # 7. Stability
    stability_results = stability_analysis(X_test, y_test, shap_results['shap_rf'], feature_names)

    # 8. Attack
    attack_results = shap_guided_attack(rf, X_test, y_test, shap_results['shap_rf'])

    # 9. Defense
    defense_results = evaluate_defense(rf, X_test, y_test, shap_results['shap_rf'])

    # 10. Summary
    print_summary(
        tuning_summary,
        eval_results,
        shap_results,
        lime_results,
        stability_results,
        attack_results,
        defense_results,
    )


if __name__ == '__main__':
    try:
        main()
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
