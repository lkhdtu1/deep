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
from sklearn.metrics import (classification_report, f1_score,
                              precision_recall_curve, auc, confusion_matrix)
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

def train_models(X_train, y_train):
    """Train all 3 model variations."""
    print("\n[TRAIN] Training models...")

    models = {
        'Logistic Regression (baseline)': LogisticRegression(
            C=1.0, max_iter=1000, random_state=SEED, n_jobs=-1),
        'Random Forest': RandomForestClassifier(
            n_estimators=100, max_depth=15, random_state=SEED, n_jobs=-1),
        'MLP': MLPClassifier(
            hidden_layer_sizes=(128, 64), activation='relu',
            max_iter=100, random_state=SEED, early_stopping=True,
            validation_fraction=0.1),
    }

    trained = {}
    for name, model in models.items():
        print(f"  → {name}...", end=' ', flush=True)
        model.fit(X_train, y_train)
        trained[name] = model
        print("done")

    return trained


def evaluate_models(models, X_test, y_test):
    """Evaluate with Precision, Recall, F1, PR-AUC."""
    results = {}
    print("\n[EVAL] Classification Results")
    print("=" * 60)

    for name, model in models.items():
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        precision, recall, _ = precision_recall_curve(y_test, y_prob)
        pr_auc = auc(recall, precision)
        f1 = f1_score(y_test, y_pred, average='macro')
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            'f1_macro': f1, 'pr_auc': pr_auc,
            'y_pred': y_pred, 'y_prob': y_prob,
            'confusion_matrix': cm
        }

        print(f"\n{name}")
        print(classification_report(y_test, y_pred,
              target_names=['normal', 'attack']))
        print(f"  PR-AUC: {pr_auc:.4f}")

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
    # Use subset for speed — 2000 test samples
    X_sub = X_test[:2000]
    shap_vals_rf = tree_explainer.shap_values(X_sub)
    shap_attack = _select_positive_class_shap(shap_vals_rf)
    print("done")

    rf_global_importance = np.mean(np.abs(shap_attack), axis=0)
    top10_rf = np.argsort(rf_global_importance)[-10:][::-1]

    print("\n  Top 10 features (RF SHAP):")
    for rank, idx in enumerate(top10_rf):
        print(f"    {rank+1:2d}. {feature_names[idx]:<35} {rf_global_importance[idx]:.4f}")

    # --- KernelSHAP for MLP ---
    print("\n  → KernelSHAP (MLP, subset 200 bg + 100 samples)...", end=' ', flush=True)
    background = shap.sample(X_train, 100, random_state=SEED)
    kernel_explainer = shap.KernelExplainer(mlp_model.predict_proba, background)
    X_explain = X_test[:100]
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
        'X_sub': X_sub
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

def lime_analysis(rf_model, X_train, X_test, y_test, feature_names, n_explain=50):
    """LIME explanations for n_explain instances."""
    print(f"\n[LIME] Computing LIME explanations for {n_explain} instances...")

    explainer = lime.lime_tabular.LimeTabularExplainer(
        X_train,
        feature_names=feature_names,
        class_names=['normal', 'attack'],
        mode='classification',
        random_state=SEED
    )

    # Pick attack samples
    attack_idx = np.where(y_test == 1)[0][:n_explain]
    lime_importances = np.zeros((len(attack_idx), len(feature_names)))

    for i, idx in enumerate(attack_idx):
        exp = explainer.explain_instance(
            X_test[idx], rf_model.predict_proba, num_features=len(feature_names)
        )
        for feat_idx, weight in exp.local_exp[1]:
            lime_importances[i, feat_idx] = abs(weight)

    lime_global = np.mean(lime_importances, axis=0)
    top10_lime = np.argsort(lime_global)[-10:][::-1]

    print("\n  Top 10 features (LIME):")
    for rank, idx in enumerate(top10_lime):
        print(f"    {rank+1:2d}. {feature_names[idx]:<35} {lime_global[idx]:.4f}")

    return lime_global, top10_lime


# ─── STABILITY ANALYSIS ───────────────────────────────────────────────────────

def stability_analysis(rf_model, X_test, y_test, shap_rf, feature_names, top_k=10):
    """
    Measure explanation stability: find pairs of similar attack samples
    (cosine sim > 0.95) and compute Jaccard similarity of their top-k SHAP features.
    """
    print("\n[STABILITY] Explanation stability analysis...")

    # Use attack samples only, first 500
    attack_mask = y_test[:len(shap_rf)] == 1
    X_att = X_test[:len(shap_rf)][attack_mask][:500]
    S_att = shap_rf[attack_mask][:500]

    # Find similar pairs via cosine similarity
    from sklearn.metrics.pairwise import cosine_similarity
    cos_sim = cosine_similarity(X_att)
    pairs = np.argwhere((cos_sim > 0.95) & (cos_sim < 1.0))

    if len(pairs) == 0:
        print("  No similar pairs found. Lowering threshold to 0.90...")
        pairs = np.argwhere((cos_sim > 0.90) & (cos_sim < 1.0))

    # Compute Jaccard stability
    jaccard_scores = []
    for a, b in pairs[:200]:  # cap at 200 pairs
        top_a = set(np.argsort(np.abs(S_att[a]))[-top_k:])
        top_b = set(np.argsort(np.abs(S_att[b]))[-top_k:])
        j = len(top_a & top_b) / len(top_a | top_b)
        jaccard_scores.append(j)

    if not jaccard_scores:
        print("  No comparable pairs found after thresholding.")
        return 0.0, []

    mean_j = np.mean(jaccard_scores)
    std_j  = np.std(jaccard_scores)
    print(f"  Pairs evaluated: {len(jaccard_scores)}")
    print(f"  SHAP Jaccard stability (top-{top_k}): {mean_j:.3f} ± {std_j:.3f}")

    # Plot distribution
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

    return mean_j, jaccard_scores


# ─── ADVERSARIAL ATTACK ───────────────────────────────────────────────────────

def shap_guided_attack(rf_model, X_test, y_test, shap_rf, epsilons=None):
    """
    SHAP-guided evasion attack: perturb top-k features of attack samples
    toward the 'normal' class direction.

    Returns evasion rates for each (top_k, epsilon) combination.
    """
    if epsilons is None:
        epsilons = [0.05, 0.10, 0.20]

    print("\n[ATTACK] SHAP-guided adversarial evasion attack...")

    # Use attack samples from the test set (aligned with shap_rf subset)
    n = min(len(shap_rf), len(X_test))
    mask = y_test[:n] == 1
    X_att = X_test[:n][mask].copy()
    S_att = shap_rf[mask]

    if len(X_att) == 0:
        print("  No attack samples available for adversarial evaluation.")
        return {}

    global_importance = np.mean(np.abs(S_att), axis=0)

    results = {}
    for top_k in [5, 10, 15]:
        top_feats = np.argsort(global_importance)[-top_k:]
        for eps in epsilons:
            X_adv = X_att.copy()
            for feat in top_feats:
                # Perturb in the direction that reduces attack SHAP contribution
                direction = -np.sign(np.mean(S_att[:, feat]))
                X_adv[:, feat] = np.clip(X_adv[:, feat] + direction * eps, 0.0, 1.0)

            preds = rf_model.predict(X_adv)
            evasion = np.mean(preds == 0)
            key = f"top{top_k}_eps{eps}"
            results[key] = evasion
            print(f"  top-{top_k} features, ε={eps}: Evasion Rate = {evasion:.2%}")

    # Plot evasion rate heatmap
    _plot_evasion_heatmap(results, epsilons)

    return results


def _plot_evasion_heatmap(results, epsilons):
    top_ks = [5, 10, 15]
    matrix = np.array([[results[f"top{k}_eps{e}"] for e in epsilons] for k in top_ks])

    fig, ax = plt.subplots(figsize=(7, 4))
    im = ax.imshow(matrix, cmap='Reds', vmin=0, vmax=1)
    ax.set_xticks(range(len(epsilons)))
    ax.set_yticks(range(len(top_ks)))
    ax.set_xticklabels([f'ε={e}' for e in epsilons])
    ax.set_yticklabels([f'Top-{k}' for k in top_ks])
    ax.set_xlabel('Perturbation Magnitude (ε)')
    ax.set_ylabel('Features Perturbed')
    ax.set_title('Evasion Rate — SHAP-Guided Attack')
    for i in range(len(top_ks)):
        for j in range(len(epsilons)):
            ax.text(j, i, f'{matrix[i,j]:.0%}', ha='center', va='center',
                    color='white' if matrix[i,j] > 0.5 else 'black', fontsize=12)
    plt.colorbar(im, ax=ax, label='Evasion Rate')
    plt.tight_layout()
    plt.savefig('outputs/evasion_heatmap.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("  → Saved outputs/evasion_heatmap.png")


# ─── DEFENSE ──────────────────────────────────────────────────────────────────

def evaluate_defense(rf_model, X_test, y_test, shap_rf, top_k=10, eps=0.10):
    """
    Defense: feature randomization — add noise to low-importance features
    to obscure the importance landscape.
    """
    print("\n[DEFENSE] Evaluating feature randomization defense...")

    n = min(len(shap_rf), len(X_test))
    mask = y_test[:n] == 1
    X_att = X_test[:n][mask].copy()
    S_att = shap_rf[mask]

    if len(X_att) == 0:
        print("  No attack samples available for defense evaluation.")
        return 0.0, 0.0

    global_importance = np.mean(np.abs(S_att), axis=0)
    top_feats = np.argsort(global_importance)[-top_k:]
    low_feats  = np.argsort(global_importance)[:20]  # perturb 20 low-importance feats

    # Build adversarial examples (attack on high-importance feats)
    X_adv = X_att.copy()
    for feat in top_feats:
        direction = -np.sign(np.mean(S_att[:, feat]))
        X_adv[:, feat] = np.clip(X_adv[:, feat] + direction * eps, 0.0, 1.0)

    # Apply defense: add noise to low-importance features (obscures landscape)
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

    return er_no_def, er_with_def


# ─── SUMMARY REPORT ───────────────────────────────────────────────────────────

def print_summary(eval_results, stability_mean, attack_results):
    print("\n" + "=" * 60)
    print("FINAL SUMMARY — Project 5: Explainable IDS")
    print("=" * 60)

    print("\n── Model Performance ──")
    for name, res in eval_results.items():
        print(f"  {name:<40} F1={res['f1_macro']:.4f}  PR-AUC={res['pr_auc']:.4f}")

    print(f"\n── Explanation Stability ──")
    print(f"  SHAP Jaccard (top-10 features, similar pairs): {stability_mean:.3f}")

    print(f"\n── Adversarial Attack ──")
    if attack_results:
        for k, v in attack_results.items():
            print(f"  {k:<25}: Evasion = {v:.2%}")
    else:
        print("  No adversarial results were produced.")

    print("\nOutputs saved to ./outputs/")
    print("=" * 60)


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("Project 5: Explainable IDS — Full Pipeline")
    print("=" * 60)

    # 1. Load data
    train_df, test_df = load_nslkdd()

    # 2. Preprocess
    X_train, y_train, X_test, y_test, feature_names, scaler = preprocess(train_df, test_df)

    # 3. Train
    models = train_models(X_train, y_train)

    # 4. Evaluate
    eval_results = evaluate_models(models, X_test, y_test)

    # 5. SHAP
    rf  = models['Random Forest']
    mlp = models['MLP']
    shap_results = shap_analysis(rf, mlp, X_train, X_test, feature_names)

    # 6. LIME
    lime_global, top10_lime = lime_analysis(rf, X_train, X_test, y_test, feature_names)

    # 7. Stability
    stability_mean, _ = stability_analysis(rf, X_test, y_test,
                                            shap_results['shap_rf'], feature_names)

    # 8. Attack
    attack_results = shap_guided_attack(rf, X_test, y_test, shap_results['shap_rf'])

    # 9. Defense
    evaluate_defense(rf, X_test, y_test, shap_results['shap_rf'])

    # 10. Summary
    print_summary(eval_results, stability_mean, attack_results)


if __name__ == '__main__':
    try:
        main()
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
