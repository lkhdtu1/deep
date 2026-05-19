import json
import os
import shutil
import struct
import zipfile
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DOCX = ROOT / "new" / "Project5_CUDA_Report_working.docx"
SUMMARY_JSON = ROOT / "outputs_cuda" / "summary.json"
OUTPUTS = ROOT / "outputs_cuda"
NEW = ROOT / "new"
DELIVERABLES = NEW / "deliverables"
IMAGES_DIR = DELIVERABLES / "images"
REPORT_DOCX = NEW / "Project5_CUDA_Report_final_heavy.docx"
REPORT_MD = NEW / "Project5_CUDA_Report_final_heavy.md"
CLAUDE_PROMPT = NEW / "claude_pptx_prompt.md"


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
PIC = "http://schemas.openxmlformats.org/drawingml/2006/picture"


def pct(x):
    return f"{100 * x:.2f}%"


def f4(x):
    return f"{x:.4f}"


def load_summary():
    with SUMMARY_JSON.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def png_size(path):
    with open(path, "rb") as handle:
        sig = handle.read(24)
    if sig[:8] != b"\x89PNG\r\n\x1a\n":
        return 1200, 700
    return struct.unpack(">II", sig[16:24])


def paragraph(text="", style=None, align=None):
    ppr = ""
    if style or align:
        parts = []
        if style:
            parts.append(f'<w:pStyle w:val="{escape(style)}"/>')
        if align:
            parts.append(f'<w:jc w:val="{align}"/>')
        ppr = f"<w:pPr>{''.join(parts)}</w:pPr>"
    runs = []
    for idx, line in enumerate(str(text).split("\n")):
        if idx:
            runs.append("<w:r><w:br/></w:r>")
        runs.append(f"<w:r><w:t xml:space=\"preserve\">{escape(line)}</w:t></w:r>")
    return f"<w:p>{ppr}{''.join(runs)}</w:p>"


def heading(text, level=1):
    return paragraph(text, style=f"Heading{level}")


def page_break():
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


def table(rows, header=True):
    xml = [
        '<w:tbl>',
        '<w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="0" w:type="auto"/>'
        '<w:tblLook w:firstRow="1" w:lastRow="0" w:firstColumn="0" w:lastColumn="0" '
        'w:noHBand="0" w:noVBand="1"/></w:tblPr>',
    ]
    for r_idx, row in enumerate(rows):
        xml.append("<w:tr>")
        for cell in row:
            bold_start = "<w:b/>" if header and r_idx == 0 else ""
            xml.append(
                "<w:tc><w:tcPr><w:tcW w:w=\"0\" w:type=\"auto\"/></w:tcPr>"
                f"<w:p><w:r><w:rPr>{bold_start}</w:rPr><w:t>{escape(str(cell))}</w:t></w:r></w:p>"
                "</w:tc>"
            )
        xml.append("</w:tr>")
    xml.append("</w:tbl>")
    return "".join(xml)


def image_paragraph(rel_id, name, path, max_width_inches=6.3):
    width_px, height_px = png_size(path)
    max_cx = int(max_width_inches * 914400)
    ratio = height_px / max(width_px, 1)
    cx = max_cx
    cy = int(cx * ratio)
    doc_id = int(rel_id.replace("rId", "")) + 100
    return f"""
<w:p>
  <w:pPr><w:jc w:val="center"/></w:pPr>
  <w:r>
    <w:drawing>
      <wp:inline distT="0" distB="0" distL="0" distR="0">
        <wp:extent cx="{cx}" cy="{cy}"/>
        <wp:effectExtent l="0" t="0" r="0" b="0"/>
        <wp:docPr id="{doc_id}" name="{escape(name)}"/>
        <wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect="1"/></wp:cNvGraphicFramePr>
        <a:graphic>
          <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
            <pic:pic>
              <pic:nvPicPr>
                <pic:cNvPr id="{doc_id}" name="{escape(name)}"/>
                <pic:cNvPicPr/>
              </pic:nvPicPr>
              <pic:blipFill>
                <a:blip r:embed="{rel_id}"/>
                <a:stretch><a:fillRect/></a:stretch>
              </pic:blipFill>
              <pic:spPr>
                <a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>
                <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
              </pic:spPr>
            </pic:pic>
          </a:graphicData>
        </a:graphic>
      </wp:inline>
    </w:drawing>
  </w:r>
</w:p>
"""


def build_report_parts(summary):
    m = summary["models"]
    stability = summary["stability"]
    attacks = summary["attacks"]
    adv_transfer = summary["adv_tree_transfer_pgd_defense"]
    sec_transfer = summary["security_or_transfer_pgd_defense"]
    constrained = summary["constrained_pgd_adversarial_finetune_defense"]
    pgd = summary["pgd_adversarial_finetune_defense"]

    model_rows = [
        ["Model", "Binary F1", "PR-AUC", "Balanced Accuracy", "Threshold"],
        ["Logistic Regression", f4(m["logistic_regression"]["binary_macro_f1"]), f4(m["logistic_regression"]["pr_auc"]), f4(m["logistic_regression"]["balanced_accuracy"]), "-"],
        ["Random Forest", f4(m["random_forest"]["binary_macro_f1"]), f4(m["random_forest"]["pr_auc"]), f4(m["random_forest"]["balanced_accuracy"]), "-"],
        ["Torch MLP CUDA", f4(m["torch_mlp"]["binary_macro_f1"]), f4(m["torch_mlp"]["pr_auc"]), f4(m["torch_mlp"]["balanced_accuracy"]), "-"],
        ["Torch Binary MLP CUDA", f4(m["torch_binary_mlp"]["binary_macro_f1"]), f4(m["torch_binary_mlp"]["pr_auc"]), f4(m["torch_binary_mlp"]["balanced_accuracy"]), f'{m["torch_binary_mlp"]["threshold"]:.2f}'],
        ["PGD-Adversarial Torch Binary MLP", f4(m["torch_binary_adv_mlp"]["binary_macro_f1"]), f4(m["torch_binary_adv_mlp"]["pr_auc"]), f4(m["torch_binary_adv_mlp"]["balanced_accuracy"]), f'{m["torch_binary_adv_mlp"]["threshold"]:.2f}'],
        ["Binary RF IDS", f4(m["binary_rf"]["binary_macro_f1"]), f4(m["binary_rf"]["pr_auc"]), f4(m["binary_rf"]["balanced_accuracy"]), f'{m["binary_rf"]["threshold"]:.2f}'],
        ["Binary ExtraTrees IDS", f4(m["binary_extratrees"]["binary_macro_f1"]), f4(m["binary_extratrees"]["pr_auc"]), f4(m["binary_extratrees"]["balanced_accuracy"]), f'{m["binary_extratrees"]["threshold"]:.2f}'],
        ["SHAP-Robust ExtraTrees IDS", f4(m["binary_robust_extratrees"]["binary_macro_f1"]), f4(m["binary_robust_extratrees"]["pr_auc"]), f4(m["binary_robust_extratrees"]["balanced_accuracy"]), f'{m["binary_robust_extratrees"]["threshold"]:.2f}'],
        ["Binary XGBoost IDS", f4(m["binary_xgboost"]["binary_macro_f1"]), f4(m["binary_xgboost"]["pr_auc"]), f4(m["binary_xgboost"]["balanced_accuracy"]), f'{m["binary_xgboost"]["threshold"]:.2f}'],
        ["Tuned Binary Ensemble IDS", f4(m["binary_ensemble"]["binary_macro_f1"]), f4(m["binary_ensemble"]["pr_auc"]), f4(m["binary_ensemble"]["balanced_accuracy"]), f'{m["binary_ensemble"]["threshold"]:.2f}'],
        ["Adv+ExtraTrees Ensemble IDS", f4(m["adv_tree_ensemble"]["binary_macro_f1"]), f4(m["adv_tree_ensemble"]["pr_auc"]), f4(m["adv_tree_ensemble"]["balanced_accuracy"]), f'{m["adv_tree_ensemble"]["threshold"]:.2f}'],
        ["Security-OR Ensemble IDS", f4(m["security_or_ensemble"]["binary_macro_f1"]), f4(m["security_or_ensemble"]["pr_auc"]), f4(m["security_or_ensemble"]["balanced_accuracy"]), f'{m["security_or_ensemble"]["threshold"]:.2f}'],
    ]

    rec = m["adv_tree_ensemble"]["per_family_recall"]
    family_rows = [["Family", "Recall"], *[[k, f4(rec[k])] for k in ["normal", "DoS", "Probe", "R2L", "U2R"]]]

    explain_rows = [
        ["Explanation", "Local Jaccard", "Local Rank", "Bootstrap Jaccard", "Bootstrap Rank"],
        ["RF SHAP", f'{f4(stability["rf_shap"]["local_jaccard_mean"])} +/- {f4(stability["rf_shap"]["local_jaccard_std"])}', f4(stability["rf_shap"]["local_rank_corr_mean"]), f4(stability["rf_shap"]["bootstrap_jaccard_mean"]), f4(stability["rf_shap"]["bootstrap_rank_corr_mean"])],
        ["Torch IG", f'{f4(stability["torch_ig"]["local_jaccard_mean"])} +/- {f4(stability["torch_ig"]["local_jaccard_std"])}', f4(stability["torch_ig"]["local_rank_corr_mean"]), f4(stability["torch_ig"]["bootstrap_jaccard_mean"]), f4(stability["torch_ig"]["bootstrap_rank_corr_mean"])],
        ["Torch Binary SmoothIG", f'{f4(stability["torch_binary_smoothig"]["local_jaccard_mean"])} +/- {f4(stability["torch_binary_smoothig"]["local_jaccard_std"])}', f4(stability["torch_binary_smoothig"]["local_rank_corr_mean"]), f4(stability["torch_binary_smoothig"]["bootstrap_jaccard_mean"]), f4(stability["torch_binary_smoothig"]["bootstrap_rank_corr_mean"])],
        ["Adv+ExtraTrees Ensemble", f'{f4(stability["adv_tree_ensemble"]["local_jaccard_mean"])} +/- {f4(stability["adv_tree_ensemble"]["local_jaccard_std"])}', f4(stability["adv_tree_ensemble"]["local_rank_corr_mean"]), f4(stability["adv_tree_ensemble"]["bootstrap_jaccard_mean"]), f4(stability["adv_tree_ensemble"]["bootstrap_rank_corr_mean"])],
    ]

    transfer_rows = [["Epsilon", "Surrogate Torch Evasion", "Ensemble Evasion", "Absolute Reduction"]]
    for key in ["transfer_pgd_eps0.03", "transfer_pgd_eps0.06", "transfer_pgd_eps0.1", "transfer_pgd_eps0.15"]:
        row = adv_transfer[key]
        transfer_rows.append([
            key.replace("transfer_pgd_eps", ""),
            pct(row["surrogate_torch_evasion"]),
            pct(row["ensemble_transfer_evasion"]),
            f'{100 * row["absolute_reduction"]:.2f} pp',
        ])

    sec_rows = [["Epsilon", "Surrogate Torch Evasion", "Security-OR Evasion", "Absolute Reduction"]]
    for key in ["security_or_transfer_pgd_eps0.03", "security_or_transfer_pgd_eps0.06", "security_or_transfer_pgd_eps0.1", "security_or_transfer_pgd_eps0.15"]:
        row = sec_transfer[key]
        sec_rows.append([
            key.replace("security_or_transfer_pgd_eps", ""),
            pct(row["surrogate_torch_evasion"]),
            pct(row["security_or_transfer_evasion"]),
            f'{100 * row["absolute_reduction"]:.2f} pp',
        ])

    pgd_rows = [["Epsilon", "Before Adv Training", "After Multi-Eps Adv Training", "Reduction"]]
    for key in ["pgd_all_eps0.03", "pgd_all_eps0.06", "pgd_all_eps0.1", "pgd_all_eps0.15"]:
        row = pgd[key]
        pgd_rows.append([key.replace("pgd_all_eps", ""), pct(row["before"]), pct(row["after"]), f'{100 * row["reduction"]:.2f} pp'])

    constrained_rows = [["Epsilon", "Before Multi-Eps Training", "After Multi-Eps Training", "Reduction"]]
    for key in ["constrained_pgd_eps0.03", "constrained_pgd_eps0.06", "constrained_pgd_eps0.1", "constrained_pgd_eps0.15"]:
        row = constrained[key]
        constrained_rows.append([key.replace("constrained_pgd_eps", ""), pct(row["before"]), pct(row["after"]), f'{100 * row["reduction"]:.2f} pp'])

    compliance_rows = [
        ["Requirement", "Implementation", "Status"],
        ["Train IDS model", "Logistic Regression, Random Forest, Torch MLP, binary IDS models, SHAP-Robust ExtraTrees, and ensembles trained on KDDTrain+.", "Done"],
        ["Apply explainability", "TreeSHAP, Integrated Gradients, SmoothIG, and a combined explanation for the final Adv+ExtraTrees ensemble.", "Done"],
        ["Evaluate stability", "Local nearest-neighbour Jaccard/rank metrics and bootstrap Jaccard/rank metrics.", "Done"],
        ["Security implications", "SHAP-guided evasion, IG-guided evasion, PGD, mutable-feature PGD, and transfer-PGD defense.", "Done"],
        ["Deliverables", "Final report, code, summary JSON, figures, interpretation notes, and presentation prompt.", "Done"],
    ]

    parts = []
    parts += [
        paragraph("ICCN - INE2  |  Deep Learning in Cybersecurity", style="Subtitle", align="center"),
        paragraph("Project 5: Explainable IDS", style="Title", align="center"),
        paragraph("Interpretable Intrusion Detection with Explainability-Guided Adversarial Analysis", style="Subtitle", align="center"),
        paragraph("Dataset: NSL-KDD (KDDTrain+ / KDDTest+)", align="center"),
        paragraph("Environment: Python 3.11 / PyTorch 2.6.0+cu124 / RTX 3060", align="center"),
        paragraph("Group: TAMIS Mohammed and GRYACH Ikram", align="center"),
        paragraph("Date: 16/05/2026", align="center"),
        page_break(),
        heading("Table of Contents", 1),
        paragraph("1. Abstract\n2. Introduction and Project Objective\n3. Assignment Requirements and Compliance\n4. Dataset and Preprocessing\n5. Experimental Design and Improvements\n6. Clean IDS Results\n7. Explainability Analysis\n8. Explanation Stability Analysis\n9. Adversarial Analysis\n10. Defense Evaluation\n11. Limitations\n12. Deliverables and Reproducibility\n13. Conclusion\nReferences"),
        page_break(),
        heading("1. Abstract", 1),
        paragraph("This report presents an explainable intrusion detection system developed for Project 5 using the NSL-KDD benchmark. The pipeline follows the required sequence of preprocessing, baseline modelling, experimental variations, explainability, stability analysis, and adversarial security evaluation. The final feature matrix contains 478 columns after one-hot encoding and IDS-oriented feature engineering. The final selected detector is the Adv+ExtraTrees Ensemble IDS, which combines a multi-epsilon PGD-adversarially fine-tuned Torch binary detector with a SHAP-robust ExtraTrees model. On KDDTest+, this ensemble reaches binary F1 0.9063, PR-AUC 0.9626, and balanced accuracy 0.9064. It also improves rare-family recall, reaching 0.6786 for R2L and 0.8060 for U2R. Explainability is provided through TreeSHAP, Integrated Gradients, SmoothIG, and a combined ensemble explanation. The adversarial analysis shows that the standalone neural detector remains vulnerable to strong white-box PGD, but the final Adv+ExtraTrees ensemble reduces transfer-PGD evasion to 0.00% for epsilons 0.06, 0.10, and 0.15, and to only 0.50% for epsilon 0.03."),
        heading("2. Introduction and Project Objective", 1),
        paragraph("Machine-learning intrusion detection systems are useful only if their decisions can be understood and their failure modes can be evaluated. A high F1 score alone is insufficient in cybersecurity because analysts must know which traffic properties influenced a detection, whether those explanations remain stable, and whether the same explanations can be used by an attacker to evade detection. This project therefore studies explainable IDS modelling as both a defensive interpretability tool and a potential adversarial information source."),
        paragraph("The project objective is to train IDS models on NSL-KDD, explain their predictions, evaluate the stability of those explanations, and analyse the security implications of explanation-guided attacks. The final system goes beyond the minimum requirement by adding feature engineering, multi-epsilon adversarial fine-tuning, a SHAP-augmented robust ExtraTrees model, a robustness-aware Adv+ExtraTrees ensemble, and a calibrated Security-OR operating point for high-security scenarios."),
        heading("3. Assignment Requirements and Compliance", 1),
        paragraph("The implementation satisfies the Project 5 deliverables. The report includes a baseline, multiple experimental variations, explainability methods, stability evaluation, adversarial analysis, defense experiments, figures, reproducibility information, and final limitations."),
        table(compliance_rows),
        heading("4. Dataset and Preprocessing", 1),
        heading("4.1 NSL-KDD", 2),
        paragraph("NSL-KDD is used as required by the project. The training set contains 125,973 records and the KDDTest+ evaluation split contains 22,544 records. The test split includes attack types that are absent from training, which makes it a more difficult generalisation benchmark than random cross-validation. The labels are mapped into five families: normal, DoS, Probe, R2L, and U2R. A binary label is also derived, where normal traffic is class 0 and any attack is class 1."),
        heading("4.2 Preprocessing and Feature Engineering", 2),
        paragraph("The preprocessing removes the difficulty column, maps raw attack labels to their canonical families, one-hot encodes the categorical protocol, service, and flag fields, and applies MinMax scaling fitted only on the training data. Feature engineering adds log-transformed byte features, traffic totals, byte ratios, service proportions, error-rate gap features, and a login anomaly score. These engineered features are included because R2L and U2R attacks are often weakly represented by the raw attributes and require stronger behavioural signals. The final aligned train and test matrices contain 478 features."),
        heading("5. Experimental Design and Improvements", 1),
        heading("5.1 Baseline and Variations", 2),
        paragraph("Logistic Regression is used as the baseline because it is intrinsically interpretable and provides a clear reference for binary detection. Random Forest and ExtraTrees models provide stronger non-linear baselines and support TreeSHAP explanations. The CUDA Torch MLP provides the deep learning variation and is explained using Integrated Gradients. A separate Torch binary MLP is trained for attack-vs-normal detection and is later used in adversarial training experiments."),
        paragraph("The main improvements are introduced in three stages. First, the Torch binary IDS is adversarially fine-tuned using multi-epsilon PGD examples at epsilons 0.03, 0.06, and 0.10. Second, the ExtraTrees model is augmented with SHAP-guided adversarial samples to form the SHAP-Robust ExtraTrees IDS. Third, a robustness-aware Adv+ExtraTrees ensemble combines the adversarial Torch detector with the robust tree detector. This ensemble is selected as the final model because it offers the best balance between clean detection and adversarial transfer robustness."),
        heading("5.2 Security-OR Operating Point", 2),
        paragraph("A calibrated Security-OR mode is also evaluated. It converts each component score into a margin relative to that component's own detection threshold and then takes the maximum margin. This avoids comparing uncalibrated raw probabilities. Security-OR is useful as a stricter high-security operating point, but it is not selected as the final model because its clean binary F1 is lower than the Adv+ExtraTrees ensemble."),
        heading("6. Clean IDS Results", 1),
        paragraph("The final results show that the Adv+ExtraTrees Ensemble IDS is the best overall detector. It reaches binary F1 0.9063 and balanced accuracy 0.9064, outperforming the standalone SHAP-Robust ExtraTrees model and the neural models. The Binary Random Forest remains a strong ranking model with PR-AUC 0.9712, but its fixed-threshold binary F1 is lower on KDDTest+."),
        table(model_rows),
        heading("6.1 Per-Family Recall of the Final Model", 2),
        paragraph("Per-family recall is important because NSL-KDD is imbalanced and the rare R2L and U2R families are the most difficult to detect. The final ensemble achieves strong DoS and Probe recall while also improving the rare-family results compared with the baseline models."),
        table(family_rows),
        heading("7. Explainability Analysis", 1),
        paragraph("TreeSHAP is applied to the Random Forest because it provides exact Shapley attributions for tree ensembles. Integrated Gradients is applied to the Torch MLP because it attributes neural predictions along a path from a baseline to the input. SmoothIG is applied to the Torch binary detector to reduce attribution noise. In the heavy run, the final Adv+ExtraTrees ensemble is also explained by combining normalized tree SHAP attributions with SmoothIG attributions from the adversarial Torch component."),
    ]
    return parts, {
        "model_rows": model_rows,
        "family_rows": family_rows,
        "explain_rows": explain_rows,
        "transfer_rows": transfer_rows,
        "sec_rows": sec_rows,
        "pgd_rows": pgd_rows,
        "constrained_rows": constrained_rows,
    }


def remaining_parts(tables):
    return [
        ("image", "rf_shap_top10.png", "Figure 1. Random Forest TreeSHAP top features."),
        ("image", "torch_binary_smoothig_top10.png", "Figure 2. Torch binary SmoothIG top features."),
        ("image", "adv_tree_ensemble_top10.png", "Figure 3. Final Adv+ExtraTrees ensemble explanation."),
        heading("7.1 Final Ensemble Explanation", 2),
        paragraph("The final ensemble explanation identifies flag_SF, same_srv_rate, dst_host_srv_count, logged_in, dst_host_same_srv_rate, rerror_rate, dst_host_rerror_rate, service_private, same_diff_srv_gap, and dst_host_srv_serror_rate as the most influential features. These features are coherent for IDS analysis: they represent connection status, service consistency, host-service concentration, login behaviour, and error patterns."),
        heading("8. Explanation Stability Analysis", 1),
        paragraph("Explanation stability is measured using local nearest-neighbour agreement and bootstrap resampling. Stable explanations are valuable because they give analysts consistent evidence across similar traffic records. However, this stability also has a dual-use security implication: if the same features remain important across nearby samples, an adversary can repeatedly target those features during evasion."),
        table(tables["explain_rows"]),
        ("image", "rf_vs_torch_explanations.png", "Figure 4. Cross-method explanation comparison."),
        heading("9. Adversarial Analysis", 1),
        heading("9.1 Threat Model", 2),
        paragraph("The adversarial evaluation uses feature-space evasion attacks. Explanation-guided attacks modify the most important SHAP or IG features, while PGD attacks use gradient information against the differentiable Torch binary model. Full-feature PGD is treated as a worst-case stress test because it allows every normalized feature to move. Mutable-feature PGD is also included as a more realistic tabular threat model, freezing categorical protocol, service, and flag indicators as well as binary login/status fields."),
        heading("9.2 Explanation-Guided Evasion", 2),
        paragraph("The RF SHAP-guided attack reaches a maximum evasion rate of 18.22%, and the Torch IG-guided attack reaches 15.97%. Against the final Adv+ExtraTrees ensemble, the TreeSHAP-guided attack fails across all tested top-k and epsilon combinations, with ensemble evasion remaining at 0.00%. This result supports the robustness contribution of the SHAP-Robust ExtraTrees component and the ensemble design."),
        ("image", "rf_shap_evasion_local.png", "Figure 5. Local RF SHAP-guided evasion."),
        ("image", "ig_evasion_heatmap.png", "Figure 6. Integrated-Gradient-guided evasion."),
        ("image", "adv_tree_shap_evasion.png", "Figure 7. TreeSHAP-guided evasion against the final ensemble."),
        heading("9.3 PGD Evasion", 2),
        paragraph("The original Torch binary model is completely vulnerable to full-feature PGD at all evaluated budgets. Multi-epsilon adversarial fine-tuning substantially improves low and medium budgets, reducing eps 0.03 evasion from 100.00% to 33.34% and eps 0.06 evasion from 100.00% to 61.72%. At eps 0.15, the standalone adversarially trained Torch model remains fully vulnerable, which is why the final system does not rely on it alone."),
        table(tables["pgd_rows"]),
        ("image", "torch_binary_pgd_evasion.png", "Figure 8. PGD and SmoothIG-constrained evasion against the original Torch binary IDS."),
        ("image", "torch_binary_adv_pgd_evasion.png", "Figure 9. Full-feature PGD evasion after multi-epsilon adversarial fine-tuning."),
        heading("9.4 Mutable-Feature PGD", 2),
        paragraph("Mutable-feature PGD gives a more realistic interpretation because it freezes features that are not freely controllable in real traffic records. Multi-epsilon adversarial training improves medium and high perturbation budgets, reducing eps 0.10 evasion by 32.03 percentage points and eps 0.15 evasion by 42.03 percentage points. The eps 0.03 result slightly worsens, which is reported as a limitation and an expected tradeoff of adversarial training."),
        table(tables["constrained_rows"]),
        ("image", "torch_binary_constrained_pgd_evasion.png", "Figure 10. Mutable-feature PGD against the original Torch binary IDS."),
        ("image", "torch_binary_adv_constrained_pgd_evasion.png", "Figure 11. Mutable-feature PGD after multi-epsilon adversarial fine-tuning."),
        heading("10. Defense Evaluation", 1),
        heading("10.1 Adv+ExtraTrees Transfer-PGD Defense", 2),
        paragraph("The strongest defense result is obtained by evaluating transfer-PGD examples generated against the differentiable adversarial Torch surrogate and then passing them to the non-differentiable Adv+ExtraTrees ensemble. The final ensemble reduces transfer evasion to 0.50% at eps 0.03 and to 0.00% at eps 0.06, 0.10, and 0.15. This is the central security result of the project."),
        table(tables["transfer_rows"]),
        ("image", "adv_tree_transfer_pgd_defense.png", "Figure 12. Transfer-PGD defense of the selected Adv+ExtraTrees ensemble."),
        heading("10.2 Security-OR High-Security Mode", 2),
        paragraph("The calibrated Security-OR mode also reaches 0.00% transfer-PGD evasion at all evaluated budgets. Its clean F1 is lower than the selected Adv+ExtraTrees ensemble, so it is best interpreted as an alternative high-security operating point for situations where reducing false negatives is more important than preserving the best clean operating balance."),
        table(tables["sec_rows"]),
        ("image", "security_or_transfer_pgd_defense.png", "Figure 13. Transfer-PGD defense of the calibrated Security-OR mode."),
        heading("10.3 Negative Control and RF Adversarial Training", 2),
        paragraph("Feature randomisation is included as a negative-control defense and does not reduce the RF SHAP-guided local attack, confirming that naive randomisation is insufficient. A separate adversarially trained binary RF reduces the binary local top-10 eps 0.10 SHAP attack from 4.59% evasion to 0.00%, but its clean binary F1 remains below the final Adv+ExtraTrees model."),
        heading("11. Limitations", 1),
        paragraph("The first limitation is the dataset itself. NSL-KDD is useful for controlled benchmarking but is old and does not represent modern encrypted, cloud, and lateral-movement traffic. The KDDTest+ split also contains a deliberate train-test distribution shift, so validation performance is much easier than the final test evaluation. The second limitation is class imbalance. R2L and U2R contain far fewer examples than DoS and Probe, so their recalls remain lower even after the improvements. The third limitation is adversarial realism. Full-feature PGD is a strong stress test, but it can modify one-hot and binary fields that would not always be mutable in a real network connection. For this reason, mutable-feature PGD is reported separately. Finally, the defense results are empirical rather than certified; they show robustness against the implemented attacks, not a formal guarantee against all possible adaptive adversaries."),
        heading("12. Deliverables and Reproducibility", 1),
        paragraph("The deliverables are stored under the new directory and the new/deliverables package. The main code is pipeline_cuda.py. The final numerical output is outputs_cuda/summary.json. The final report is Project5_CUDA_Report_final_heavy.docx. The generated figures are copied under new/deliverables/images. The report can be reproduced by running the CUDA pipeline with ENABLE_MULTI_EPS_ADV_TRAIN=1, ENABLE_SHAP_ROBUST_ET=1, and ENABLE_HEAVY_ADV_TREE_XAI=1."),
        heading("13. Conclusion", 1),
        paragraph("The project demonstrates that explainability improves IDS interpretability but also creates a security tradeoff. Stable attributions help analysts understand model decisions, yet they also reveal consistent manipulation directions that can be exploited by explanation-guided attacks. The final Adv+ExtraTrees Ensemble IDS provides the best operational balance in this project. It improves clean binary detection, gives strong rare-family recall, supports direct ensemble explanation, and substantially reduces transfer-PGD evasion. The calibrated Security-OR operating point further shows that stricter thresholding can eliminate the tested transfer-PGD evasion, but with lower clean performance. The recommended submitted model is therefore the Adv+ExtraTrees Ensemble IDS, with Security-OR documented as an optional high-security configuration."),
        heading("References", 1),
        paragraph("Tavallaee, M., Bagheri, E., Lu, W., and Ghorbani, A. A. (2009). A detailed analysis of the KDD CUP 99 data set. IEEE Symposium on Computational Intelligence for Security and Defense Applications.\nLundberg, S. M., Erion, G., Chen, H., et al. (2020). From local explanations to global understanding with explainable AI for trees. Nature Machine Intelligence.\nSundararajan, M., Taly, A., and Yan, Q. (2017). Axiomatic attribution for deep networks. International Conference on Machine Learning.\nGoodfellow, I. J., Shlens, J., and Szegedy, C. (2015). Explaining and harnessing adversarial examples. International Conference on Learning Representations.\nMadry, A., Makelov, A., Schmidt, L., Tsipras, D., and Vladu, A. (2018). Towards deep learning models resistant to adversarial attacks. International Conference on Learning Representations."),
    ]


def build_markdown(summary):
    adv = summary["models"]["adv_tree_ensemble"]
    sec = summary["models"]["security_or_ensemble"]
    return f"""# Project 5: Explainable IDS - Final Heavy Report Summary

Selected model: Adv+ExtraTrees Ensemble IDS.

- Binary F1: {f4(adv["binary_macro_f1"])}
- PR-AUC: {f4(adv["pr_auc"])}
- Balanced accuracy: {f4(adv["balanced_accuracy"])}
- R2L recall: {f4(adv["per_family_recall"]["R2L"])}
- U2R recall: {f4(adv["per_family_recall"]["U2R"])}

Security-OR is documented as an optional high-security operating point, not the selected final model.

- Security-OR binary F1: {f4(sec["binary_macro_f1"])}
- Security-OR balanced accuracy: {f4(sec["balanced_accuracy"])}
- Security-OR transfer-PGD evasion: 0.00% for eps 0.03, 0.06, 0.10, and 0.15.

The final `.docx` report contains the full formal analysis, figures, limitations, and deliverables.
"""


def build_document_xml(summary, image_map):
    parts, tables = build_report_parts(summary)
    all_parts = parts + remaining_parts(tables)
    body = []
    rels = []
    media_files = []
    rel_counter = 1
    for item in all_parts:
        if isinstance(item, tuple) and item[0] == "image":
            image_name, caption = item[1], item[2]
            path = OUTPUTS / image_name
            if not path.exists():
                continue
            rel_id = f"rId{rel_counter}"
            rel_counter += 1
            target = f"media/final_{image_name}"
            rels.append((rel_id, target))
            media_files.append((path, f"word/{target}"))
            body.append(image_paragraph(rel_id, image_name, path))
            body.append(paragraph(caption, style="Caption", align="center"))
        else:
            body.append(item)
    sect = (
        '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
        '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="708" w:footer="708" w:gutter="0"/>'
        '<w:cols w:space="708"/><w:docGrid w:linePitch="360"/></w:sectPr>'
    )
    xml = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<w:document xmlns:w="{W}" xmlns:r="{R}" xmlns:wp="{WP}" xmlns:a="{A}" xmlns:pic="{PIC}">'
        f"<w:body>{''.join(body)}{sect}</w:body></w:document>"
    )
    rel_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(
            f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="{target}"/>'
            for rid, target in rels
        )
        + "</Relationships>"
    )
    return xml.encode("utf-8"), rel_xml.encode("utf-8"), media_files


def ensure_content_types(content):
    text = content.decode("utf-8")
    if 'Extension="png"' not in text:
        text = text.replace("</Types>", '<Default Extension="png" ContentType="image/png"/></Types>')
    return text.encode("utf-8")


def write_docx(summary):
    document_xml, rels_xml, media_files = build_document_xml(summary, {})
    with zipfile.ZipFile(TEMPLATE_DOCX, "r") as zin, zipfile.ZipFile(REPORT_DOCX, "w", zipfile.ZIP_DEFLATED) as zout:
        skip = {"word/document.xml", "word/_rels/document.xml.rels"}
        media_targets = {target for _, target in media_files}
        for item in zin.infolist():
            if item.filename in skip or item.filename in media_targets:
                continue
            data = zin.read(item.filename)
            if item.filename == "[Content_Types].xml":
                data = ensure_content_types(data)
            zout.writestr(item, data)
        zout.writestr("word/document.xml", document_xml)
        zout.writestr("word/_rels/document.xml.rels", rels_xml)
        for src, target in media_files:
            zout.write(src, target)


def write_claude_prompt():
    prompt = """Create a formal 10-12 slide PowerPoint presentation for the attached Project 5 report about an Explainable Intrusion Detection System on NSL-KDD.

Use a professional academic cybersecurity style. Keep slides concise, with clear visuals and speaker notes. Use the figures from the report where appropriate.

Required slide structure:
1. Title slide: Project 5 Explainable IDS, NSL-KDD, group names, date.
2. Problem and objective: explain IDS interpretability, stability, and adversarial risk.
3. Dataset and preprocessing: KDDTrain+/KDDTest+, 478 features, family mapping, feature engineering.
4. Model pipeline: Logistic Regression baseline, Random Forest, Torch MLP, Torch Binary MLP, SHAP-Robust ExtraTrees, Adv+ExtraTrees Ensemble.
5. Main clean results: show that Adv+ExtraTrees is selected with binary F1 0.9063, PR-AUC 0.9626, balanced accuracy 0.9064.
6. Rare-family recall: emphasize R2L recall 0.6786 and U2R recall 0.8060.
7. Explainability: TreeSHAP, Integrated Gradients, SmoothIG, combined ensemble explanation; include top features.
8. Stability analysis: local Jaccard/rank and bootstrap stability; explain dual-use implication.
9. Adversarial attacks: SHAP-guided, IG-guided, PGD, mutable-feature PGD.
10. Defense results: transfer-PGD reduced to 0.50% at eps 0.03 and 0.00% at eps 0.06/0.10/0.15 for Adv+ExtraTrees.
11. Limitations: NSL-KDD age, distribution shift, rare classes, full-feature PGD realism, empirical not certified robustness.
12. Conclusion: Adv+ExtraTrees is final selected model; Security-OR is optional high-security mode.

Important numbers:
- Adv+ExtraTrees binary F1: 0.9063
- Adv+ExtraTrees PR-AUC: 0.9626
- Adv+ExtraTrees balanced accuracy: 0.9064
- Final recall: DoS 0.9859, Probe 1.0000, R2L 0.6786, U2R 0.8060
- Adv+ExtraTrees transfer-PGD evasion: 0.50%, 0.00%, 0.00%, 0.00% for eps 0.03, 0.06, 0.10, 0.15
- Security-OR transfer-PGD evasion: 0.00% at all tested eps values, but lower clean F1 0.8796, so it is not the selected final model.

Please generate the `.pptx` file with clean tables, readable charts, and short speaker notes for each slide.
"""
    CLAUDE_PROMPT.write_text(prompt, encoding="utf-8")


def copy_deliverables():
    DELIVERABLES.mkdir(exist_ok=True)
    IMAGES_DIR.mkdir(exist_ok=True)
    for src in [
        REPORT_DOCX,
        REPORT_MD,
        CLAUDE_PROMPT,
        ROOT / "pipeline_cuda.py",
        SUMMARY_JSON,
        NEW / "final_heavy_results_for_report.md",
        NEW / "heavy_run_results_interpretation.md",
    ]:
        if src.exists():
            shutil.copy2(src, DELIVERABLES / src.name)
    for image in OUTPUTS.glob("*.png"):
        shutil.copy2(image, IMAGES_DIR / image.name)


def main():
    summary = load_summary()
    write_docx(summary)
    REPORT_MD.write_text(build_markdown(summary), encoding="utf-8")
    write_claude_prompt()
    copy_deliverables()
    print(f"Wrote {REPORT_DOCX}")
    print(f"Wrote {REPORT_MD}")
    print(f"Wrote {CLAUDE_PROMPT}")
    print(f"Wrote deliverables to {DELIVERABLES}")


if __name__ == "__main__":
    main()
