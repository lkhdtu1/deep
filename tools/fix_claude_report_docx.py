import shutil
import struct
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "Project5_CUDA_Report_final_regenerated (1).docx"
OUT = ROOT / "Project5_CUDA_Report_final_regenerated_corrected.docx"
STABILITY_IMAGE = ROOT / "outputs_cuda" / "ig_stability.png"

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "pic": "http://schemas.openxmlformats.org/drawingml/2006/picture",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
}

for prefix, uri in NS.items():
    if prefix != "rel":
        ET.register_namespace(prefix, uri)


REPLACEMENTS = {
    "Eleven models trained: Logistic Regression, Random Forest, Torch MLP, Torch Binary MLP, PGD-Adversarial Torch MLP, Binary RF, ExtraTrees, XGBoost, SHAP-Robust ExtraTrees, and two ensemble configurations.":
        "Eleven models trained: Logistic Regression, Random Forest, Torch MLP, Torch Binary MLP, PGD-Adversarial Torch Binary MLP, Binary RF, ExtraTrees, XGBoost, SHAP-Robust ExtraTrees, and two ensemble configurations.",
    "TreeSHAP (RF), Integrated Gradients (Torch MLP), SmoothIG (Torch Binary MLP), weighted ensemble SHAP explanation for final model.":
        "TreeSHAP (RF), Integrated Gradients (Torch MLP), SmoothIG (Torch Binary MLP), and a combined weighted ensemble explanation for the final model.",
    "Random Forest with TreeSHAP: 100 trees, bootstrapped, with TreeSHAP for exact Shapley value computation. This model is the primary source of global feature attribution and SHAP-guided evasion evaluation.":
        "Random Forest with TreeSHAP: the final Random Forest variation uses the selected configuration n_estimators=320, max_depth=24, and min_samples_leaf=2. TreeSHAP is then applied for exact tree-ensemble Shapley attribution. This model is the primary source of global feature attribution and SHAP-guided evasion evaluation.",
    "Binary RF IDS, Binary ExtraTrees IDS, Binary XGBoost IDS: Tree ensemble variants with threshold optimization on the training PR-curve to maximize F1.":
        "Binary RF IDS, Binary ExtraTrees IDS, Binary XGBoost IDS: tree ensemble variants with thresholds tuned on validation splits derived from the training data. This avoids using KDDTest+ for model selection while still selecting an operational threshold that balances precision and recall.",
    "SHAP-Robust ExtraTrees IDS: An ExtraTrees classifier augmented with SHAP-guided feature deweighting: features identified as most used in prior SHAP-guided evasion attacks are downweighted via sample reweighting during training, reducing the model's reliance on easily manipulable features.":
        "SHAP-Robust ExtraTrees IDS: an ExtraTrees classifier augmented with SHAP-guided adversarial samples. The pipeline identifies influential features through SHAP on attack records, generates perturbed adversarial examples along those important directions, and adds those examples to the training set with attack labels. This is adversarial data augmentation, not manual feature deweighting, and it improves the tree component's robustness to explanation-guided feature manipulation.",
    "Adv+ExtraTrees Ensemble IDS (final selected model): A soft-voting ensemble combining the adversarially trained Torch Binary MLP (weight 0.15) with the SHAP-Robust ExtraTrees (weight 0.85). The vote threshold is optimized at 0.15 on the training data. The higher weight on the tree component reflects its superior clean-data precision; the neural component contributes principally adversarial robustness via architectural heterogeneity.":
        "Adv+ExtraTrees Ensemble IDS (final selected model): a soft-voting ensemble combining the adversarially trained Torch Binary MLP (weight 0.15) with the SHAP-Robust ExtraTrees (weight 0.85). The ensemble threshold is selected on a validation split with a robustness-aware objective that considers both clean binary F1 and transfer-PGD evasion. The higher weight on the tree component reflects its stronger clean-data behavior, while the neural component contributes architectural diversity and provides the differentiable surrogate used during robustness evaluation.",
    "Table 5.1 summarizes clean test performance on KDDTest+ for all trained models. Thresholds for binary models are optimized on KDDTrain+ to maximize binary F1. The pipeline was executed on an NVIDIA GeForce RTX 3060 Laptop GPU using PyTorch 2.6.0+cu124 (CUDA 12.4). The Random Forest was selected with n_estimators=320, max_depth=24, min_samples_leaf=2 after grid search (validation macro-F1=0.9469). The Torch MLP converged at epoch 32 (validation macro-F1=0.7478). The Torch Binary MLP converged at epoch 40 (validation binary-F1=0.9988).":
        "Table 5.1 summarizes clean test performance on KDDTest+ for all trained models. Model hyperparameters and thresholds are selected using validation splits derived from KDDTrain+, while KDDTest+ is reserved for the final evaluation. The pipeline was executed on an NVIDIA GeForce RTX 3060 Laptop GPU using PyTorch 2.6.0+cu124 (CUDA 12.4). The Random Forest was selected with n_estimators=320, max_depth=24, min_samples_leaf=2 after grid search (validation macro-F1=0.9469). The Torch MLP converged at epoch 32 (validation macro-F1=0.7478). The Torch Binary MLP converged at epoch 40 (validation binary-F1=0.9988).",
    "The Adv+ExtraTrees Ensemble IDS achieves the highest binary F1 score of 0.9063 and balanced accuracy of 0.9064 across all evaluated models, with a strong PR-AUC of 0.9626 at threshold 0.15. The ensemble combines the adversarially trained Torch Binary MLP (weight 0.15) with the SHAP-Robust ExtraTrees (weight 0.85), reflecting that the tree component provides more reliable clean-data detection while the neural component contributes adversarial robustness. The SHAP-Robust ExtraTrees alone reaches F1=0.8912, demonstrating the value of SHAP-guided feature deweighting over vanilla ExtraTrees (F1=0.7969).":
        "The Adv+ExtraTrees Ensemble IDS achieves the highest binary F1 score of 0.9063 and balanced accuracy of 0.9064 across all evaluated models, with a strong PR-AUC of 0.9626 at threshold 0.15. The ensemble combines the adversarially trained Torch Binary MLP (weight 0.15) with the SHAP-Robust ExtraTrees (weight 0.85), reflecting that the tree component provides more reliable clean-data detection while the neural component contributes architectural diversity and a robustness-trained surrogate. The SHAP-Robust ExtraTrees alone reaches F1=0.8912, demonstrating the value of SHAP-guided adversarial augmentation over vanilla ExtraTrees (F1=0.7969).",
    "PGD-Adversarial Torch MLP":
        "PGD-Adversarial Torch Binary MLP",
    "Figure 9.2: Transfer PGD Defense — Security-OR Ensemble. Complete blockage of all tested adversarial examples at the cost of higher false positive rate.":
        "Figure 9.2: Transfer PGD Defense — Security-OR Ensemble. Under the tested transfer-PGD threat model, Security-OR produces 0.00% evasion at all evaluated epsilon values. This result should be interpreted as an optional high-security operating point rather than the selected final model, because its clean binary F1 is lower than the Adv+ExtraTrees ensemble.",
}


def para_text(p):
    return "".join(t.text or "" for t in p.findall(".//w:t", NS)).strip()


def set_para_text(p, text):
    ppr = p.find("w:pPr", NS)
    rpr = None
    first_r = p.find("w:r", NS)
    if first_r is not None:
        found = first_r.find("w:rPr", NS)
        if found is not None:
            rpr = ET.fromstring(ET.tostring(found))
    for child in list(p):
        p.remove(child)
    if ppr is not None:
        p.append(ppr)
    r = ET.SubElement(p, f"{{{NS['w']}}}r")
    if rpr is not None:
        r.append(rpr)
    t = ET.SubElement(r, f"{{{NS['w']}}}t")
    t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    t.text = text


def png_size(path):
    with path.open("rb") as handle:
        sig = handle.read(24)
    if sig[:8] != b"\x89PNG\r\n\x1a\n":
        return 1200, 700
    return struct.unpack(">II", sig[16:24])


def make_image_run(rel_id, doc_id, name, path, max_width_inches=6.4):
    width_px, height_px = png_size(path)
    cx = int(max_width_inches * 914400)
    cy = int(cx * height_px / max(width_px, 1))

    r = ET.Element(f"{{{NS['w']}}}r")
    drawing = ET.SubElement(r, f"{{{NS['w']}}}drawing")
    inline = ET.SubElement(drawing, f"{{{NS['wp']}}}inline", {
        "distT": "0", "distB": "0", "distL": "0", "distR": "0",
    })
    ET.SubElement(inline, f"{{{NS['wp']}}}extent", {"cx": str(cx), "cy": str(cy)})
    ET.SubElement(inline, f"{{{NS['wp']}}}effectExtent", {"l": "0", "t": "0", "r": "0", "b": "0"})
    ET.SubElement(inline, f"{{{NS['wp']}}}docPr", {"id": str(doc_id), "name": name})
    c_nv = ET.SubElement(inline, f"{{{NS['wp']}}}cNvGraphicFramePr")
    ET.SubElement(c_nv, f"{{{NS['a']}}}graphicFrameLocks", {"noChangeAspect": "1"})
    graphic = ET.SubElement(inline, f"{{{NS['a']}}}graphic")
    graphic_data = ET.SubElement(graphic, f"{{{NS['a']}}}graphicData", {
        "uri": "http://schemas.openxmlformats.org/drawingml/2006/picture",
    })
    pic = ET.SubElement(graphic_data, f"{{{NS['pic']}}}pic")
    nv = ET.SubElement(pic, f"{{{NS['pic']}}}nvPicPr")
    ET.SubElement(nv, f"{{{NS['pic']}}}cNvPr", {"id": str(doc_id), "name": name})
    ET.SubElement(nv, f"{{{NS['pic']}}}cNvPicPr")
    blip_fill = ET.SubElement(pic, f"{{{NS['pic']}}}blipFill")
    ET.SubElement(blip_fill, f"{{{NS['a']}}}blip", {f"{{{NS['r']}}}embed": rel_id})
    stretch = ET.SubElement(blip_fill, f"{{{NS['a']}}}stretch")
    ET.SubElement(stretch, f"{{{NS['a']}}}fillRect")
    sppr = ET.SubElement(pic, f"{{{NS['pic']}}}spPr")
    xfrm = ET.SubElement(sppr, f"{{{NS['a']}}}xfrm")
    ET.SubElement(xfrm, f"{{{NS['a']}}}off", {"x": "0", "y": "0"})
    ET.SubElement(xfrm, f"{{{NS['a']}}}ext", {"cx": str(cx), "cy": str(cy)})
    geom = ET.SubElement(sppr, f"{{{NS['a']}}}prstGeom", {"prst": "rect"})
    ET.SubElement(geom, f"{{{NS['a']}}}avLst")
    return r


def replace_placeholder_with_image(root, rel_id):
    for p in root.findall(".//w:p", NS):
        if para_text(p) != "[Figure not available]":
            continue
        ppr = p.find("w:pPr", NS)
        for child in list(p):
            p.remove(child)
        if ppr is not None:
            p.append(ppr)
        if ppr is None:
            ppr = ET.SubElement(p, f"{{{NS['w']}}}pPr")
        jc = ppr.find("w:jc", NS)
        if jc is None:
            ET.SubElement(ppr, f"{{{NS['w']}}}jc", {f"{{{NS['w']}}}val": "center"})
        else:
            jc.set(f"{{{NS['w']}}}val", "center")
        p.append(make_image_run(rel_id, 9001, "ig_stability.png", STABILITY_IMAGE))
        return True
    return False


def next_rid(rels_root):
    nums = []
    for rel in rels_root:
        rid = rel.attrib.get("Id", "")
        if rid.startswith("rId"):
            try:
                nums.append(int(rid[3:]))
            except ValueError:
                pass
    return f"rId{max(nums, default=0) + 1}"


def main():
    if not SRC.exists():
        raise FileNotFoundError(SRC)
    if not STABILITY_IMAGE.exists():
        raise FileNotFoundError(STABILITY_IMAGE)

    with zipfile.ZipFile(SRC, "r") as zin:
        document = ET.fromstring(zin.read("word/document.xml"))
        rels = ET.fromstring(zin.read("word/_rels/document.xml.rels"))

        changed = 0
        for p in document.findall(".//w:p", NS):
            text = para_text(p)
            if text in REPLACEMENTS:
                set_para_text(p, REPLACEMENTS[text])
                changed += 1

        rel_id = next_rid(rels)
        ET.SubElement(rels, f"{{{NS['rel']}}}Relationship", {
            "Id": rel_id,
            "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
            "Target": "media/ig_stability_fixed.png",
        })
        if replace_placeholder_with_image(document, rel_id):
            changed += 1

        with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename in {
                    "word/document.xml",
                    "word/_rels/document.xml.rels",
                    "word/media/ig_stability_fixed.png",
                }:
                    continue
                zout.writestr(item, zin.read(item.filename))
            zout.writestr("word/document.xml", ET.tostring(document, encoding="utf-8", xml_declaration=True))
            zout.writestr("word/_rels/document.xml.rels", ET.tostring(rels, encoding="utf-8", xml_declaration=True))
            zout.write(STABILITY_IMAGE, "word/media/ig_stability_fixed.png")

    print(f"Wrote {OUT}")
    print(f"Corrected paragraphs/images: {changed}")


if __name__ == "__main__":
    main()
