import argparse
import json
import os
import pickle
from typing import Dict

from utils.rules import evaluate_rules
from utils.url_checker import analyze_urls

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")
SAFE_LABEL = "safe"


def load_model(model_path: str = MODEL_PATH):
    with open(model_path, "rb") as f:
        artifacts = pickle.load(f)
    return artifacts["pipeline"]


def _normalize_rule_scores(rule_scores: Dict[str, float]) -> Dict[str, float]:
    total = sum(max(v, 0.0) for v in rule_scores.values())
    if total == 0:
        return {SAFE_LABEL: 1.0}
    return {k: max(v, 0.0) / total for k, v in rule_scores.items()}


def analyze_text(text: str, model=None) -> Dict:
    if model is None:
        model = load_model()

    probabilities = model.predict_proba([text])[0]
    class_labels = model.named_steps["classifier"].classes_
    ml_probs = {cls: float(prob) for cls, prob in zip(class_labels, probabilities)}

    safe_prob = ml_probs.get(SAFE_LABEL, 0.0)
    ml_risk = (1.0 - safe_prob) * 100.0

    rule_result = evaluate_rules(text)
    url_result = analyze_urls(text)

    rule_score = rule_result["score"]
    reasons = list(rule_result["reasons"])
    highlighted_words = set(rule_result["highlighted_words"])

    if url_result["flag"] == "Suspicious":
        rule_score = min(100, rule_score + 15)
        reasons.append("Suspicious URL found")
        highlighted_words.update(url_result["suspicious_urls"])
    elif url_result["urls"]:
        reasons.append("URL present but no high-risk domain pattern found")

    for r in url_result["reasons"]:
        if r not in reasons:
            reasons.append(r)

    rule_class_scores = dict(rule_result["class_scores"])
    if url_result["flag"] == "Suspicious":
        rule_class_scores["phishing"] = rule_class_scores.get("phishing", 0.0) + 20.0

    rule_probs = _normalize_rule_scores(rule_class_scores)
    combined_probs = {
        cls: 0.6 * ml_probs.get(cls, 0.0) + 0.4 * rule_probs.get(cls, 0.0)
        for cls in ml_probs
    }

    prediction = max(combined_probs, key=combined_probs.get)
    final_risk = int(round(0.6 * ml_risk + 0.4 * rule_score))
    final_risk = max(0, min(100, final_risk))

    if final_risk < 35 and safe_prob >= 0.40 and rule_score < 30:
        prediction = SAFE_LABEL

    if prediction != SAFE_LABEL and "No major scam indicators found" in reasons:
        reasons.remove("No major scam indicators found")
    if not reasons:
        reasons = ["No major scam indicators found"]

    return {
        "prediction": prediction,
        "risk_score": final_risk,
        "reasons": reasons,
        "highlighted_words": sorted(highlighted_words),
        "url_flag": url_result["flag"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="PhishGuard AI inference")
    parser.add_argument(
        "--text",
        type=str,
        required=True,
        help="Input message to analyze",
    )
    args = parser.parse_args()

    result = analyze_text(args.text)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
