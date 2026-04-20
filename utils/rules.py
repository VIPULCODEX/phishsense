import re
from typing import Dict, List, Set

from utils.url_checker import extract_urls

CLASSES = ["phishing", "otp_scam", "job_scam", "lottery", "safe"]

URGENCY_WORDS = {
    "urgent",
    "immediately",
    "immediate",
    "now",
    "asap",
    "quickly",
    "fast",
    "limited",
    "action",
    "alert",
}

PHISHING_WORDS = {
    "verify",
    "verification",
    "account",
    "kyc",
    "login",
    "suspended",
    "blocked",
    "confirm",
    "identity",
    "credentials",
    "bank",
    "debit",
    "upi",
    "pan",
}

OTP_WORDS = {"otp", "0tp"}

JOB_WORDS = {
    "job",
    "hiring",
    "salary",
    "work",
    "income",
    "earn",
    "registration",
    "selected",
    "offer",
    "amazon",
    "flipkart",
    "fee",
}

LOTTERY_WORDS = {
    "lottery",
    "winner",
    "win",
    "prize",
    "jackpot",
    "reward",
    "cashback",
    "bonus",
    "claim",
    "lakh",
    "money",
}

OBFUSCATION_PATTERNS = {
    r"\bcl[1i]ck\b": "click",
    r"\bfr[3e]{2}\b": "free",
    r"\b0tp\b": "otp",
    r"\bv[3e]rify\b": "verify",
}


def _find_keywords(tokens: Set[str], words: Set[str]) -> List[str]:
    return sorted(tokens.intersection(words))


def evaluate_rules(text: str) -> Dict:
    lowered = (text or "").lower()
    tokens = set(re.findall(r"[a-z0-9]+", lowered))

    score = 0
    reasons: List[str] = []
    highlighted_words: Set[str] = set()
    class_scores = {c: 0.0 for c in CLASSES}

    urgency_hits = _find_keywords(tokens, URGENCY_WORDS)
    if urgency_hits:
        score += 20
        reasons.append("Urgency detected")
        highlighted_words.update(urgency_hits)
        class_scores["phishing"] += 10

    phishing_hits = _find_keywords(tokens, PHISHING_WORDS)
    if phishing_hits:
        score += 25
        reasons.append("Account verification pressure detected")
        highlighted_words.update(phishing_hits)
        class_scores["phishing"] += 35

    otp_hits = _find_keywords(tokens, OTP_WORDS)
    if otp_hits:
        score += 40
        reasons.append("OTP solicitation detected")
        highlighted_words.update(otp_hits)
        class_scores["otp_scam"] += 70

    job_hits = _find_keywords(tokens, JOB_WORDS)
    if job_hits:
        score += 30
        reasons.append("Job/earning lure detected")
        highlighted_words.update(job_hits)
        class_scores["job_scam"] += 60

    lottery_hits = _find_keywords(tokens, LOTTERY_WORDS)
    if lottery_hits:
        score += 30
        reasons.append("Financial lure detected")
        highlighted_words.update(lottery_hits)
        class_scores["lottery"] += 60

    for pattern, canonical in OBFUSCATION_PATTERNS.items():
        if re.search(pattern, lowered):
            score += 15
            if "Obfuscated wording detected" not in reasons:
                reasons.append("Obfuscated wording detected")
            highlighted_words.add(canonical)
            if canonical == "otp":
                class_scores["otp_scam"] += 20
            elif canonical in {"verify", "click"}:
                class_scores["phishing"] += 10
            else:
                class_scores["lottery"] += 5

    if extract_urls(lowered):
        score += 5
        class_scores["phishing"] += 5

    score = min(score, 100)
    if score < 15:
        class_scores["safe"] = 100
        reasons = ["No major scam indicators found"]

    return {
        "score": score,
        "reasons": reasons,
        "highlighted_words": sorted(highlighted_words),
        "class_scores": class_scores,
    }

