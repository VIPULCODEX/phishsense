import re
from typing import Dict, List
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rb.gy",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {"xyz", "top", "click", "work", "gq", "tk", "ml", "cf", "buzz"}


def extract_urls(text: str) -> List[str]:
    if not isinstance(text, str):
        return []
    return URL_PATTERN.findall(text)


def _parse_domain(url: str) -> str:
    candidate = url if url.startswith(("http://", "https://")) else f"http://{url}"
    parsed = urlparse(candidate)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _looks_random_domain(domain: str) -> bool:
    core = domain.split(".")[0]
    has_digits = any(ch.isdigit() for ch in core)
    long_core = len(core) >= 12
    many_hyphens = core.count("-") >= 2
    return (has_digits and long_core) or many_hyphens


def analyze_urls(text: str) -> Dict:
    urls = extract_urls(text)
    suspicious_urls: List[str] = []
    reasons: List[str] = []

    for url in urls:
        domain = _parse_domain(url)
        if not domain:
            continue

        tld = domain.split(".")[-1] if "." in domain else ""
        is_shortener = domain in SHORTENERS
        suspicious_tld = tld in SUSPICIOUS_TLDS
        random_domain = _looks_random_domain(domain)

        if is_shortener or suspicious_tld or random_domain:
            suspicious_urls.append(url)

        if is_shortener and "Shortened link detected" not in reasons:
            reasons.append("Shortened link detected")
        if suspicious_tld and "Suspicious domain extension found" not in reasons:
            reasons.append("Suspicious domain extension found")
        if random_domain and "Random-looking domain detected" not in reasons:
            reasons.append("Random-looking domain detected")

    flag = "Suspicious" if suspicious_urls else "Safe"
    return {
        "flag": flag,
        "urls": urls,
        "suspicious_urls": suspicious_urls,
        "reasons": reasons,
    }

