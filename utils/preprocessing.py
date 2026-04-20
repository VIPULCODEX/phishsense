import re
from typing import List

URL_PATTERN = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)


def extract_urls(text: str) -> List[str]:
    if not isinstance(text, str):
        return []
    return URL_PATTERN.findall(text)


def preprocess_text(text: str) -> str:
    """
    Lightweight text normalization:
    1. Lowercase
    2. Preserve URLs
    3. Remove special chars from non-URL text
    4. Collapse extra spaces
    """
    if not isinstance(text, str):
        return ""

    lowered = text.lower().strip()
    urls = extract_urls(lowered)

    no_urls = URL_PATTERN.sub(" ", lowered)
    no_urls = re.sub(r"[^a-z0-9\s]", " ", no_urls)
    no_urls = re.sub(r"\s+", " ", no_urls).strip()

    if urls:
        return f"{no_urls} {' '.join(urls)}".strip()
    return no_urls

