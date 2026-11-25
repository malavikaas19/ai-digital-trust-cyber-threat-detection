"""Offline URL risk detector using lexical URL features and explainable rules."""
from urllib.parse import urlparse
import ipaddress
import re

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl"}
SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account", "bank",
    "password", "wallet", "gift", "free", "claim", "confirm"
}

def extract_url_features(url: str) -> dict:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a non-empty URL.")
    candidate = url.strip()
    parsed = urlparse(candidate if "://" in candidate else "http://" + candidate)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("The URL does not contain a valid hostname.")

    try:
        ipaddress.ip_address(host)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    tokens = set(re.findall(r"[a-z0-9]+", candidate.lower()))
    return {
        "url_length": len(candidate),
        "hostname_length": len(host),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "uses_https": int(parsed.scheme.lower() == "https"),
        "uses_ip_address": uses_ip,
        "has_at_symbol": int("@" in candidate),
        "has_port": int(parsed.port is not None),
        "is_shortened": int(host in SHORTENERS),
        "suspicious_word_count": len(tokens & SUSPICIOUS_WORDS),
        "has_punycode": int("xn--" in host),
    }

def detect_url(url: str) -> dict:
    """Return Safe/Suspicious assessment and feature-based reasons.

    This is a heuristic prototype, not a reputation lookup or proof that a
    website is safe. It does not visit the URL.
    """
    f = extract_url_features(url)
    score = 0.0
    reasons = []

    checks = [
        (f["uses_https"] == 0, 0.10, "URL does not use HTTPS."),
        (f["uses_ip_address"] == 1, 0.25, "Hostname is an IP address."),
        (f["has_at_symbol"] == 1, 0.20, "URL contains an @ symbol."),
        (f["is_shortened"] == 1, 0.20, "URL uses a known link-shortening domain."),
        (f["has_punycode"] == 1, 0.20, "Hostname contains punycode."),
        (f["url_length"] > 75, 0.10, "Unusually long URL."),
        (f["hyphen_count"] >= 3, 0.10, "Hostname contains several hyphens."),
        (f["suspicious_word_count"] >= 2, 0.20, "URL contains multiple sensitive or lure-related words."),
        (f["dot_count"] >= 4, 0.10, "Hostname has an unusually high number of subdomains."),
        (f["has_port"] == 1, 0.05, "URL specifies a non-default port."),
    ]
    for condition, weight, reason in checks:
        if condition:
            score += weight
            reasons.append(reason)

    score = min(score, 1.0)
    return {
        "label": "Suspicious" if score >= 0.30 else "Safe",
        "suspicious_probability": round(score, 4),
        "confidence": round(max(score, 1 - score), 4),
        "reasons": reasons or ["No listed URL risk indicators were detected."],
        "features": f,
        "model_note": "Explainable lexical heuristic; URL was not opened or reputation-checked."
    }
