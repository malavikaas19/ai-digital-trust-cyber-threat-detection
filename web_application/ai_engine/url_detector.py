
"""Offline URL risk detector using explainable lexical rules."""

from urllib.parse import urlparse
import ipaddress
import re


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co",
    "is.gd", "cutt.ly", "goo.gl"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure",
    "account", "bank", "password", "wallet",
    "gift", "free", "claim", "confirm"
}


def extract_url_features(url: str) -> dict:

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a non-empty URL.")

    candidate = url.strip()

    parsed = urlparse(
        candidate if "://" in candidate else "http://" + candidate
    )

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
    """
    Explainable URL risk assessment.

    This is a heuristic prototype. It does not visit the URL,
    verify website ownership, or check external reputation databases.
    """

    features = extract_url_features(url)

    score = 0.0
    reasons = []

    checks = [
        (features["uses_https"] == 0, 0.10,
         "URL does not use HTTPS."),

        (features["uses_ip_address"] == 1, 0.25,
         "Hostname is an IP address."),

        (features["has_at_symbol"] == 1, 0.20,
         "URL contains an @ symbol."),

        (features["is_shortened"] == 1, 0.20,
         "URL uses a known link-shortening domain."),

        (features["has_punycode"] == 1, 0.20,
         "Hostname contains punycode."),

        (features["url_length"] > 75, 0.10,
         "Unusually long URL."),

        (features["hyphen_count"] >= 3, 0.10,
         "Hostname contains several hyphens."),

        (features["suspicious_word_count"] >= 2, 0.20,
         "URL contains multiple sensitive or lure-related words."),

        (features["dot_count"] >= 4, 0.10,
         "Hostname has an unusually high number of subdomains."),

        (features["has_port"] == 1, 0.05,
         "URL specifies a non-default port."),
    ]

    for condition, weight, reason in checks:
        if condition:
            score += weight
            reasons.append(reason)

    score = min(score, 1.0)

    risk_percentage = round(score * 100)
    trust_score = 100 - risk_percentage

    if risk_percentage >= 30:
        label = "Suspicious"
        risk_level = "High Risk"
    elif risk_percentage >= 15:
        label = "Needs Review"
        risk_level = "Medium Risk"
    else:
        label = "Safe"
        risk_level = "Low Risk"

    return {
        "label": label,
        "risk_level": risk_level,
        "suspicious_probability": round(score, 4),
        "trust_score": trust_score,
        "reasons": reasons or [
            "No listed URL risk indicators were detected."
        ],
        "features": features,
        "model_note": (
            "Explainable lexical heuristic. "
            "This is an estimated risk score, not a validated "
            "machine-learning probability. The URL was not opened "
            "or reputation-checked."
        )
    }
