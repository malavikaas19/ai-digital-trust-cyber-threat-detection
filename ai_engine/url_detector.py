
"""Explainable URL risk detector for the Digital Trust System.

Uses lexical URL features and weighted rules.
Does not visit websites or perform live reputation checks.
"""

from urllib.parse import urlparse
import ipaddress
import re


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "goo.gl",
    "ow.ly",
    "buff.ly",
}

SUSPICIOUS_WORDS = {
    "login", "verify", "update", "secure", "account",
    "bank", "password", "wallet", "gift", "free",
    "claim", "confirm", "signin", "payment",
    "credential", "unlock", "suspended",
}


def extract_url_features(url: str) -> dict:
    """Extract explainable lexical features from a URL."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a non-empty URL.")

    candidate = url.strip()

    if any(char.isspace() for char in candidate):
        raise ValueError("URL must not contain spaces.")

    parsed = urlparse(
        candidate if "://" in candidate else "http://" + candidate
    )

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    host = (parsed.hostname or "").lower()

    if not host:
        raise ValueError("The URL does not contain a valid hostname.")

    try:
        parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")

    try:
        ipaddress.ip_address(host)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    tokens = set(re.findall(r"[a-z0-9]+", candidate.lower()))

    hostname_parts = host.split(".")

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
        "subdomain_count": max(0, len(hostname_parts) - 2),
        "has_encoded_characters": int("%" in candidate),
        "has_double_slash_redirect": int("//" in parsed.path),
    }


def detect_url(url: str) -> dict:
    """Return a heuristic URL risk assessment."""

    features = extract_url_features(url)

    score = 0.0
    reasons = []

    checks = [
        (
            features["uses_https"] == 0,
            0.10,
            "URL does not use HTTPS."
        ),
        (
            features["uses_ip_address"] == 1,
            0.25,
            "Hostname is an IP address."
        ),
        (
            features["has_at_symbol"] == 1,
            0.20,
            "URL contains an @ symbol."
        ),
        (
            features["is_shortened"] == 1,
            0.20,
            "URL uses a known link-shortening domain."
        ),
        (
            features["has_punycode"] == 1,
            0.20,
            "Hostname contains punycode."
        ),
        (
            features["url_length"] > 75,
            0.10,
            "URL is unusually long."
        ),
        (
            features["hyphen_count"] >= 3,
            0.10,
            "Hostname contains several hyphens."
        ),
        (
            features["suspicious_word_count"] >= 2,
            0.20,
            "URL contains multiple sensitive or lure-related words."
        ),
        (
            features["dot_count"] >= 4,
            0.10,
            "Hostname has an unusually high number of subdomains."
        ),
        (
            features["has_port"] == 1,
            0.05,
            "URL specifies a non-default port."
        ),
        (
            features["has_encoded_characters"] == 1,
            0.05,
            "URL contains encoded characters."
        ),
        (
            features["has_double_slash_redirect"] == 1,
            0.10,
            "URL path contains a double-slash pattern."
        ),
    ]

    for condition, weight, reason in checks:
        if condition:
            score += weight
            reasons.append(reason)

    score = min(score, 1.0)

    label = "Suspicious" if score >= 0.30 else "Safe"

    return {
        "label": label,
        "suspicious_probability": round(score, 4),
        "confidence": round(max(score, 1 - score), 4),
        "reasons": reasons or [
            "No listed URL risk indicators were detected."
        ],
        "features": features,
        "model_note": (
            "Explainable lexical heuristic. "
            "This is not a trained ML model. "
            "The URL was not opened or reputation-checked."
        )
    }
