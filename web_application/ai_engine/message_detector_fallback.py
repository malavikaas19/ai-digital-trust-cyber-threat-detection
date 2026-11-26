
"""Rule-based fallback message detector.

This module does not use scikit-learn or external ML libraries.
Its risk estimate is heuristic, not a calibrated ML probability.
"""

import re


SUSPICIOUS_PATTERNS = [
    (
        r"\b(urgent|immediately|act now|limited time|verify now)\b",
        "Urgent or immediate-action language detected."
    ),
    (
        r"\b(password|otp|pin|bank details|credit card)\b",
        "Sensitive information is being mentioned."
    ),
    (
        r"\b(account.{0,20}(blocked|suspended|closed|locked))\b",
        "Message contains an account restriction warning."
    ),
    (
        r"\b(won|winner|prize|free gift|cashback)\b",
        "Prize, reward, or cashback language detected."
    ),
    (
        r"\b(pay.{0,15}(fee|charges|now))\b",
        "Message requests an urgent payment."
    ),
    (
        r"https?://|www\.",
        "Message contains a website link."
    ),
]


def detect_message(message: str) -> dict:

    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please provide a non-empty message.")

    reasons = []
    risk_points = 0

    for pattern, explanation in SUSPICIOUS_PATTERNS:

        if re.search(pattern, message, flags=re.IGNORECASE):

            reasons.append(explanation)

            if "website link" in explanation:
                risk_points += 10
            else:
                risk_points += 25

    suspicious_probability = min(risk_points / 100, 0.95)

    is_suspicious = suspicious_probability >= 0.25

    return {
        "label": "Suspicious" if is_suspicious else "Safe",
        "suspicious_probability": round(suspicious_probability, 4),
        "confidence": 0.0,
        "reasons": reasons or [
            "No listed suspicious message patterns were detected."
        ],
        "model_note": (
            "Rule-based fallback detector. "
            "This is not an ML model. "
            "Risk estimate is heuristic, not a calibrated probability. "
            "ML confidence is unavailable."
        )
    }
