"""Combine message and URL detection results into a digital trust score."""
def calculate_trust_score(message_result=None, url_result=None) -> dict:
    """Calculate a 0-100 score (higher means lower detected risk).

    Inputs are dictionaries returned by detect_message() and detect_url().
    Either input may be omitted. If both are omitted, score is 100.
    """
    risks = []
    if message_result is not None:
        risks.append(("message", float(message_result["suspicious_probability"]), 0.5))
    if url_result is not None:
        risks.append(("url", float(url_result["suspicious_probability"]), 0.5))

    if not risks:
        return {"trust_score": 100, "risk_level": "Low Risk",
                "risk_probability": 0.0, "breakdown": {}}

    total_weight = sum(weight for _, _, weight in risks)
    risk = sum(prob * weight for _, prob, weight in risks) / total_weight
    score = round((1 - risk) * 100)

    if score >= 80:
        level = "Low Risk"
    elif score >= 50:
        level = "Medium Risk"
    else:
        level = "High Risk"

    return {
        "trust_score": score,
        "risk_level": level,
        "risk_probability": round(risk, 4),
        "breakdown": {name: round(prob, 4) for name, prob, _ in risks}
    }
