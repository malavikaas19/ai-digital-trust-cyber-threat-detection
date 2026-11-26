
"""Digital Trust Score calculation module.

Combines message and URL detection results into an
explainable score from 0 to 100.
"""


def calculate_trust_score(message_result=None, url_result=None) -> dict:

    risks = []

    if message_result is not None:
        if "suspicious_probability" not in message_result:
            raise ValueError("Message result is missing suspicious_probability.")

        message_risk = float(message_result["suspicious_probability"])

        if not 0 <= message_risk <= 1:
            raise ValueError("Message risk must be between 0 and 1.")

        risks.append({
            "name": "message",
            "risk": message_risk,
            "weight": 0.5
        })

    if url_result is not None:
        if "suspicious_probability" not in url_result:
            raise ValueError("URL result is missing suspicious_probability.")

        url_risk = float(url_result["suspicious_probability"])

        if not 0 <= url_risk <= 1:
            raise ValueError("URL risk must be between 0 and 1.")

        risks.append({
            "name": "url",
            "risk": url_risk,
            "weight": 0.5
        })

    if not risks:
        return {
            "trust_score": 100,
            "risk_level": "Low Risk",
            "risk_probability": 0.0,
            "breakdown": {},
            "contributions": {},
            "message": "No scan results available."
        }

    total_weight = sum(item["weight"] for item in risks)

    combined_risk = sum(
        item["risk"] * item["weight"]
        for item in risks
    ) / total_weight

    trust_score = round((1 - combined_risk) * 100)

    if trust_score >= 80:
        risk_level = "Low Risk"
    elif trust_score >= 50:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk"

    breakdown = {
        item["name"]: round(item["risk"], 4)
        for item in risks
    }

    contributions = {
        item["name"]: round((1 - item["risk"]) * 100, 2)
        for item in risks
    }

    if len(risks) == 2:
        explanation = (
            "The final trust score combines message and URL "
            "risk estimates with equal weights."
        )
    elif risks[0]["name"] == "message":
        explanation = (
            "The trust score uses the message risk estimate."
        )
    else:
        explanation = (
            "The trust score uses the URL risk estimate."
        )

    return {
        "trust_score": trust_score,
        "risk_level": risk_level,
        "risk_probability": round(combined_risk, 4),
        "breakdown": breakdown,
        "contributions": contributions,
        "message": explanation
    }
