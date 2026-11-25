"""Message phishing detector. Demo model: TF-IDF + Logistic Regression.

The small embedded dataset makes the hackathon prototype runnable offline.
Replace it with a larger, reviewed dataset before real-world deployment.
"""
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

TRAINING_DATA = [
    ("Hi, are we still meeting at the library at 4 pm?", 0),
    ("Your assignment feedback is available on the college portal.", 0),
    ("The meeting has been moved to room 204 tomorrow.", 0),
    ("Thanks for sharing the project document. I received it.", 0),
    ("Your food order has been delivered. Enjoy your meal.", 0),
    ("Please review the attached class timetable.", 0),
    ("Your OTP for the requested login is 482193. Do not share it.", 0),
    ("Reminder: your electricity bill is due next week.", 0),
    ("Congratulations, you won a prize. Click this link immediately to claim.", 1),
    ("URGENT: Your bank account will be blocked. Verify your password now.", 1),
    ("Your account is suspended. Send your OTP to restore access.", 1),
    ("You have won a free gift card. Pay a small fee to receive it.", 1),
    ("Click here now to avoid arrest. Confirm your bank details.", 1),
    ("We detected unusual activity. Login at this link to unlock your account.", 1),
    ("Act now! Limited offer. Enter your credit card and password.", 1),
    ("Your package is on hold. Pay now using this unknown link.", 1),
    ("Dear user, update KYC immediately or your account will be closed.", 1),
    ("Claim your cashback by sharing your PIN and OTP.", 1),
    ("You are selected for a job. Pay registration charges today.", 1),
]

SUSPICIOUS_PATTERNS = [
    r"\b(urgent|immediately|act now|limited time|verify now)\b",
    r"\b(password|otp|pin|bank details|credit card)\b",
    r"\b(account.{0,20}(blocked|suspended|closed|locked))\b",
    r"\b(won|winner|prize|free gift|cashback)\b",
    r"\b(pay.{0,15}(fee|charges|now))\b",
    r"https?://|www\.",
]

def _build_model():
    texts, labels = zip(*TRAINING_DATA)
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True,
                                  sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])
    model.fit(list(texts), list(labels))
    return model

_MODEL = _build_model()

def detect_message(message: str) -> dict:
    """Return label, suspicious probability, confidence, and explainable reasons."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please provide a non-empty message.")

    probabilities = _MODEL.predict_proba([message])[0]
    suspicious_probability = float(probabilities[1])
    reasons = []
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, message, flags=re.IGNORECASE):
            reasons.append(f"Matched suspicious pattern: {pattern}")

    # The model probability drives the decision; patterns explain warning signs.
    is_suspicious = suspicious_probability >= 0.50
    return {
        "label": "Suspicious" if is_suspicious else "Safe",
        "suspicious_probability": round(suspicious_probability, 4),
        "confidence": round(max(probabilities), 4),
        "reasons": reasons or ["No obvious phishing keywords detected by the demo rules."],
        "model_note": "Prototype model trained on a small embedded sample dataset."
    }
