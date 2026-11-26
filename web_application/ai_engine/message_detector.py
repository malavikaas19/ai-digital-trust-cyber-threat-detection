
"""Context-aware message phishing detector.

Uses TF-IDF, Logistic Regression and explainable
contextual security indicators.

Educational prototype. Not validated for production use.
"""

import re

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


# 0 = Legitimate
# 1 = Suspicious

TRAINING_DATA = [

    # Original legitimate messages

    ("Hi, are we still meeting at the library at 4 pm?", 0),
    ("Your assignment feedback is available on the college portal.", 0),
    ("The meeting has been moved to room 204 tomorrow.", 0),
    ("Thanks for sharing the project document. I received it.", 0),
    ("Your food order has been delivered. Enjoy your meal.", 0),
    ("Please review the attached class timetable.", 0),
    ("Your OTP for the requested login is 482193. Do not share it.", 0),
    ("Reminder: your electricity bill is due next week.", 0),
    ("Hi, our project meeting is scheduled for tomorrow at 10 AM. Please bring your notes.", 0),
    ("Good morning, the lecture starts at 9 AM in classroom 204.", 0),
    ("Please send me the assignment file when you get time.", 0),
    ("Our team presentation is scheduled for Friday.", 0),
    ("The college library will remain open until 5 PM today.", 0),
    ("I have shared the meeting notes with everyone.", 0),
    ("Please check the updated project timetable.", 0),
    ("Thank you for attending today's class.", 0),
    ("Your appointment is confirmed for Monday at 11 AM.", 0),
    ("The class notes are available in the student portal.", 0),
    ("Can you share the presentation slides with me?", 0),
    ("The project submission deadline is next Thursday.", 0),
    ("Your payment receipt has been generated successfully.", 0),
    ("The faculty meeting will begin after lunch.", 0),
    ("I will reach the college in fifteen minutes.", 0),
    ("Please find the meeting agenda attached.", 0),
    ("The examination timetable has been updated.", 0),
    ("Thanks for your help with the assignment.", 0),

    # Legitimate security notifications

    ("Your login was successful. If this was not you, contact support.", 0),
    ("Your password reset request has been received.", 0),
    ("A new device signed in to your account. Review your account activity.", 0),
    ("Your monthly electricity bill has been generated. Please review the amount.", 0),
    ("Your payment is complete. Your transaction receipt is available.", 0),
    ("Your account statement is ready to view in the official banking application.", 0),
    ("The college portal will undergo scheduled maintenance tonight.", 0),
    ("Your verification code was requested. Never share it with anyone.", 0),
    ("Your subscription renewal is scheduled for next month.", 0),
    ("Please visit the college website to view the examination timetable.", 0),
    ("The project announcement is available at https://example.com/announcement.", 0),
    ("Your bank transaction notification is available in your banking app.", 0),
    ("Your account password was changed successfully.", 0),
    ("Your electricity payment receipt is available in your account.", 0),
    ("The payment deadline for your college fees is Friday.", 0),
    ("Your requested account verification is complete.", 0),
    ("Please check the official student portal for your results.", 0),
    ("Your appointment reminder is scheduled for tomorrow morning.", 0),
    ("The login code you requested should not be shared with anyone.", 0),
    ("Your online order payment was successful.", 0),

    # Additional legitimate college messages

    ("The department has published the updated laboratory schedule for next week.", 0),
    ("Students are requested to attend the project discussion at 2 PM tomorrow.", 0),
    ("The placement cell has shared the schedule for the upcoming orientation session.", 0),
    ("Please collect your library membership card from the college office.", 0),
    ("The faculty coordinator has approved the revised project presentation date.", 0),
    ("The workshop registration details are available on the college website.", 0),
    ("The semester examination begins on Monday according to the published timetable.", 0),
    ("Your class attendance summary is available on the student portal.", 0),
    ("The computer laboratory will remain closed during the maintenance period.", 0),
    ("Please bring your college ID card for tomorrow's department meeting.", 0),

    # Additional legitimate account security notifications

    ("Your account password was changed successfully.", 0),
    ("A new device signed in to your account. Review your account activity.", 0),
    ("Your recent login was successful.", 0),
    ("Your account security settings were updated successfully.", 0),
    ("A sign-in notification was generated for your account.", 0),

    # Additional legitimate college notifications

    ("Your internal assessment marks are available on the college portal.", 0),
    ("The department meeting is scheduled for tomorrow morning.", 0),
    ("Your semester examination timetable has been published.", 0),
    ("The college has announced the project submission deadline.", 0),
    ("Please attend the scheduled placement training session.", 0),

    # Suspicious messages

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
    ("Your bank account will be permanently blocked. Verify your details now.", 1),
    ("You have been selected for a reward. Share your OTP to claim it.", 1),
    ("Your account access is restricted. Click the unknown link to continue.", 1),
    ("Pay an urgent processing fee to receive your unexpected prize.", 1),
    ("Your password has expired. Confirm your credentials through this link.", 1),
    ("You won a special lottery. Submit your banking information to receive money.", 1),
    ("Immediate action required: your account will be closed today.", 1),
    ("Share your card number and PIN to complete the refund.", 1),
    ("Your KYC verification failed. Send your password to reactivate the account.", 1),
    ("Claim your free reward by paying a registration charge immediately.", 1),

    # Additional suspicious examples

    ("Your account will be disabled today. Send your OTP to prevent suspension.", 1),
    ("URGENT: Confirm your banking password immediately to avoid account closure.", 1),
    ("Click this unknown link and enter your card details to receive a refund.", 1),
    ("Your electricity connection will be disconnected unless you pay this urgent fee through our link.", 1),
    ("Your account has suspicious activity. Share your login password with our support team.", 1),
    ("Congratulations winner! Pay a processing charge to release your prize money.", 1),
    ("Your parcel is blocked. Submit your card number and PIN to arrange delivery.", 1),
    ("Your student account will be deleted. Verify your password using this link now.", 1),
    ("You have an unexpected cashback reward. Share your OTP to receive it.", 1),
    ("Immediate verification required. Enter your banking credentials at this unknown website.", 1),
]


# Contextual indicators

CREDENTIAL_REQUEST_PATTERNS = [
    (
        r"\b(share|send|provide|reveal|tell|submit|enter|"
        r"confirm|forward)\b.{0,60}\b(password|otp|pin|"
        r"card number|bank details|credentials)\b",
        "The message requests sensitive credentials or banking information."
    ),
    (
        r"\b(password|otp|pin|credentials)\b.{0,60}"
        r"\b(share|send|provide|reveal|submit|enter)\b",
        "The message appears to request sensitive authentication information."
    ),
]

PRESSURE_PATTERNS = [
    (
        r"\b(urgent|immediately|act now|limited time|"
        r"verify now|within minutes)\b",
        "Urgent or pressure-based language detected."
    ),
    (
        r"\b(account|card|service|connection).{0,35}"
        r"\b(blocked|suspended|closed|locked|disabled|"
        r"disconnected)\b",
        "Account or service restriction language detected."
    ),
    (
        r"\b(won|winner|prize|free gift|cashback|lottery)\b",
        "Prize, reward, or unexpected offer language detected."
    ),
    (
        r"\b(pay|payment).{0,35}\b(fee|charges|registration)\b",
        "Payment or registration fee request detected."
    ),
]

PROTECTIVE_PATTERNS = [
    (
        r"\b(do not|don't|never|never ever)\b.{0,35}"
        r"\b(share|send|reveal|tell|forward)\b"
        r"(?:\s+(?:it|them|your))?"
        r"(?:\s+(password|otp|pin|verification code))?\b",
        "The message warns the recipient not to share authentication information."
    ),
    (
        r"\b(password|otp|pin|verification code)\b.{0,40}"
        r"\b(should not|must not|never)\b.{0,25}\bshared\b",
        "The message contains a warning against sharing authentication information."
    ),
]

LINK_PATTERN = r"https?://|www\."


def _build_model():
    """Build and train the TF-IDF and Logistic Regression model."""

    texts, labels = zip(*TRAINING_DATA)

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                lowercase=True,
                sublinear_tf=True
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced"
            )
        )
    ])

    model.fit(list(texts), list(labels))

    return model


# Train the model when this module is imported.

_MODEL = _build_model()


def detect_message(message: str) -> dict:
    """Classify a message and return contextual risk indicators."""

    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please provide a non-empty message.")

    if len(message) > 10000:
        raise ValueError("Message must not exceed 10000 characters.")

    # Get ML probability

    probabilities = _MODEL.predict_proba([message])[0]
    ml_probability = float(probabilities[1])

    # Contextual analysis

    reasons = []

    credential_request = False
    protective_warning = False
    pressure_detected = False

    # Split the message into sentences before checking
    # credential requests to reduce cross-sentence false matches.

    sentences = re.split(r"(?<=[.!?])\s+", message)

    for sentence in sentences:

        sentence_has_warning = any(
            re.search(pattern, sentence, flags=re.IGNORECASE)
            for pattern, _ in PROTECTIVE_PATTERNS
        )

        if sentence_has_warning:
            continue

        for pattern, explanation in CREDENTIAL_REQUEST_PATTERNS:
            if re.search(pattern, sentence, flags=re.IGNORECASE):
                credential_request = True

                if explanation not in reasons:
                    reasons.append(explanation)

    # Detect pressure indicators across the full message.

    for pattern, explanation in PRESSURE_PATTERNS:
        if re.search(pattern, message, flags=re.IGNORECASE):
            pressure_detected = True

            if explanation not in reasons:
                reasons.append(explanation)

    # Detect protective warnings.

    for pattern, explanation in PROTECTIVE_PATTERNS:
        if re.search(pattern, message, flags=re.IGNORECASE):
            protective_warning = True

            if explanation not in reasons:
                reasons.append(explanation)

    has_link = bool(
        re.search(LINK_PATTERN, message, flags=re.IGNORECASE)
    )

    if has_link:
        reasons.append("A website link is present in the message.")

    # Context-aware adjustment

    suspicious_probability = ml_probability

    if credential_request:
        suspicious_probability = max(
            suspicious_probability, 0.65
        )

    if credential_request and pressure_detected:
        suspicious_probability = max(
            suspicious_probability, 0.80
        )

    # Protective warnings reduce the probability only when
    # no separate credential request has been identified.

    if protective_warning and not credential_request:
        suspicious_probability = min(
            suspicious_probability, 0.15
        )

    suspicious_probability = min(
        max(suspicious_probability, 0.0), 1.0
    )

    # Classification thresholds

    if suspicious_probability >= 0.50:
        label = "Suspicious"
        risk_level = "High Risk"

    elif suspicious_probability >= 0.20:
        label = "Needs Review"
        risk_level = "Medium Risk"

    else:
        label = "Safe"
        risk_level = "Low Risk"

    prediction_confidence = max(
        suspicious_probability,
        1 - suspicious_probability
    )

    if not reasons:
        reasons.append(
            "No listed suspicious patterns were detected."
        )

    return {
        "label": label,
        "risk_level": risk_level,
        "suspicious_probability": round(
            suspicious_probability, 4
        ),
        "confidence": round(
            prediction_confidence, 4
        ),
        "reasons": reasons,
        "model_note": (
            "TF-IDF and Logistic Regression with contextual "
            f"risk indicators, trained on {len(TRAINING_DATA)} "
            "manually created examples. Risk adjustments are "
            "rule-based and have not been independently validated. "
            "Prediction confidence is not validated model accuracy."
        )
    }
