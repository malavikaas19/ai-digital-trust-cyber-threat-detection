
import re
from io import BytesIO
from urllib.parse import urlparse

import cv2
import numpy as np
import pytesseract

from PIL import Image, ImageEnhance, ImageFilter


# ----------------------------------
# CONFIGURATION
# ----------------------------------

MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000

# Tesseract installation path on Windows
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


# ----------------------------------
# SCREENSHOT ANALYSIS
# ----------------------------------

def analyze_screenshot(image_bytes):

    """
    Analyse a website screenshot using OCR and
    heuristic phishing indicators.

    This is a preliminary detector, not a verified
    phishing classifier.
    """

    if not image_bytes:
        raise ValueError("Please upload a screenshot.")

    if len(image_bytes) > MAX_IMAGE_SIZE:
        raise ValueError("Screenshot must not exceed 5 MB.")

    try:
        image = Image.open(BytesIO(image_bytes))
        image.verify()

        image = Image.open(BytesIO(image_bytes)).convert("RGB")

    except Exception:
        raise ValueError(
            "Unable to read the image. Upload a valid PNG or JPG."
        )

    if image.width * image.height > MAX_IMAGE_PIXELS:
        raise ValueError("Image dimensions are too large.")

    # ----------------------------------
    # IMAGE PREPROCESSING
    # ----------------------------------

    image = ImageEnhance.Contrast(image).enhance(1.5)
    image = image.filter(ImageFilter.SHARPEN)

    # ----------------------------------
    # VISUAL ANALYSIS
    # ----------------------------------

    image_array = np.array(image)

    gray = cv2.cvtColor(
        image_array,
        cv2.COLOR_RGB2GRAY
    )

    edges = cv2.Canny(gray, 100, 200)

    edge_density = (
        float(np.count_nonzero(edges)) / edges.size
    )

    # ----------------------------------
    # OCR TEXT EXTRACTION
    # ----------------------------------

    try:

        extracted_text = pytesseract.image_to_string(
            image,
            config="--psm 6"
        )

    except Exception as e:

        raise ValueError(
            f"OCR text extraction failed: {str(e)}"
        )

    text = extracted_text.lower()

    # ----------------------------------
    # RISK ANALYSIS
    # ----------------------------------

    reasons = []
    risk_score = 0.0

    urgent_words = [
        "urgent",
        "immediately",
        "account suspended",
        "account blocked",
        "verify now",
        "limited time",
        "act now",
        "unusual activity",
    ]

    credential_words = [
        "password",
        "login",
        "sign in",
        "bank account",
        "credit card",
        "otp",
        "verify your account",
        "enter your credentials",
    ]

    # Urgent language
    for word in urgent_words:

        if word in text:

            risk_score += 0.15

            reasons.append(
                f"Urgent or pressure-based language detected: {word}"
            )

    # Sensitive information requests
    for word in credential_words:

        if word in text:

            risk_score += 0.10

            reasons.append(
                f"Sensitive account-related wording detected: {word}"
            )

    # ----------------------------------
    # URL ANALYSIS
    # ----------------------------------

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        extracted_text,
        flags=re.IGNORECASE,
    )

    for url in urls:

        parsed = urlparse(
            url if url.startswith("http") else "https://" + url
        )

        hostname = parsed.hostname or ""

        if "@" in url:

            risk_score += 0.20

            reasons.append(
                "A URL contains an unusual @ symbol."
            )

        if hostname.startswith("xn--") or ".xn--" in hostname:

            risk_score += 0.20

            reasons.append(
                "A URL contains an internationalized domain."
            )

    # ----------------------------------
    # VISUAL STATISTICS
    # ----------------------------------

    if edge_density > 0.15:

        reasons.append(
            "The screenshot contains many visual edges and elements. "
            "This is not, by itself, evidence of phishing."
        )

    # ----------------------------------
    # FINAL RESULT
    # ----------------------------------

    risk_score = min(risk_score, 1.0)

    if not extracted_text.strip():

        label = "Needs Review"

        reasons.append(
            "No readable text was extracted. "
            "The screenshot could not be fully assessed."
        )

    elif risk_score >= 0.50:

        label = "Suspicious"

    elif risk_score >= 0.20:

        label = "Needs Review"

    else:

        label = "No Strong Warning Signs"

    if not reasons:

        reasons.append(
            "No strong phishing indicators were detected "
            "by the current checks."
        )

    return {

        "label": label,

        "risk_score": round(
            risk_score * 100,
            2
        ),

        "confidence": None,

        "reasons": reasons,

        "extracted_text": extracted_text[:3000],

        "edge_density": round(
            edge_density,
            4
        ),

        "model_note": (
            "OCR-based heuristic analysis. "
            "This result is not a guarantee that a website "
            "or screenshot is safe."
        ),

    }
