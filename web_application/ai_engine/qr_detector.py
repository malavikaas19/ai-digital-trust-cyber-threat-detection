
import cv2
import numpy as np


MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_IMAGE_PIXELS = 20_000_000


def decode_qr_image(image_bytes: bytes) -> str:
    """
    Decode a QR code from uploaded image bytes.

    Returns the decoded text or URL.
    Does not open or visit any extracted URL.
    """

    if not image_bytes:
        raise ValueError("Please upload a valid QR code image.")

    if len(image_bytes) > MAX_IMAGE_SIZE:
        raise ValueError("Image size must not exceed 5 MB.")

    image_array = np.frombuffer(image_bytes, dtype=np.uint8)

    image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)

    if image is None:
        raise ValueError("Unable to read this image. Please upload a valid image.")

    height, width = image.shape[:2]

    if height * width > MAX_IMAGE_PIXELS:
        raise ValueError("Image dimensions are too large. Please upload a smaller image.")

    detector = cv2.QRCodeDetector()

    decoded_text, points, _ = detector.detectAndDecode(image)

    if not decoded_text or not decoded_text.strip():
        raise ValueError(
            "No readable QR code was detected. Please upload a clearer QR code image."
        )

    return decoded_text.strip()
