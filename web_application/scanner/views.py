
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from urllib.parse import urlparse

from .models import ScanHistory


# ----------------------------------
# TRUST SCORE
# ----------------------------------

def add_trust_score(result, message_result=None, url_result=None):
    from ai_engine.trust_score import calculate_trust_score

    trust = calculate_trust_score(
        message_result=message_result,
        url_result=url_result
    )

    result.update(trust)
    return result


# ----------------------------------
# MESSAGE SCANNER
# ----------------------------------

@login_required
def message_scanner(request):

    result = None
    error = None

    if request.method == "POST":

        message = request.POST.get("message", "").strip()

        if not message:
            error = "Please enter a message to scan."

        else:
            try:
                from ai_engine.message_detector import detect_message

                result = detect_message(message)

                result = add_trust_score(
                    result,
                    message_result=result
                )

                explanation = "\n".join(
                    result.get("reasons", [])
                )

                ScanHistory.objects.create(
                    user=request.user,
                    scan_type="MESSAGE",
                    submitted_input=message,
                    prediction=result.get("label", "Unknown"),
                    risk_score=(
                        result.get("suspicious_probability", 0) * 100
                    ),
                    confidence=(
                        float(result.get("confidence", 0)) * 100
                    ),
                    explanation=explanation
                )

            except ImportError:
                error = "Message detection model could not be loaded."

            except ValueError as e:
                error = str(e)

            except Exception as e:
                error = f"Message scanning failed: {str(e)}"

    return render(
        request,
        "scanner/message_scanner.html",
        {
            "result": result,
            "error": error
        }
    )


# ----------------------------------
# URL SCANNER
# ----------------------------------

@login_required
def url_scanner(request):

    result = None
    error = None

    if request.method == "POST":

        url = request.POST.get("url", "").strip()

        if not url:
            error = "Please enter a URL."

        else:
            try:
                parsed_url = urlparse(url)

                if (
                    parsed_url.scheme.lower() not in ["http", "https"]
                    or not parsed_url.hostname
                    or any(char.isspace() for char in url)
                ):
                    error = "Please enter a valid HTTP or HTTPS URL."

                else:
                    from ai_engine.url_detector import detect_url

                    # Use the original URL detector result.
                    result = detect_url(url)

                    # Do not overwrite the URL-specific trust score.
                    explanation = "\n".join(
                        result.get("reasons", [])
                    )

                    ScanHistory.objects.create(
                        user=request.user,
                        scan_type="URL",
                        submitted_input=url,
                        prediction=result.get("label", "Unknown"),
                        risk_score=(
                            result.get("suspicious_probability", 0) * 100
                        ),
                        confidence=0,
                        explanation=explanation
                    )

            except ValueError:
                error = "Please enter a valid URL and port number."

            except ImportError:
                error = "URL detection module could not be loaded."

            except Exception as e:
                error = f"URL scanning failed: {str(e)}"

    return render(
        request,
        "scanner/url_scanner.html",
        {
            "result": result,
            "error": error
        }
    )


# ----------------------------------
# QR CODE SCANNER
# ----------------------------------

@login_required
def qr_scanner(request):

    result = None
    error = None
    extracted_text = None

    if request.method == "POST":

        uploaded_file = request.FILES.get("qr_image")

        if not uploaded_file:
            error = "Please upload a QR code image."

        elif uploaded_file.size > 5 * 1024 * 1024:
            error = "Image size must not exceed 5 MB."

        else:
            try:
                from ai_engine.qr_detector import decode_qr_image

                image_bytes = uploaded_file.read()

                extracted_text = decode_qr_image(image_bytes)

                parsed = urlparse(extracted_text)

                # Only HTTP/HTTPS URLs are sent to URL detection.
                if (
                    parsed.scheme.lower() in ("http", "https")
                    and parsed.hostname
                    and not any(char.isspace() for char in extracted_text)
                ):

                    from ai_engine.url_detector import detect_url

                    result = detect_url(extracted_text)

                    result = add_trust_score(
                        result,
                        url_result=result
                    )

                    result["content_type"] = "URL"

                    explanation = "\n".join(
                        result.get("reasons", [])
                    )

                    prediction = result.get(
                        "label", "Unknown"
                    )

                    risk_score = (
                        result.get("suspicious_probability", 0) * 100
                    )

                    confidence = (
                        float(result.get("confidence", 0)) * 100
                    )

                else:

                    result = {
                        "label": "Text / Unsupported Content",
                        "risk_level": "Not assessed",
                        "trust_score": None,
                        "suspicious_probability": None,
                        "confidence": None,
                        "reasons": [
                            "The QR code does not contain a supported HTTP or HTTPS URL.",
                            "Its contents have not been security-verified."
                        ],
                        "message": (
                            "Review the extracted content carefully. "
                            "No website reputation check was performed."
                        ),
                        "content_type": "TEXT"
                    }

                    prediction = "Not Assessed"
                    risk_score = 0
                    confidence = 0

                    explanation = "\n".join(
                        result["reasons"]
                    )

                ScanHistory.objects.create(
                    user=request.user,
                    scan_type="QR",
                    submitted_input=extracted_text[:5000],
                    prediction=prediction,
                    risk_score=risk_score,
                    confidence=confidence,
                    explanation=explanation
                )

            except ImportError:
                error = "QR scanning dependencies could not be loaded."

            except ValueError as e:
                error = str(e)

            except Exception as e:
                error = f"QR scanning failed: {str(e)}"

    return render(
        request,
        "scanner/qr_scanner.html",
        {
            "result": result,
            "error": error,
            "extracted_text": extracted_text
        }
    )


# ----------------------------------
# VIEW SCAN HISTORY
# ----------------------------------

@login_required
def scan_history(request):

    history = ScanHistory.objects.filter(
        user=request.user
    ).order_by("-created_at")

    return render(
        request,
        "scanner/history.html",
        {
            "history": history
        }
    )


# ----------------------------------
# DELETE ONE SCAN
# ----------------------------------

@login_required
@require_POST
def delete_scan(request, scan_id):

    scan = get_object_or_404(
        ScanHistory,
        id=scan_id,
        user=request.user
    )

    scan.delete()

    return redirect("scan_history")


# ----------------------------------
# DELETE ALL USER HISTORY
# ----------------------------------

@login_required
@require_POST
def clear_history(request):

    ScanHistory.objects.filter(
        user=request.user
    ).delete()

    return redirect("scan_history")


# ----------------------------------
# INDIVIDUAL SCAN DETAILS
# ----------------------------------

@login_required
def scan_detail(request, scan_id):

    scan = get_object_or_404(
        ScanHistory,
        id=scan_id,
        user=request.user
    )

    return render(
        request,
        "scanner/scan_detail.html",
        {
            "scan": scan
        }
    )


# ----------------------------------
# SCREENSHOT-BASED PHISHING DETECTION
# ----------------------------------

@login_required
def screenshot_scanner(request):

    result = None
    error = None

    if request.method == "POST":

        uploaded_file = request.FILES.get("screenshot")

        if not uploaded_file:
            error = "Please upload a website screenshot."

        elif uploaded_file.size > 5 * 1024 * 1024:
            error = "Screenshot size must not exceed 5 MB."

        else:
            try:
                from ai_engine.screenshot_detector import analyze_screenshot

                image_bytes = uploaded_file.read()

                result = analyze_screenshot(image_bytes)

                explanation = "\n".join(
                    result.get("reasons", [])
                )

                extracted_text = result.get(
                    "extracted_text", ""
                )

                submitted_input = (
                    f"Screenshot: {uploaded_file.name}\n"
                    f"Extracted text: {extracted_text[:3000]}"
                )

                ScanHistory.objects.create(
                    user=request.user,
                    scan_type="SCREENSHOT",
                    submitted_input=submitted_input,
                    prediction=result.get("label", "Unknown"),
                    risk_score=float(
                        result.get("risk_score", 0)
                    ),
                    confidence=0,
                    explanation=explanation
                )

            except ImportError:
                error = (
                    "Screenshot detection module could not be loaded."
                )

            except ValueError as e:
                error = str(e)

            except Exception as e:
                error = f"Screenshot analysis failed: {str(e)}"

    return render(
        request,
        "scanner/screenshot_scanner.html",
        {
            "result": result,
            "error": error
        }
    )
