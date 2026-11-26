

from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required

from scanner.models import ScanHistory
from .models import UserProfile
from .forms import RegisterForm, ProfileUpdateForm


# ==========================================
# DASHBOARD
# ==========================================

@login_required
def home(request):

    # Get scans belonging to the logged-in user
    user_scans = ScanHistory.objects.filter(
        user=request.user
    )

    # Total scans
    total_scans = user_scans.count()

    # Scan type statistics
    message_scans = user_scans.filter(
        scan_type="MESSAGE"
    ).count()

    url_scans = user_scans.filter(
        scan_type="URL"
    ).count()

    qr_scans = user_scans.filter(
        scan_type="QR"
    ).count()

    screenshot_scans = user_scans.filter(
        scan_type="SCREENSHOT"
    ).count()

    # Result statistics
    safe_scans = user_scans.filter(
        prediction="Safe"
    ).count()

    suspicious_scans = user_scans.filter(
        prediction="Suspicious"
    ).count()

    # High-risk scans
    high_risk_scans = user_scans.exclude(
        prediction="Not Assessed"
    ).filter(
        risk_score__gte=70
    ).count()

    # Latest five scans
    recent_scans = user_scans.order_by(
        "-created_at"
    )[:5]

    context = {
        "total_scans": total_scans,
        "message_scans": message_scans,
        "url_scans": url_scans,
        "qr_scans": qr_scans,
        "screenshot_scans": screenshot_scans,
        "safe_scans": safe_scans,
        "suspicious_scans": suspicious_scans,
        "high_risk_scans": high_risk_scans,
        "recent_scans": recent_scans,
    }

    return render(
        request,
        "dashboard/home.html",
        context
    )


# ==========================================
# USER REGISTRATION
# ==========================================

def register(request):

    if request.method == "POST":

        form = RegisterForm(request.POST)

        if form.is_valid():

            user = form.save()

            # Automatically log in after registration
            login(request, user)

            return redirect("home")

    else:

        form = RegisterForm()

    return render(
        request,
        "registration/register.html",
        {
            "form": form
        }
    )


# ==========================================
# USER PROFILE
# ==========================================

@login_required
def profile(request):

    profile, created = UserProfile.objects.get_or_create(
        user=request.user
    )

    if request.method == "POST":

        form = ProfileUpdateForm(
            request.POST,
            request.FILES,
            instance=profile,
            user=request.user
        )

        if form.is_valid():

            form.save()

            return redirect("profile")

    else:

        form = ProfileUpdateForm(
            instance=profile,
            user=request.user
        )

    return render(
        request,
        "dashboard/profile.html",
        {
            "form": form,
            "profile": profile
        }
    )


# ==========================================
# SETTINGS
# ==========================================

@login_required
def settings_page(request):

    return render(
        request,
        "dashboard/settings.html"
    )
