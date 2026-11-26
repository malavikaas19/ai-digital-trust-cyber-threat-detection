
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views

from cyber_assistant import views as assistant_views
from dashboard import views as dashboard_views
from scanner import views as scanner_views


urlpatterns = [

    path('admin/', admin.site.urls),

    # LOGIN
    path(
        'login/',
        auth_views.LoginView.as_view(
            template_name='registration/login.html',
            redirect_authenticated_user=True
        ),
        name='login'
    ),

    # LOGOUT
    path(
        'logout/',
        auth_views.LogoutView.as_view(
            next_page='login'
        ),
        name='logout'
    ),

    # REGISTRATION
    path(
        'register/',
        dashboard_views.register,
        name='register'
    ),

    # DASHBOARD
    path('', dashboard_views.home, name='home'),

    # PROFILE
    path('profile/', dashboard_views.profile, name='profile'),

    # SETTINGS
    path('settings/', dashboard_views.settings_page, name='settings'),

    # MESSAGE SCANNER
    path(
        'message-scanner/',
        scanner_views.message_scanner,
        name='message_scanner'
    ),

    # URL SCANNER
    path(
        'url-scanner/',
        scanner_views.url_scanner,
        name='url_scanner'
    ),

    # QR SCANNER
    path(
        'qr-scanner/',
        scanner_views.qr_scanner,
        name='qr_scanner'
    ),

    # SCREENSHOT SCANNER
    path(
        'screenshot-scanner/',
        scanner_views.screenshot_scanner,
        name='screenshot_scanner'
    ),

    # AI CYBER ASSISTANT
    path(
        'cyber-assistant/',
        assistant_views.assistant_home,
        name='cyber_assistant'
    ),

    # SCAN HISTORY
    path(
        'history/',
        scanner_views.scan_history,
        name='scan_history'
    ),

    # INDIVIDUAL SCAN DETAILS
    path(
        'history/<int:scan_id>/',
        scanner_views.scan_detail,
        name='scan_detail'
    ),

    # DELETE SCAN
    path(
        'history/delete/<int:scan_id>/',
        scanner_views.delete_scan,
        name='delete_scan'
    ),

    # CLEAR HISTORY
    path(
        'history/clear/',
        scanner_views.clear_history,
        name='clear_history'
    ),
]


if settings.DEBUG:
    urlpatterns += static(
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT
    )
