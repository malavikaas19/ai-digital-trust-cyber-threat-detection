
from django.db import models
from django.contrib.auth.models import User


class ScanHistory(models.Model):

    SCAN_TYPES = [
        ('MESSAGE', 'Message Scan'),
        ('URL', 'URL Scan'),
        ('QR', 'QR Code Scan'),
        ('SCREENSHOT', 'Screenshot Scan'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='scan_history',
        null=True,
        blank=True
    )

    scan_type = models.CharField(
        max_length=20,
        choices=SCAN_TYPES
    )

    submitted_input = models.TextField()

    prediction = models.CharField(max_length=50)

    risk_score = models.FloatField(default=0)

    confidence = models.FloatField(default=0)

    explanation = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.scan_type} - {self.prediction}"
