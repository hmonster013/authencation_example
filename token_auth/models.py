from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import secrets
import hashlib


class APIToken(models.Model):
    """Custom API Token model with expiry and refresh capabilities"""

    TOKEN_TYPES = [
        ('access', 'Access Token'),
        ('refresh', 'Refresh Token'),
        ('api_key', 'API Key'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_tokens')
    token = models.CharField(max_length=128, unique=True, db_index=True)
    token_type = models.CharField(max_length=10, choices=TOKEN_TYPES, default='access')
    name = models.CharField(max_length=100, help_text="Human-readable name for this token")

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    # Token properties
    is_active = models.BooleanField(default=True)
    scopes = models.JSONField(default=list, help_text="List of permissions/scopes for this token")

    # Usage tracking
    usage_count = models.PositiveIntegerField(default=0)
    max_usage = models.PositiveIntegerField(null=True, blank=True, help_text="Maximum number of uses (null = unlimited)")

    # Security
    ip_whitelist = models.JSONField(default=list, help_text="List of allowed IP addresses")
    user_agent = models.TextField(blank=True, help_text="User agent when token was created")

    class Meta:
        ordering = ['-created_at']
        verbose_name = "API Token"
        verbose_name_plural = "API Tokens"

    def __str__(self):
        return f"{self.user.username} - {self.name} ({self.token_type})"

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_token()
        if not self.expires_at:
            self.set_default_expiry()
        super().save(*args, **kwargs)

    @classmethod
    def generate_token(cls):
        """Generate a secure random token"""
        # Generate 32 bytes of random data and hash it
        random_bytes = secrets.token_bytes(32)
        token_hash = hashlib.sha256(random_bytes).hexdigest()
        return token_hash

    def set_default_expiry(self):
        """Set default expiry based on token type"""
        if self.token_type == 'access':
            self.expires_at = timezone.now() + timedelta(hours=24)  # 24 hours
        elif self.token_type == 'refresh':
            self.expires_at = timezone.now() + timedelta(days=30)   # 30 days
        elif self.token_type == 'api_key':
            self.expires_at = timezone.now() + timedelta(days=365)  # 1 year

    def is_expired(self):
        """Check if token is expired"""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if token is valid (active, not expired, usage limit not exceeded)"""
        if not self.is_active:
            return False
        if self.is_expired():
            return False
        if self.max_usage and self.usage_count >= self.max_usage:
            return False
        return True

    def use_token(self, ip_address=None):
        """Mark token as used and update usage statistics"""
        if not self.is_valid():
            return False

        self.usage_count += 1
        self.last_used = timezone.now()

        # Check IP whitelist if configured
        if self.ip_whitelist and ip_address:
            if ip_address not in self.ip_whitelist:
                return False

        self.save(update_fields=['usage_count', 'last_used'])
        return True

    def refresh_token(self):
        """Generate a new token (for refresh functionality)"""
        if self.token_type == 'refresh':
            # Create new access token
            new_token = APIToken.objects.create(
                user=self.user,
                token_type='access',
                name=f"Refreshed from {self.name}",
                scopes=self.scopes,
                ip_whitelist=self.ip_whitelist
            )
            return new_token
        return None

    def revoke(self):
        """Revoke the token"""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def extend_expiry(self, days=30):
        """Extend token expiry"""
        self.expires_at = timezone.now() + timedelta(days=days)
        self.save(update_fields=['expires_at'])

    def get_masked_token(self):
        """Return masked token for display purposes"""
        if len(self.token) > 8:
            return f"{self.token[:4]}...{self.token[-4:]}"
        return "****"


class TokenUsageLog(models.Model):
    """Log token usage for analytics and security"""

    token = models.ForeignKey(APIToken, on_delete=models.CASCADE, related_name='usage_logs')
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    endpoint = models.CharField(max_length=200, blank=True)
    method = models.CharField(max_length=10, blank=True)
    status_code = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Token Usage Log"
        verbose_name_plural = "Token Usage Logs"

    def __str__(self):
        return f"{self.token.name} - {self.timestamp} - {self.ip_address}"
