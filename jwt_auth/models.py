from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import uuid


class JWTBlacklist(models.Model):
    """Model to store blacklisted JWT tokens"""

    jti = models.CharField(max_length=255, unique=True, db_index=True, help_text="JWT ID (jti claim)")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blacklisted_tokens')
    token_type = models.CharField(max_length=20, choices=[
        ('access', 'Access Token'),
        ('refresh', 'Refresh Token'),
    ], default='access')

    # Timestamps
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(help_text="When the original token would have expired")

    # Metadata
    reason = models.CharField(max_length=100, default='manual_revoke', choices=[
        ('manual_revoke', 'Manual Revocation'),
        ('logout', 'User Logout'),
        ('security', 'Security Concern'),
        ('expired', 'Token Expired'),
    ])
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-blacklisted_at']
        verbose_name = "JWT Blacklist Entry"
        verbose_name_plural = "JWT Blacklist Entries"
        indexes = [
            models.Index(fields=['jti']),
            models.Index(fields=['user', 'blacklisted_at']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.token_type} - {self.jti[:8]}..."

    @classmethod
    def is_blacklisted(cls, jti):
        """Check if a token JTI is blacklisted"""
        return cls.objects.filter(jti=jti, expires_at__gt=timezone.now()).exists()

    @classmethod
    def cleanup_expired(cls):
        """Remove expired blacklist entries"""
        expired_count = cls.objects.filter(expires_at__lte=timezone.now()).count()
        cls.objects.filter(expires_at__lte=timezone.now()).delete()
        return expired_count


class JWTUserSession(models.Model):
    """Track user JWT sessions for security monitoring"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='jwt_sessions')
    session_id = models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)

    # Token information
    refresh_jti = models.CharField(max_length=255, unique=True, db_index=True)

    # Session metadata
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField()

    # Client information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    device_info = models.JSONField(default=dict, blank=True)

    # Session status
    is_active = models.BooleanField(default=True)
    logout_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "JWT User Session"
        verbose_name_plural = "JWT User Sessions"
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['refresh_jti']),
            models.Index(fields=['session_id']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.session_id} - {'Active' if self.is_active else 'Inactive'}"

    def is_expired(self):
        """Check if session is expired"""
        return timezone.now() > self.expires_at

    def terminate(self, reason='manual'):
        """Terminate the session"""
        self.is_active = False
        self.logout_at = timezone.now()
        self.save(update_fields=['is_active', 'logout_at'])

        # Blacklist the refresh token
        JWTBlacklist.objects.create(
            jti=self.refresh_jti,
            user=self.user,
            token_type='refresh',
            expires_at=self.expires_at,
            reason=reason,
            ip_address=self.ip_address,
            user_agent=self.user_agent
        )

    @classmethod
    def cleanup_expired(cls):
        """Clean up expired sessions"""
        expired_sessions = cls.objects.filter(
            expires_at__lte=timezone.now(),
            is_active=True
        )

        # Blacklist refresh tokens for expired sessions
        for session in expired_sessions:
            session.terminate(reason='expired')

        return expired_sessions.count()


class JWTLoginAttempt(models.Model):
    """Track JWT login attempts for security monitoring"""

    username = models.CharField(max_length=150, db_index=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)

    # Attempt details
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField()
    failure_reason = models.CharField(max_length=100, blank=True, choices=[
        ('invalid_credentials', 'Invalid Credentials'),
        ('account_disabled', 'Account Disabled'),
        ('rate_limited', 'Rate Limited'),
        ('suspicious_activity', 'Suspicious Activity'),
    ])

    # Additional metadata
    request_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "JWT Login Attempt"
        verbose_name_plural = "JWT Login Attempts"
        indexes = [
            models.Index(fields=['username', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['success', 'timestamp']),
        ]

    def __str__(self):
        status = "Success" if self.success else f"Failed ({self.failure_reason})"
        return f"{self.username} - {self.ip_address} - {status}"

    @classmethod
    def get_recent_failures(cls, username=None, ip_address=None, minutes=15):
        """Get recent failed login attempts"""
        since = timezone.now() - timedelta(minutes=minutes)
        queryset = cls.objects.filter(
            timestamp__gte=since,
            success=False
        )

        if username:
            queryset = queryset.filter(username=username)
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)

        return queryset.count()
