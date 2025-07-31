from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from allauth.socialaccount.models import SocialAccount, SocialApp
import uuid


class OAuthUserProfile(models.Model):
    """Extended user profile for OAuth authentication"""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='oauth_profile')

    # OAuth preferences
    preferred_provider = models.CharField(max_length=50, blank=True, help_text="User's preferred OAuth provider")
    auto_login_enabled = models.BooleanField(default=False, help_text="Enable automatic login with preferred provider")

    # Profile completion
    profile_completed = models.BooleanField(default=False)
    profile_completion_date = models.DateTimeField(null=True, blank=True)

    # Privacy settings
    share_email = models.BooleanField(default=True, help_text="Allow sharing email with connected apps")
    share_profile = models.BooleanField(default=True, help_text="Allow sharing profile info with connected apps")

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "OAuth User Profile"
        verbose_name_plural = "OAuth User Profiles"

    def __str__(self):
        return f"{self.user.username} - OAuth Profile"

    def get_connected_accounts(self):
        """Get all connected social accounts for this user"""
        return SocialAccount.objects.filter(user=self.user)

    def get_primary_account(self):
        """Get the primary social account (preferred provider or first one)"""
        accounts = self.get_connected_accounts()
        if self.preferred_provider:
            preferred = accounts.filter(provider=self.preferred_provider).first()
            if preferred:
                return preferred
        return accounts.first()

    def complete_profile(self):
        """Mark profile as completed"""
        self.profile_completed = True
        self.profile_completion_date = timezone.now()
        self.save(update_fields=['profile_completed', 'profile_completion_date'])


class OAuthLoginSession(models.Model):
    """Track OAuth login sessions for analytics and security"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_sessions')
    session_id = models.UUIDField(default=uuid.uuid4, unique=True, db_index=True)

    # OAuth provider information
    provider = models.CharField(max_length=50, help_text="OAuth provider (google, github, etc.)")
    provider_uid = models.CharField(max_length=255, help_text="User ID from OAuth provider")

    # Session details
    login_timestamp = models.DateTimeField(auto_now_add=True)
    logout_timestamp = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    # Client information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)

    # OAuth specific data
    access_token_expires = models.DateTimeField(null=True, blank=True)
    scope_granted = models.JSONField(default=list, help_text="OAuth scopes granted by user")

    # Additional metadata
    login_method = models.CharField(max_length=20, choices=[
        ('oauth_new', 'OAuth New User'),
        ('oauth_existing', 'OAuth Existing User'),
        ('oauth_connect', 'OAuth Account Connection'),
    ], default='oauth_existing')

    class Meta:
        ordering = ['-login_timestamp']
        verbose_name = "OAuth Login Session"
        verbose_name_plural = "OAuth Login Sessions"
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['provider', 'login_timestamp']),
            models.Index(fields=['session_id']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.provider} - {self.login_timestamp}"

    def end_session(self):
        """End the OAuth session"""
        self.is_active = False
        self.logout_timestamp = timezone.now()
        self.save(update_fields=['is_active', 'logout_timestamp'])

    def is_token_expired(self):
        """Check if OAuth access token is expired"""
        if not self.access_token_expires:
            return False
        return timezone.now() > self.access_token_expires

    @classmethod
    def get_active_sessions(cls, user):
        """Get all active OAuth sessions for a user"""
        return cls.objects.filter(user=user, is_active=True)


class OAuthAppConnection(models.Model):
    """Track OAuth app connections and permissions"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_connections')
    social_app = models.ForeignKey(SocialApp, on_delete=models.CASCADE)

    # Connection details
    connected_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    # Permissions
    permissions_granted = models.JSONField(default=list, help_text="List of permissions granted to this app")
    data_access_level = models.CharField(max_length=20, choices=[
        ('basic', 'Basic Profile'),
        ('email', 'Email Access'),
        ('full', 'Full Profile'),
        ('custom', 'Custom Permissions'),
    ], default='basic')

    # Usage tracking
    usage_count = models.PositiveIntegerField(default=0)
    last_ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        unique_together = ['user', 'social_app']
        verbose_name = "OAuth App Connection"
        verbose_name_plural = "OAuth App Connections"

    def __str__(self):
        return f"{self.user.username} - {self.social_app.name}"

    def revoke_connection(self):
        """Revoke the OAuth app connection"""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def update_usage(self, ip_address=None):
        """Update usage statistics"""
        self.usage_count += 1
        self.last_used = timezone.now()
        if ip_address:
            self.last_ip_address = ip_address
        self.save(update_fields=['usage_count', 'last_used', 'last_ip_address'])


class OAuthSecurityLog(models.Model):
    """Security logging for OAuth authentication events"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='oauth_security_logs', null=True, blank=True)

    # Event details
    event_type = models.CharField(max_length=50, choices=[
        ('login_success', 'Login Success'),
        ('login_failed', 'Login Failed'),
        ('account_connected', 'Account Connected'),
        ('account_disconnected', 'Account Disconnected'),
        ('permission_granted', 'Permission Granted'),
        ('permission_revoked', 'Permission Revoked'),
        ('suspicious_activity', 'Suspicious Activity'),
    ])
    provider = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)

    # Context information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    session_id = models.UUIDField(null=True, blank=True)

    # Event specific data
    event_data = models.JSONField(default=dict, help_text="Additional event-specific information")
    risk_level = models.CharField(max_length=10, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ], default='low')

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "OAuth Security Log"
        verbose_name_plural = "OAuth Security Logs"
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['risk_level', 'timestamp']),
        ]

    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.event_type} - {self.provider}"

    @classmethod
    def log_event(cls, event_type, provider, ip_address, user=None, user_agent='',
                  session_id=None, event_data=None, risk_level='low'):
        """Create a security log entry"""
        return cls.objects.create(
            user=user,
            event_type=event_type,
            provider=provider,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            event_data=event_data or {},
            risk_level=risk_level
        )
