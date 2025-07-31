from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import OAuthUserProfile, OAuthLoginSession, OAuthAppConnection, OAuthSecurityLog


@admin.register(OAuthUserProfile)
class OAuthUserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'preferred_provider', 'auto_login_enabled', 'profile_completed', 'created_at']
    list_filter = ['preferred_provider', 'auto_login_enabled', 'profile_completed', 'share_email', 'share_profile']
    search_fields = ['user__username', 'user__email', 'preferred_provider']
    readonly_fields = ['created_at', 'updated_at', 'profile_completion_date']

    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('OAuth Preferences', {
            'fields': ('preferred_provider', 'auto_login_enabled')
        }),
        ('Profile Status', {
            'fields': ('profile_completed', 'profile_completion_date')
        }),
        ('Privacy Settings', {
            'fields': ('share_email', 'share_profile')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(OAuthLoginSession)
class OAuthLoginSessionAdmin(admin.ModelAdmin):
    list_display = ['user', 'provider', 'session_id_short', 'login_timestamp', 'is_active', 'ip_address', 'login_method']
    list_filter = ['provider', 'is_active', 'login_method', 'login_timestamp']
    search_fields = ['user__username', 'provider', 'provider_uid', 'ip_address', 'session_id']
    readonly_fields = ['session_id', 'login_timestamp', 'logout_timestamp']
    date_hierarchy = 'login_timestamp'

    def session_id_short(self, obj):
        return f"{str(obj.session_id)[:8]}..."
    session_id_short.short_description = 'Session ID'

    fieldsets = (
        ('Session Information', {
            'fields': ('user', 'session_id', 'is_active')
        }),
        ('OAuth Details', {
            'fields': ('provider', 'provider_uid', 'login_method')
        }),
        ('Timestamps', {
            'fields': ('login_timestamp', 'logout_timestamp', 'access_token_expires')
        }),
        ('Client Information', {
            'fields': ('ip_address', 'user_agent')
        }),
        ('OAuth Data', {
            'fields': ('scope_granted',),
            'classes': ('collapse',)
        }),
    )


@admin.register(OAuthAppConnection)
class OAuthAppConnectionAdmin(admin.ModelAdmin):
    list_display = ['user', 'social_app', 'data_access_level', 'is_active', 'connected_at', 'usage_count']
    list_filter = ['social_app', 'data_access_level', 'is_active', 'connected_at']
    search_fields = ['user__username', 'social_app__name', 'last_ip_address']
    readonly_fields = ['connected_at', 'last_used', 'usage_count']

    fieldsets = (
        ('Connection Information', {
            'fields': ('user', 'social_app', 'is_active')
        }),
        ('Permissions', {
            'fields': ('data_access_level', 'permissions_granted')
        }),
        ('Usage Statistics', {
            'fields': ('connected_at', 'last_used', 'usage_count', 'last_ip_address')
        }),
    )


@admin.register(OAuthSecurityLog)
class OAuthSecurityLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'user', 'event_type', 'provider', 'risk_level', 'ip_address']
    list_filter = ['event_type', 'provider', 'risk_level', 'timestamp']
    search_fields = ['user__username', 'provider', 'ip_address', 'user_agent']
    readonly_fields = ['timestamp', 'session_id']
    date_hierarchy = 'timestamp'

    fieldsets = (
        ('Event Information', {
            'fields': ('user', 'event_type', 'provider', 'risk_level')
        }),
        ('Context', {
            'fields': ('timestamp', 'ip_address', 'user_agent', 'session_id')
        }),
        ('Event Data', {
            'fields': ('event_data',),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user').order_by('-timestamp')
