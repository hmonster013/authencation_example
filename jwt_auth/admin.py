from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import JWTBlacklist, JWTUserSession, JWTLoginAttempt


@admin.register(JWTBlacklist)
class JWTBlacklistAdmin(admin.ModelAdmin):
    list_display = ['jti_short', 'user', 'token_type', 'reason', 'blacklisted_at', 'expires_at', 'is_expired']
    list_filter = ['token_type', 'reason', 'blacklisted_at']
    search_fields = ['jti', 'user__username', 'ip_address']
    readonly_fields = ['jti', 'blacklisted_at']
    date_hierarchy = 'blacklisted_at'

    def jti_short(self, obj):
        return f"{obj.jti[:8]}..." if len(obj.jti) > 8 else obj.jti
    jti_short.short_description = 'JTI'

    def is_expired(self, obj):
        expired = timezone.now() > obj.expires_at
        color = 'red' if expired else 'green'
        text = 'Expired' if expired else 'Active'
        return format_html(f'<span style="color: {color};">{text}</span>')
    is_expired.short_description = 'Status'


@admin.register(JWTUserSession)
class JWTUserSessionAdmin(admin.ModelAdmin):
    list_display = ['session_id_short', 'user', 'ip_address', 'device_summary', 'is_active', 'created_at', 'expires_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['session_id', 'user__username', 'ip_address', 'refresh_jti']
    readonly_fields = ['session_id', 'refresh_jti', 'created_at', 'last_activity']
    date_hierarchy = 'created_at'

    def session_id_short(self, obj):
        return f"{str(obj.session_id)[:8]}..."
    session_id_short.short_description = 'Session ID'

    def device_summary(self, obj):
        device_info = obj.device_info
        if device_info.get('browser'):
            device_type = '📱' if device_info.get('is_mobile') else '💻'
            return f"{device_type} {device_info.get('browser', 'Unknown')}"
        return 'Unknown Device'
    device_summary.short_description = 'Device'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(JWTLoginAttempt)
class JWTLoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'username', 'ip_address', 'success', 'failure_reason', 'user_agent_short']
    list_filter = ['success', 'failure_reason', 'timestamp']
    search_fields = ['username', 'ip_address', 'user_agent']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'

    def user_agent_short(self, obj):
        return obj.user_agent[:50] + '...' if len(obj.user_agent) > 50 else obj.user_agent
    user_agent_short.short_description = 'User Agent'

    def get_queryset(self, request):
        return super().get_queryset(request).order_by('-timestamp')
