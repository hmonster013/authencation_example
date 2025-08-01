from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.conf import settings
from django.urls import reverse
from allauth.socialaccount.models import SocialAccount, SocialApp, SocialToken
from allauth.socialaccount.helpers import complete_social_login
from allauth.socialaccount import app_settings
from allauth.account.utils import get_next_redirect_url
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from .models import OAuthUserProfile, OAuthLoginSession, OAuthAppConnection, OAuthSecurityLog
import json
import uuid
from user_agents import parse
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client


def direct_google_login(request):
    """
    Direct redirect to Google OAuth with auto-submit
    """
    # Create a simple auto-submit page
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting to Google...</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 2s linear infinite; margin: 20px auto; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        </style>
    </head>
    <body>
        <h3>Redirecting to Google OAuth...</h3>
        <div class="spinner"></div>
        <p>Please wait while we redirect you to Google for authentication.</p>

        <form method="post" action="/accounts/google/login/" id="oauth-form">
            <input type="hidden" name="csrfmiddlewaretoken" value="''' + str(request.META.get('CSRF_COOKIE', request.COOKIES.get('csrftoken', ''))) + '''">
        </form>

        <script>
            setTimeout(function() {
                document.getElementById('oauth-form').submit();
            }, 1000);
        </script>
    </body>
    </html>
    '''

    from django.http import HttpResponse
    return HttpResponse(html)


def direct_github_login(request):
    """
    Direct redirect to GitHub OAuth using allauth properly
    """
    # Use allauth's proper OAuth flow instead of manual redirect
    return redirect('/accounts/github/login/')


# Utility functions
def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def parse_device_info(user_agent_string):
    """Parse device information from user agent"""
    try:
        user_agent = parse(user_agent_string)
        return {
            'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
            'os': f"{user_agent.os.family} {user_agent.os.version_string}",
            'device': user_agent.device.family,
            'is_mobile': user_agent.is_mobile,
            'is_tablet': user_agent.is_tablet,
            'is_pc': user_agent.is_pc,
        }
    except:
        return {'raw': user_agent_string}


def create_oauth_session(user, provider, provider_uid, request, login_method='oauth_existing'):
    """Create OAuth login session"""
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')

    # Get OAuth token expiry if available
    social_account = SocialAccount.objects.filter(user=user, provider=provider).first()
    token_expires = None
    scope_granted = []

    if social_account:
        try:
            social_token = SocialToken.objects.filter(account=social_account).first()
            if social_token and social_token.expires_at:
                token_expires = social_token.expires_at

            # Get scope from extra data
            extra_data = social_account.extra_data
            if 'scope' in extra_data:
                scope_granted = extra_data['scope'].split() if isinstance(extra_data['scope'], str) else extra_data['scope']
        except:
            pass

    session = OAuthLoginSession.objects.create(
        user=user,
        provider=provider,
        provider_uid=provider_uid,
        ip_address=ip_address,
        user_agent=user_agent,
        access_token_expires=token_expires,
        scope_granted=scope_granted,
        login_method=login_method
    )

    # Log security event
    OAuthSecurityLog.log_event(
        event_type='login_success',
        provider=provider,
        ip_address=ip_address,
        user=user,
        user_agent=user_agent,
        session_id=session.session_id,
        event_data={
            'login_method': login_method,
            'scope_granted': scope_granted
        }
    )

    return session


# Web Views
def oauth_auth_home(request):
    """Home page for OAuth authentication demo"""
    context = {
        'available_providers': [],
        'user_accounts': [],
        'recent_sessions': [],
        'connected_apps': []
    }

    # Get available OAuth providers
    available_providers = SocialApp.objects.filter(sites__id=settings.SITE_ID)
    context['available_providers'] = available_providers

    if request.user.is_authenticated:
        # Get user's connected accounts
        user_accounts = SocialAccount.objects.filter(user=request.user)
        context['user_accounts'] = user_accounts

        # Get recent OAuth sessions
        recent_sessions = OAuthLoginSession.objects.filter(user=request.user)[:5]
        context['recent_sessions'] = recent_sessions

        # Get connected apps
        connected_apps = OAuthAppConnection.objects.filter(user=request.user, is_active=True)
        context['connected_apps'] = connected_apps

        # Get or create OAuth profile
        oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)
        context['oauth_profile'] = oauth_profile

    return render(request, 'oauth_auth/home.html', context)


@login_required
def oauth_dashboard(request):
    """Protected dashboard with OAuth session management"""
    user_sessions = OAuthLoginSession.objects.filter(user=request.user).order_by('-login_timestamp')
    connected_accounts = SocialAccount.objects.filter(user=request.user)
    connected_apps = OAuthAppConnection.objects.filter(user=request.user)

    # Pagination for sessions
    paginator = Paginator(user_sessions, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Statistics
    total_sessions = user_sessions.count()
    active_sessions = user_sessions.filter(is_active=True).count()
    total_providers = connected_accounts.values('provider').distinct().count()

    # Get OAuth profile
    oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)

    context = {
        'page_obj': page_obj,
        'connected_accounts': connected_accounts,
        'connected_apps': connected_apps,
        'total_sessions': total_sessions,
        'active_sessions': active_sessions,
        'total_providers': total_providers,
        'oauth_profile': oauth_profile,
    }

    return render(request, 'oauth_auth/dashboard.html', context)


@login_required
def oauth_profile(request):
    """User profile with OAuth account management"""
    connected_accounts = SocialAccount.objects.filter(user=request.user)
    recent_sessions = OAuthLoginSession.objects.filter(user=request.user).order_by('-login_timestamp')[:10]
    security_logs = OAuthSecurityLog.objects.filter(user=request.user).order_by('-timestamp')[:10]

    # Get or create OAuth profile
    oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)

    context = {
        'connected_accounts': connected_accounts,
        'recent_sessions': recent_sessions,
        'security_logs': security_logs,
        'oauth_profile': oauth_profile,
        'total_logins': OAuthLoginSession.objects.filter(user=request.user).count(),
        'providers_used': connected_accounts.values('provider').distinct().count(),
    }
    return render(request, 'oauth_auth/profile.html', context)


@login_required
@csrf_protect
def oauth_account_management(request):
    """OAuth account management page"""
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'disconnect_account':
            account_id = request.POST.get('account_id')
            try:
                account = SocialAccount.objects.get(id=account_id, user=request.user)
                provider = account.provider

                # Log security event
                OAuthSecurityLog.log_event(
                    event_type='account_disconnected',
                    provider=provider,
                    ip_address=get_client_ip(request),
                    user=request.user,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    event_data={'account_id': account_id}
                )

                account.delete()
                messages.success(request, f'{provider.title()} account disconnected successfully.')
            except SocialAccount.DoesNotExist:
                messages.error(request, 'Account not found.')

        elif action == 'set_preferred_provider':
            provider = request.POST.get('provider')
            oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)
            oauth_profile.preferred_provider = provider
            oauth_profile.save()
            messages.success(request, f'{provider.title()} set as preferred provider.')

        elif action == 'toggle_auto_login':
            oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)
            oauth_profile.auto_login_enabled = not oauth_profile.auto_login_enabled
            oauth_profile.save()
            status = 'enabled' if oauth_profile.auto_login_enabled else 'disabled'
            messages.success(request, f'Auto-login {status}.')

        elif action == 'update_privacy':
            oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)
            oauth_profile.share_email = request.POST.get('share_email') == 'on'
            oauth_profile.share_profile = request.POST.get('share_profile') == 'on'
            oauth_profile.save()
            messages.success(request, 'Privacy settings updated.')

        return redirect('oauth_auth:account_management')

    connected_accounts = SocialAccount.objects.filter(user=request.user)
    oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=request.user)
    available_providers = SocialApp.objects.filter(sites__id=settings.SITE_ID)

    context = {
        'connected_accounts': connected_accounts,
        'oauth_profile': oauth_profile,
        'available_providers': available_providers,
    }
    return render(request, 'oauth_auth/account_management.html', context)


@login_required
def oauth_session_detail(request, session_id):
    """Detailed view of a specific OAuth session"""
    try:
        session = OAuthLoginSession.objects.get(
            session_id=session_id,
            user=request.user
        )
    except OAuthLoginSession.DoesNotExist:
        messages.error(request, 'Session not found.')
        return redirect('oauth_auth:dashboard')

    # Get related security logs
    security_logs = OAuthSecurityLog.objects.filter(
        user=request.user,
        session_id=session_id
    ).order_by('-timestamp')

    # Get social account info
    social_account = SocialAccount.objects.filter(
        user=request.user,
        provider=session.provider
    ).first()

    context = {
        'session': session,
        'security_logs': security_logs,
        'social_account': social_account,
        'device_info': parse_device_info(session.user_agent),
    }
    return render(request, 'oauth_auth/session_detail.html', context)


@login_required
@csrf_protect
def oauth_app_connections(request):
    """Manage OAuth app connections"""
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'revoke_connection':
            connection_id = request.POST.get('connection_id')
            try:
                connection = OAuthAppConnection.objects.get(
                    id=connection_id,
                    user=request.user
                )
                connection.revoke_connection()

                # Log security event
                OAuthSecurityLog.log_event(
                    event_type='permission_revoked',
                    provider=connection.social_app.provider,
                    ip_address=get_client_ip(request),
                    user=request.user,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    event_data={'app_name': connection.social_app.name}
                )

                messages.success(request, f'Connection to {connection.social_app.name} revoked.')
            except OAuthAppConnection.DoesNotExist:
                messages.error(request, 'Connection not found.')

        return redirect('oauth_auth:app_connections')

    connections = OAuthAppConnection.objects.filter(user=request.user).order_by('-connected_at')

    context = {
        'connections': connections,
    }
    return render(request, 'oauth_auth/app_connections.html', context)


def oauth_logout(request):
    """OAuth-based logout with session cleanup"""
    username = request.user.username if request.user.is_authenticated else 'User'

    # End all active OAuth sessions
    if request.user.is_authenticated:
        active_sessions = OAuthLoginSession.get_active_sessions(request.user)
        for session in active_sessions:
            session.end_session()

            # Log security event
            OAuthSecurityLog.log_event(
                event_type='login_success',  # This is actually logout, but we track it as session end
                provider=session.provider,
                ip_address=get_client_ip(request),
                user=request.user,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                session_id=session.session_id,
                event_data={'action': 'logout'}
            )

    logout(request)
    messages.success(request, f'Goodbye {username}! All OAuth sessions ended.')
    return redirect('oauth_auth:home')


# Custom OAuth signal handlers and views
def oauth_login_success_handler(request, user, sociallogin, **kwargs):
    """Handle successful OAuth login"""
    provider = sociallogin.account.provider
    provider_uid = sociallogin.account.uid

    # Determine login method
    login_method = 'oauth_new' if sociallogin.is_existing else 'oauth_existing'

    # Create OAuth session
    session = create_oauth_session(user, provider, provider_uid, request, login_method)

    # Store session ID in Django session
    request.session['oauth_session_id'] = str(session.session_id)

    # Get or create OAuth profile
    oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=user)

    # Set preferred provider if this is the first login
    if not oauth_profile.preferred_provider:
        oauth_profile.preferred_provider = provider
        oauth_profile.save()

    # Complete profile if needed
    if not oauth_profile.profile_completed:
        oauth_profile.complete_profile()

    return None  # Continue with normal flow


def oauth_connect_success_handler(request, user, sociallogin, **kwargs):
    """Handle successful OAuth account connection"""
    provider = sociallogin.account.provider

    # Log security event
    OAuthSecurityLog.log_event(
        event_type='account_connected',
        provider=provider,
        ip_address=get_client_ip(request),
        user=user,
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        event_data={'provider_uid': sociallogin.account.uid}
    )

    messages.success(request, f'{provider.title()} account connected successfully!')
    return None


# API Views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_oauth_user_profile(request):
    """API endpoint to get user profile with OAuth information"""
    user = request.user

    # Get OAuth profile
    try:
        oauth_profile = OAuthUserProfile.objects.get(user=user)
    except OAuthUserProfile.DoesNotExist:
        oauth_profile = None

    # Get connected accounts
    connected_accounts = SocialAccount.objects.filter(user=user)
    accounts_data = []
    for account in connected_accounts:
        accounts_data.append({
            'provider': account.provider,
            'uid': account.uid,
            'date_joined': account.date_joined,
            'extra_data': account.extra_data
        })

    # Get active sessions
    active_sessions = OAuthLoginSession.get_active_sessions(user)
    sessions_data = []
    for session in active_sessions:
        sessions_data.append({
            'session_id': str(session.session_id),
            'provider': session.provider,
            'login_timestamp': session.login_timestamp,
            'ip_address': session.ip_address,
            'is_token_expired': session.is_token_expired()
        })

    return Response({
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'date_joined': user.date_joined,
        'oauth_profile': {
            'preferred_provider': oauth_profile.preferred_provider if oauth_profile else None,
            'auto_login_enabled': oauth_profile.auto_login_enabled if oauth_profile else False,
            'profile_completed': oauth_profile.profile_completed if oauth_profile else False,
            'share_email': oauth_profile.share_email if oauth_profile else True,
            'share_profile': oauth_profile.share_profile if oauth_profile else True,
        } if oauth_profile else None,
        'connected_accounts': accounts_data,
        'active_sessions': sessions_data,
        'total_sessions': OAuthLoginSession.objects.filter(user=user).count(),
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_oauth_sessions(request):
    """API endpoint to get user's OAuth sessions"""
    sessions = OAuthLoginSession.objects.filter(user=request.user).order_by('-login_timestamp')

    session_data = []
    for session in sessions:
        session_data.append({
            'session_id': str(session.session_id),
            'provider': session.provider,
            'provider_uid': session.provider_uid,
            'login_timestamp': session.login_timestamp,
            'logout_timestamp': session.logout_timestamp,
            'is_active': session.is_active,
            'ip_address': session.ip_address,
            'user_agent': session.user_agent,
            'access_token_expires': session.access_token_expires,
            'scope_granted': session.scope_granted,
            'login_method': session.login_method,
            'is_token_expired': session.is_token_expired(),
        })

    return Response({
        'sessions': session_data,
        'total_count': len(session_data),
        'active_count': sum(1 for s in session_data if s['is_active']),
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_oauth_disconnect_account(request):
    """API endpoint to disconnect OAuth account"""
    provider = request.data.get('provider')

    if not provider:
        return Response({
            'error': 'provider is required'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        account = SocialAccount.objects.get(
            user=request.user,
            provider=provider
        )

        # Log security event
        OAuthSecurityLog.log_event(
            event_type='account_disconnected',
            provider=provider,
            ip_address=get_client_ip(request),
            user=request.user,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            event_data={'account_uid': account.uid}
        )

        account.delete()

        return Response({
            'message': f'{provider.title()} account disconnected successfully',
            'provider': provider
        })

    except SocialAccount.DoesNotExist:
        return Response({
            'error': 'Account not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_oauth_end_session(request):
    """API endpoint to end specific OAuth session"""
    session_id = request.data.get('session_id')

    if not session_id:
        return Response({
            'error': 'session_id is required'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = OAuthLoginSession.objects.get(
            session_id=session_id,
            user=request.user
        )
        session.end_session()

        return Response({
            'message': 'Session ended successfully',
            'session_id': session_id
        })

    except OAuthLoginSession.DoesNotExist:
        return Response({
            'error': 'Session not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_oauth_end_all_sessions(request):
    """API endpoint to end all user's OAuth sessions"""
    active_sessions = OAuthLoginSession.get_active_sessions(request.user)

    count = 0
    for session in active_sessions:
        session.end_session()
        count += 1

    return Response({
        'message': f'Ended {count} active sessions',
        'ended_count': count
    })


# Status and utility views
def oauth_auth_status(request):
    """API endpoint to check OAuth authentication status"""
    context = {
        'authenticated': request.user.is_authenticated,
        'username': request.user.username if request.user.is_authenticated else None,
        'user_id': request.user.id if request.user.is_authenticated else None,
        'session_authenticated': request.user.is_authenticated,
        'oauth_session_id': request.session.get('oauth_session_id'),
    }

    if request.user.is_authenticated:
        # Get connected accounts
        connected_accounts = SocialAccount.objects.filter(user=request.user)
        context['connected_providers'] = [acc.provider for acc in connected_accounts]
        context['total_providers'] = connected_accounts.count()

        # Get active sessions
        active_sessions = OAuthLoginSession.get_active_sessions(request.user)
        context['active_oauth_sessions'] = active_sessions.count()

        # Get OAuth profile
        try:
            oauth_profile = OAuthUserProfile.objects.get(user=request.user)
            context['preferred_provider'] = oauth_profile.preferred_provider
            context['auto_login_enabled'] = oauth_profile.auto_login_enabled
        except OAuthUserProfile.DoesNotExist:
            context['preferred_provider'] = None
            context['auto_login_enabled'] = False

    return JsonResponse(context)
