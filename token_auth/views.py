from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import APIToken, TokenUsageLog
import json


# Custom Token Authentication Class
class TokenAuthentication(BaseAuthentication):
    """Custom token authentication for API endpoints"""

    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Token '):
            return None

        token = auth_header.split(' ')[1]

        try:
            api_token = APIToken.objects.get(token=token)
            if not api_token.is_valid():
                return None

            # Log token usage
            ip_address = self.get_client_ip(request)
            if api_token.use_token(ip_address):
                # Log usage
                TokenUsageLog.objects.create(
                    token=api_token,
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    endpoint=request.path,
                    method=request.method
                )
                return (api_token.user, api_token)

        except APIToken.DoesNotExist:
            pass

        return None

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


# Web Views
def token_auth_home(request):
    """Home page for token authentication demo"""
    context = {
        'user_tokens': [],
        'token_count': 0
    }

    if request.user.is_authenticated:
        user_tokens = APIToken.objects.filter(user=request.user, is_active=True)
        context['user_tokens'] = user_tokens[:5]  # Show first 5 tokens
        context['token_count'] = user_tokens.count()

    return render(request, 'token_auth/home.html', context)


@csrf_protect
def token_login(request):
    """Token-based login (creates session and optionally API token)"""
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        create_token = request.POST.get('create_token', False)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)

                # Create API token if requested
                if create_token:
                    token = APIToken.objects.create(
                        user=user,
                        token_type='access',
                        name=f'Web Login Token - {timezone.now().strftime("%Y-%m-%d %H:%M")}',
                        scopes=['read', 'write'],
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    messages.success(request, f'Welcome back, {username}! API token created: {token.get_masked_token()}')
                else:
                    messages.success(request, f'Welcome back, {username}!')

                return redirect('token_auth:dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()

    return render(request, 'token_auth/login.html', {'form': form})


@csrf_protect
def token_register(request):
    """Token-based registration with automatic API token creation"""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')

            # Auto login after registration
            login(request, user)

            # Create initial API token
            token = APIToken.objects.create(
                user=user,
                token_type='api_key',
                name='Initial API Key',
                scopes=['read', 'write'],
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

            messages.success(request, f'Account created for {username}! Your API key: {token.get_masked_token()}')
            return redirect('token_auth:dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserCreationForm()

    return render(request, 'token_auth/register.html', {'form': form})


def token_logout(request):
    """Token-based logout"""
    username = request.user.username if request.user.is_authenticated else 'User'
    logout(request)
    messages.success(request, f'Goodbye {username}! You have been logged out.')
    return redirect('token_auth:home')


@login_required
def token_dashboard(request):
    """Protected dashboard with token management"""
    user_tokens = APIToken.objects.filter(user=request.user).order_by('-created_at')

    # Pagination
    paginator = Paginator(user_tokens, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Statistics
    total_tokens = user_tokens.count()
    active_tokens = user_tokens.filter(is_active=True).count()
    expired_tokens = user_tokens.filter(expires_at__lt=timezone.now()).count()

    context = {
        'page_obj': page_obj,
        'total_tokens': total_tokens,
        'active_tokens': active_tokens,
        'expired_tokens': expired_tokens,
    }

    return render(request, 'token_auth/dashboard.html', context)


@login_required
def token_profile(request):
    """User profile with token statistics"""
    user_tokens = APIToken.objects.filter(user=request.user)
    recent_usage = TokenUsageLog.objects.filter(token__user=request.user).order_by('-timestamp')[:10]

    context = {
        'user_tokens': user_tokens,
        'recent_usage': recent_usage,
        'total_usage': TokenUsageLog.objects.filter(token__user=request.user).count(),
    }
    return render(request, 'token_auth/profile.html', context)


@login_required
@csrf_protect
def token_management(request):
    """Token management page"""
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'create_token':
            token_name = request.POST.get('token_name', 'New Token')
            token_type = request.POST.get('token_type', 'access')
            scopes = request.POST.getlist('scopes')

            token = APIToken.objects.create(
                user=request.user,
                token_type=token_type,
                name=token_name,
                scopes=scopes,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            messages.success(request, f'Token "{token_name}" created successfully! Token: {token.get_masked_token()}')

        elif action == 'revoke_token':
            token_id = request.POST.get('token_id')
            try:
                token = APIToken.objects.get(id=token_id, user=request.user)
                token.revoke()
                messages.success(request, f'Token "{token.name}" has been revoked.')
            except APIToken.DoesNotExist:
                messages.error(request, 'Token not found.')

        elif action == 'extend_token':
            token_id = request.POST.get('token_id')
            days = int(request.POST.get('days', 30))
            try:
                token = APIToken.objects.get(id=token_id, user=request.user)
                token.extend_expiry(days)
                messages.success(request, f'Token "{token.name}" expiry extended by {days} days.')
            except APIToken.DoesNotExist:
                messages.error(request, 'Token not found.')

        return redirect('token_auth:token_management')

    user_tokens = APIToken.objects.filter(user=request.user).order_by('-created_at')
    available_scopes = ['read', 'write', 'admin', 'delete']

    context = {
        'user_tokens': user_tokens,
        'available_scopes': available_scopes,
    }
    return render(request, 'token_auth/management.html', context)


@login_required
def token_detail(request, token_id):
    """Detailed view of a specific token"""
    token = get_object_or_404(APIToken, id=token_id, user=request.user)
    usage_logs = TokenUsageLog.objects.filter(token=token).order_by('-timestamp')

    # Pagination for usage logs
    paginator = Paginator(usage_logs, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'token': token,
        'page_obj': page_obj,
        'usage_count': usage_logs.count(),
    }
    return render(request, 'token_auth/token_detail.html', context)


# API Views
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def api_user_profile(request):
    """API endpoint to get user profile (requires token authentication)"""
    user = request.user
    token = request.auth

    return Response({
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'date_joined': user.date_joined,
        'token_info': {
            'name': token.name,
            'type': token.token_type,
            'scopes': token.scopes,
            'expires_at': token.expires_at,
            'usage_count': token.usage_count,
        }
    })


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def api_token_info(request):
    """API endpoint to get current token information"""
    token = request.auth

    return Response({
        'token_name': token.name,
        'token_type': token.token_type,
        'scopes': token.scopes,
        'created_at': token.created_at,
        'expires_at': token.expires_at,
        'last_used': token.last_used,
        'usage_count': token.usage_count,
        'max_usage': token.max_usage,
        'is_active': token.is_active,
        'is_expired': token.is_expired(),
        'is_valid': token.is_valid(),
    })


@api_view(['POST'])
@csrf_exempt
def api_create_token(request):
    """API endpoint to create new token (requires username/password)"""
    username = request.data.get('username')
    password = request.data.get('password')
    token_name = request.data.get('token_name', 'API Generated Token')
    token_type = request.data.get('token_type', 'access')
    scopes = request.data.get('scopes', ['read'])

    if not username or not password:
        return Response({
            'error': 'Username and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if not user:
        return Response({
            'error': 'Invalid credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)

    token = APIToken.objects.create(
        user=user,
        token_type=token_type,
        name=token_name,
        scopes=scopes,
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )

    return Response({
        'token': token.token,
        'token_type': token.token_type,
        'expires_at': token.expires_at,
        'scopes': token.scopes,
        'message': 'Token created successfully'
    }, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def api_refresh_token(request):
    """API endpoint to refresh token"""
    current_token = request.auth

    if current_token.token_type != 'refresh':
        return Response({
            'error': 'Only refresh tokens can be used to generate new tokens'
        }, status=status.HTTP_400_BAD_REQUEST)

    new_token = current_token.refresh_token()
    if new_token:
        return Response({
            'access_token': new_token.token,
            'expires_at': new_token.expires_at,
            'token_type': new_token.token_type,
            'scopes': new_token.scopes,
        })
    else:
        return Response({
            'error': 'Failed to refresh token'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def api_revoke_token(request):
    """API endpoint to revoke current token"""
    token = request.auth
    token.revoke()

    return Response({
        'message': 'Token revoked successfully'
    })


# Status and utility views
def token_auth_status(request):
    """API endpoint to check token authentication status"""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    has_token = auth_header.startswith('Token ')

    token_info = None
    if has_token:
        token_value = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else ''
        try:
            token = APIToken.objects.get(token=token_value)
            token_info = {
                'name': token.name,
                'type': token.token_type,
                'is_valid': token.is_valid(),
                'expires_at': token.expires_at.isoformat(),
                'usage_count': token.usage_count,
            }
        except APIToken.DoesNotExist:
            pass

    return JsonResponse({
        'authenticated': request.user.is_authenticated,
        'username': request.user.username if request.user.is_authenticated else None,
        'user_id': request.user.id if request.user.is_authenticated else None,
        'has_token_header': has_token,
        'token_info': token_info,
        'session_authenticated': request.user.is_authenticated,
    })
