from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from .models import JWTBlacklist, JWTUserSession, JWTLoginAttempt
import json
import jwt
import uuid
from datetime import timedelta
from user_agents import parse


# Custom JWT Token Serializer
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom JWT token serializer with additional claims and session tracking"""

    def validate(self, attrs):
        # Get request from context
        request = self.context.get('request')
        ip_address = self.get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Check for rate limiting
        username = attrs.get('username')
        recent_failures = JWTLoginAttempt.get_recent_failures(
            username=username,
            ip_address=ip_address
        )

        if recent_failures >= 5:  # Max 5 failed attempts in 15 minutes
            JWTLoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                failure_reason='rate_limited'
            )
            raise TokenError('Too many failed login attempts. Please try again later.')

        try:
            data = super().validate(attrs)

            # Log successful login
            JWTLoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True
            )

            # Create user session
            refresh_token = RefreshToken(data['refresh'])
            session = JWTUserSession.objects.create(
                user=self.user,
                refresh_jti=str(refresh_token['jti']),
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=self.parse_device_info(user_agent),
                expires_at=timezone.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
            )

            # Add custom claims to tokens
            refresh_token['session_id'] = str(session.session_id)
            refresh_token['ip'] = ip_address

            access_token = refresh_token.access_token
            access_token['session_id'] = str(session.session_id)
            access_token['ip'] = ip_address

            data['refresh'] = str(refresh_token)
            data['access'] = str(access_token)
            data['session_id'] = str(session.session_id)

            return data

        except Exception as e:
            # Log failed login
            JWTLoginAttempt.objects.create(
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                failure_reason='invalid_credentials'
            )
            raise

    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def parse_device_info(self, user_agent_string):
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


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT token obtain view with session tracking"""
    serializer_class = CustomTokenObtainPairSerializer


# Custom JWT Authentication Middleware
class JWTBlacklistMiddleware:
    """Middleware to check JWT blacklist"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Check if request has JWT token
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                # Decode token without verification to get JTI
                decoded = jwt.decode(token, options={"verify_signature": False})
                jti = decoded.get('jti')

                if jti and JWTBlacklist.is_blacklisted(jti):
                    return JsonResponse({
                        'error': 'Token has been revoked',
                        'code': 'token_blacklisted'
                    }, status=401)

            except jwt.DecodeError:
                pass  # Let DRF handle invalid tokens

        response = self.get_response(request)
        return response


# Web Views
def jwt_auth_home(request):
    """Home page for JWT authentication demo"""
    context = {
        'user_sessions': [],
        'session_count': 0,
        'recent_logins': []
    }

    if request.user.is_authenticated:
        user_sessions = JWTUserSession.objects.filter(user=request.user, is_active=True)
        context['user_sessions'] = user_sessions[:5]  # Show first 5 sessions
        context['session_count'] = user_sessions.count()

        recent_logins = JWTLoginAttempt.objects.filter(
            username=request.user.username,
            success=True
        )[:5]
        context['recent_logins'] = recent_logins

    return render(request, 'jwt_auth/home.html', context)


@csrf_protect
def jwt_login(request):
    """JWT-based login (creates session and returns tokens)"""
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        create_session = request.POST.get('create_session', False)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)

                # Create JWT tokens if requested
                if create_session:
                    try:
                        # Use custom serializer to create tokens
                        serializer = CustomTokenObtainPairSerializer()
                        serializer.context = {'request': request}
                        tokens = serializer.validate({
                            'username': username,
                            'password': password
                        })

                        # Store tokens in session for web interface
                        request.session['jwt_access'] = tokens['access']
                        request.session['jwt_refresh'] = tokens['refresh']
                        request.session['jwt_session_id'] = tokens['session_id']

                        messages.success(request, f'Welcome back, {username}! JWT session created.')
                    except Exception as e:
                        messages.warning(request, f'Login successful but JWT creation failed: {str(e)}')
                else:
                    messages.success(request, f'Welcome back, {username}!')

                return redirect('jwt_auth:dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()

    return render(request, 'jwt_auth/login.html', {'form': form})


@csrf_protect
def jwt_register(request):
    """JWT-based registration with automatic JWT session creation"""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')

            # Auto login after registration
            login(request, user)

            # Create JWT session
            try:
                serializer = CustomTokenObtainPairSerializer()
                serializer.context = {'request': request}
                tokens = serializer.validate({
                    'username': username,
                    'password': password
                })

                # Store tokens in session
                request.session['jwt_access'] = tokens['access']
                request.session['jwt_refresh'] = tokens['refresh']
                request.session['jwt_session_id'] = tokens['session_id']

                messages.success(request, f'Account created for {username}! JWT session established.')
            except Exception as e:
                messages.warning(request, f'Account created but JWT session failed: {str(e)}')

            return redirect('jwt_auth:dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserCreationForm()

    return render(request, 'jwt_auth/register.html', {'form': form})


def jwt_logout(request):
    """JWT-based logout with token blacklisting"""
    username = request.user.username if request.user.is_authenticated else 'User'

    # Blacklist JWT tokens if they exist in session
    if 'jwt_session_id' in request.session:
        try:
            session_id = request.session['jwt_session_id']
            session = JWTUserSession.objects.get(session_id=session_id)
            session.terminate(reason='logout')

            # Clear JWT data from session
            for key in ['jwt_access', 'jwt_refresh', 'jwt_session_id']:
                request.session.pop(key, None)

        except JWTUserSession.DoesNotExist:
            pass

    logout(request)
    messages.success(request, f'Goodbye {username}! JWT session terminated.')
    return redirect('jwt_auth:home')


@login_required
def jwt_dashboard(request):
    """Protected dashboard with JWT session management"""
    user_sessions = JWTUserSession.objects.filter(user=request.user).order_by('-created_at')

    # Pagination
    paginator = Paginator(user_sessions, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # Statistics
    total_sessions = user_sessions.count()
    active_sessions = user_sessions.filter(is_active=True).count()
    expired_sessions = user_sessions.filter(expires_at__lt=timezone.now()).count()

    # Current session info
    current_session = None
    if 'jwt_session_id' in request.session:
        try:
            current_session = JWTUserSession.objects.get(
                session_id=request.session['jwt_session_id']
            )
        except JWTUserSession.DoesNotExist:
            pass

    context = {
        'page_obj': page_obj,
        'total_sessions': total_sessions,
        'active_sessions': active_sessions,
        'expired_sessions': expired_sessions,
        'current_session': current_session,
    }

    return render(request, 'jwt_auth/dashboard.html', context)


@login_required
def jwt_profile(request):
    """User profile with JWT session statistics"""
    user_sessions = JWTUserSession.objects.filter(user=request.user)
    recent_logins = JWTLoginAttempt.objects.filter(
        username=request.user.username
    ).order_by('-timestamp')[:10]

    context = {
        'user_sessions': user_sessions,
        'recent_logins': recent_logins,
        'total_logins': JWTLoginAttempt.objects.filter(
            username=request.user.username,
            success=True
        ).count(),
        'failed_logins': JWTLoginAttempt.objects.filter(
            username=request.user.username,
            success=False
        ).count(),
    }
    return render(request, 'jwt_auth/profile.html', context)


@login_required
@csrf_protect
def jwt_session_management(request):
    """JWT session management page"""
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'terminate_session':
            session_id = request.POST.get('session_id')
            try:
                session = JWTUserSession.objects.get(
                    session_id=session_id,
                    user=request.user
                )
                session.terminate(reason='manual')
                messages.success(request, f'Session terminated successfully.')
            except JWTUserSession.DoesNotExist:
                messages.error(request, 'Session not found.')

        elif action == 'terminate_all':
            active_sessions = JWTUserSession.objects.filter(
                user=request.user,
                is_active=True
            )
            count = 0
            for session in active_sessions:
                session.terminate(reason='manual')
                count += 1
            messages.success(request, f'Terminated {count} active sessions.')

        return redirect('jwt_auth:session_management')

    user_sessions = JWTUserSession.objects.filter(user=request.user).order_by('-created_at')

    # Current session
    current_session_id = request.session.get('jwt_session_id')

    context = {
        'user_sessions': user_sessions,
        'current_session_id': current_session_id,
    }
    return render(request, 'jwt_auth/session_management.html', context)


@login_required
def jwt_session_detail(request, session_id):
    """Detailed view of a specific JWT session"""
    try:
        session = JWTUserSession.objects.get(
            session_id=session_id,
            user=request.user
        )
    except JWTUserSession.DoesNotExist:
        messages.error(request, 'Session not found.')
        return redirect('jwt_auth:session_management')

    # Get login attempts for this session
    login_attempts = JWTLoginAttempt.objects.filter(
        username=request.user.username,
        timestamp__gte=session.created_at,
        ip_address=session.ip_address
    ).order_by('-timestamp')

    context = {
        'session': session,
        'login_attempts': login_attempts,
        'is_current': str(session.session_id) == request.session.get('jwt_session_id'),
    }
    return render(request, 'jwt_auth/session_detail.html', context)


# API Views
@api_view(['POST'])
@permission_classes([AllowAny])
def api_jwt_login(request):
    """API endpoint for JWT login"""
    serializer = CustomTokenObtainPairSerializer(
        data=request.data,
        context={'request': request}
    )

    try:
        serializer.is_valid(raise_exception=True)
        tokens = serializer.validated_data

        return Response({
            'access_token': tokens['access'],
            'refresh_token': tokens['refresh'],
            'session_id': tokens['session_id'],
            'token_type': 'Bearer',
            'expires_in': settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
            'message': 'Login successful'
        }, status=status.HTTP_200_OK)

    except TokenError as e:
        return Response({
            'error': str(e),
            'code': 'authentication_failed'
        }, status=status.HTTP_401_UNAUTHORIZED)
    except Exception as e:
        return Response({
            'error': 'Login failed',
            'detail': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_jwt_logout(request):
    """API endpoint for JWT logout with token blacklisting"""
    try:
        # Get token from request
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            return Response({
                'error': 'No valid token provided'
            }, status=status.HTTP_400_BAD_REQUEST)

        token = auth_header.split(' ')[1]

        # Decode token to get claims
        try:
            decoded = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )
            jti = decoded.get('jti')
            session_id = decoded.get('session_id')

            # Blacklist the access token
            if jti:
                JWTBlacklist.objects.create(
                    jti=jti,
                    user=request.user,
                    token_type='access',
                    expires_at=timezone.now() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                    reason='logout',
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )

            # Terminate session if session_id is provided
            if session_id:
                try:
                    session = JWTUserSession.objects.get(session_id=session_id)
                    session.terminate(reason='logout')
                except JWTUserSession.DoesNotExist:
                    pass

            return Response({
                'message': 'Logout successful'
            })

        except jwt.DecodeError:
            return Response({
                'error': 'Invalid token'
            }, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({
            'error': 'Logout failed',
            'detail': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_jwt_user_profile(request):
    """API endpoint to get user profile (requires JWT authentication)"""
    user = request.user

    # Get current session info
    session_info = None
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            session_id = decoded.get('session_id')
            if session_id:
                try:
                    session = JWTUserSession.objects.get(session_id=session_id)
                    session_info = {
                        'session_id': str(session.session_id),
                        'created_at': session.created_at,
                        'last_activity': session.last_activity,
                        'expires_at': session.expires_at,
                        'ip_address': session.ip_address,
                        'device_info': session.device_info,
                    }
                except JWTUserSession.DoesNotExist:
                    pass
        except jwt.DecodeError:
            pass

    return Response({
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'date_joined': user.date_joined,
        'session_info': session_info,
        'active_sessions': JWTUserSession.objects.filter(
            user=user,
            is_active=True
        ).count(),
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def api_jwt_sessions(request):
    """API endpoint to get user's JWT sessions"""
    sessions = JWTUserSession.objects.filter(user=request.user).order_by('-created_at')

    session_data = []
    for session in sessions:
        session_data.append({
            'session_id': str(session.session_id),
            'created_at': session.created_at,
            'last_activity': session.last_activity,
            'expires_at': session.expires_at,
            'ip_address': session.ip_address,
            'device_info': session.device_info,
            'is_active': session.is_active,
            'is_expired': session.is_expired(),
        })

    return Response({
        'sessions': session_data,
        'total_count': len(session_data),
        'active_count': sum(1 for s in session_data if s['is_active']),
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_jwt_terminate_session(request):
    """API endpoint to terminate a specific JWT session"""
    session_id = request.data.get('session_id')

    if not session_id:
        return Response({
            'error': 'session_id is required'
        }, status=status.HTTP_400_BAD_REQUEST)

    try:
        session = JWTUserSession.objects.get(
            session_id=session_id,
            user=request.user
        )
        session.terminate(reason='api_request')

        return Response({
            'message': 'Session terminated successfully',
            'session_id': session_id
        })

    except JWTUserSession.DoesNotExist:
        return Response({
            'error': 'Session not found'
        }, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def api_jwt_terminate_all_sessions(request):
    """API endpoint to terminate all user's JWT sessions"""
    active_sessions = JWTUserSession.objects.filter(
        user=request.user,
        is_active=True
    )

    count = 0
    for session in active_sessions:
        session.terminate(reason='api_request')
        count += 1

    return Response({
        'message': f'Terminated {count} active sessions',
        'terminated_count': count
    })


# Status and utility views
def jwt_auth_status(request):
    """API endpoint to check JWT authentication status"""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    has_jwt = auth_header.startswith('Bearer ')

    jwt_info = None
    session_info = None

    if has_jwt:
        token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else ''
        try:
            # Decode without verification to get claims
            decoded = jwt.decode(token, options={"verify_signature": False})
            jwt_info = {
                'jti': decoded.get('jti'),
                'exp': decoded.get('exp'),
                'iat': decoded.get('iat'),
                'user_id': decoded.get('user_id'),
                'session_id': decoded.get('session_id'),
                'is_blacklisted': JWTBlacklist.is_blacklisted(decoded.get('jti', ''))
            }

            # Get session info
            session_id = decoded.get('session_id')
            if session_id:
                try:
                    session = JWTUserSession.objects.get(session_id=session_id)
                    session_info = {
                        'session_id': str(session.session_id),
                        'is_active': session.is_active,
                        'expires_at': session.expires_at.isoformat(),
                        'ip_address': session.ip_address,
                    }
                except JWTUserSession.DoesNotExist:
                    pass

        except jwt.DecodeError:
            jwt_info = {'error': 'Invalid token format'}

    return JsonResponse({
        'authenticated': request.user.is_authenticated,
        'username': request.user.username if request.user.is_authenticated else None,
        'user_id': request.user.id if request.user.is_authenticated else None,
        'has_jwt_header': has_jwt,
        'jwt_info': jwt_info,
        'session_info': session_info,
        'session_authenticated': request.user.is_authenticated,
    })


# Utility functions
def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# Cleanup task (can be called by management command or celery)
def cleanup_expired_tokens():
    """Clean up expired JWT sessions and blacklist entries"""
    sessions_cleaned = JWTUserSession.cleanup_expired()
    blacklist_cleaned = JWTBlacklist.cleanup_expired()

    return {
        'sessions_cleaned': sessions_cleaned,
        'blacklist_cleaned': blacklist_cleaned
    }
