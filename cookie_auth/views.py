from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone
from datetime import datetime, timedelta
import hashlib
import uuid
from authencation_example.auth_utils import safe_login


def cookie_auth_home(request):
    """Home page for cookie authentication demo"""
    return render(request, 'cookie_auth/home.html')


@csrf_protect
def cookie_login(request):
    """Cookie-based login with advanced cookie settings"""
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        remember_me = request.POST.get('remember_me', False)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)

                # Create response with redirect
                response = redirect('cookie_auth:dashboard')

                # Set custom authentication cookie
                auth_token = generate_auth_token(user)

                if remember_me:
                    # Long-term cookie (30 days)
                    max_age = 30 * 24 * 60 * 60  # 30 days in seconds
                    expires = timezone.now() + timedelta(days=30)
                    request.session.set_expiry(max_age)
                else:
                    # Session cookie (browser session)
                    max_age = None
                    expires = None
                    request.session.set_expiry(0)

                # Set secure authentication cookie
                response.set_cookie(
                    'auth_token',
                    auth_token,
                    max_age=max_age,
                    expires=expires,
                    secure=request.is_secure(),  # HTTPS only in production
                    httponly=True,  # Prevent XSS
                    samesite='Lax'  # CSRF protection
                )

                # Set user preference cookie
                response.set_cookie(
                    'user_prefs',
                    f'username:{username}|login_time:{timezone.now().isoformat()}',
                    max_age=max_age,
                    secure=request.is_secure(),
                    samesite='Lax'
                )

                messages.success(request, f'Welcome back, {username}! Cookie authentication successful.')
                return response
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()

    return render(request, 'cookie_auth/login.html', {'form': form})


@csrf_protect
def cookie_register(request):
    """Cookie-based registration with automatic login"""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')

            # Auto login after registration
            safe_login(request, user)

            # Create response with redirect
            response = redirect('cookie_auth:dashboard')

            # Set authentication cookie for new user
            auth_token = generate_auth_token(user)
            response.set_cookie(
                'auth_token',
                auth_token,
                max_age=24 * 60 * 60,  # 24 hours for new users
                secure=request.is_secure(),
                httponly=True,
                samesite='Lax'
            )

            # Set welcome cookie
            response.set_cookie(
                'user_prefs',
                f'username:{username}|registered:{timezone.now().isoformat()}|new_user:true',
                max_age=24 * 60 * 60,
                secure=request.is_secure(),
                samesite='Lax'
            )

            messages.success(request, f'Account created for {username}! Welcome to cookie authentication.')
            return response
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserCreationForm()

    return render(request, 'cookie_auth/register.html', {'form': form})


def cookie_logout(request):
    """Cookie-based logout with proper cookie cleanup"""
    username = request.user.username if request.user.is_authenticated else 'User'

    # Django logout
    logout(request)

    # Create response
    response = redirect('cookie_auth:home')

    # Clear custom cookies
    response.delete_cookie('auth_token')
    response.delete_cookie('user_prefs')

    # Set logout confirmation cookie (temporary)
    response.set_cookie(
        'logout_confirmation',
        f'logged_out:{timezone.now().isoformat()}',
        max_age=60,  # 1 minute
        secure=request.is_secure(),
        samesite='Lax'
    )

    messages.success(request, f'Goodbye {username}! All cookies have been cleared.')
    return response


@login_required
def cookie_dashboard(request):
    """Protected dashboard with cookie information"""
    # Get cookie information
    auth_token = request.COOKIES.get('auth_token', 'Not set')
    user_prefs = request.COOKIES.get('user_prefs', 'Not set')
    session_key = request.session.session_key

    # Parse user preferences
    prefs_data = parse_user_prefs(user_prefs)

    context = {
        'auth_token': auth_token[:20] + '...' if len(auth_token) > 20 else auth_token,
        'user_prefs': prefs_data,
        'session_key': session_key,
        'session_expiry': request.session.get_expiry_date(),
        'all_cookies': dict(request.COOKIES),
    }

    return render(request, 'cookie_auth/dashboard.html', context)


@login_required
def cookie_profile(request):
    """User profile with cookie management"""
    context = {
        'cookies_count': len(request.COOKIES),
        'session_data': dict(request.session),
        'user_agent': request.META.get('HTTP_USER_AGENT', 'Unknown'),
    }
    return render(request, 'cookie_auth/profile.html', context)


def cookie_auth_status(request):
    """API endpoint to check cookie authentication status"""
    auth_token = request.COOKIES.get('auth_token')
    user_prefs = request.COOKIES.get('user_prefs')
    logout_confirmation = request.COOKIES.get('logout_confirmation')

    return JsonResponse({
        'authenticated': request.user.is_authenticated,
        'username': request.user.username if request.user.is_authenticated else None,
        'user_id': request.user.id if request.user.is_authenticated else None,
        'has_auth_token': bool(auth_token),
        'has_user_prefs': bool(user_prefs),
        'recently_logged_out': bool(logout_confirmation),
        'session_key': request.session.session_key,
        'cookies_count': len(request.COOKIES),
    })


def cookie_settings(request):
    """Cookie settings and management page"""
    if request.method == 'POST':
        action = request.POST.get('action')
        response = redirect('cookie_auth:cookie_settings')

        if action == 'clear_all':
            # Clear all custom cookies
            for cookie_name in ['auth_token', 'user_prefs', 'logout_confirmation']:
                response.delete_cookie(cookie_name)
            messages.success(request, 'All custom cookies cleared!')

        elif action == 'set_preference':
            theme = request.POST.get('theme', 'light')
            language = request.POST.get('language', 'en')
            response.set_cookie(
                'user_preferences',
                f'theme:{theme}|language:{language}|updated:{timezone.now().isoformat()}',
                max_age=365 * 24 * 60 * 60,  # 1 year
                secure=request.is_secure(),
                samesite='Lax'
            )
            messages.success(request, 'Preferences saved in cookie!')

        return response

    # Get current preferences
    prefs_cookie = request.COOKIES.get('user_preferences', '')
    current_prefs = parse_user_prefs(prefs_cookie)

    context = {
        'all_cookies': dict(request.COOKIES),
        'current_prefs': current_prefs,
    }
    return render(request, 'cookie_auth/settings.html', context)


# Helper functions
def generate_auth_token(user):
    """Generate a secure authentication token"""
    timestamp = str(timezone.now().timestamp())
    user_id = str(user.id)
    random_string = str(uuid.uuid4())

    # Create hash
    token_string = f"{user_id}:{timestamp}:{random_string}"
    return hashlib.sha256(token_string.encode()).hexdigest()


def parse_user_prefs(prefs_string):
    """Parse user preferences from cookie string"""
    if not prefs_string or prefs_string == 'Not set':
        return {}

    prefs = {}
    try:
        pairs = prefs_string.split('|')
        for pair in pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                prefs[key] = value
    except Exception:
        pass

    return prefs
