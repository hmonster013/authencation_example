from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse
from authencation_example.auth_utils import safe_login


def basic_auth_home(request):
    """Home page for basic authentication demo"""
    return render(request, 'basic_auth/home.html')


@csrf_protect
def basic_login(request):
    """Basic login view using Django's built-in authentication"""
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('basic_auth:dashboard')
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = AuthenticationForm()

    return render(request, 'basic_auth/login.html', {'form': form})


@csrf_protect
def basic_register(request):
    """Basic registration view"""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}!')
            safe_login(request, user)
            return redirect('basic_auth:dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserCreationForm()

    return render(request, 'basic_auth/register.html', {'form': form})


def basic_logout(request):
    """Basic logout view"""
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('basic_auth:home')


@login_required
def basic_dashboard(request):
    """Protected dashboard view"""
    return render(request, 'basic_auth/dashboard.html')


@login_required
def basic_profile(request):
    """User profile view"""
    return render(request, 'basic_auth/profile.html')


# API endpoint for checking authentication status
def auth_status(request):
    """API endpoint to check if user is authenticated"""
    return JsonResponse({
        'authenticated': request.user.is_authenticated,
        'username': request.user.username if request.user.is_authenticated else None,
        'user_id': request.user.id if request.user.is_authenticated else None,
    })
