"""
Common authentication utilities for the Django authentication example project.
"""

from django.contrib.auth import login as django_login
from django.conf import settings


def safe_login(request, user, backend=None):
    """
    Safely login a user with proper backend handling.
    
    This function handles the case where multiple authentication backends
    are configured and ensures the correct backend is used for login.
    
    Args:
        request: The HTTP request object
        user: The user object to login
        backend: Optional backend to use. If not provided, uses ModelBackend
    
    Returns:
        None
    """
    if backend is None:
        # Use Django's default ModelBackend for standard username/password auth
        backend = 'django.contrib.auth.backends.ModelBackend'
    
    # Check if user already has a backend attribute (from authenticate())
    if hasattr(user, 'backend'):
        # User was authenticated via authenticate(), use that backend
        django_login(request, user)
    else:
        # User was created directly (e.g., registration), specify backend
        django_login(request, user, backend=backend)


def get_available_backends():
    """
    Get list of available authentication backends.
    
    Returns:
        list: List of configured authentication backend classes
    """
    return getattr(settings, 'AUTHENTICATION_BACKENDS', [
        'django.contrib.auth.backends.ModelBackend'
    ])


def is_allauth_enabled():
    """
    Check if django-allauth is enabled in the project.
    
    Returns:
        bool: True if allauth is configured, False otherwise
    """
    backends = get_available_backends()
    allauth_backends = [
        'allauth.account.auth_backends.AuthenticationBackend',
    ]
    return any(backend in backends for backend in allauth_backends)


def get_primary_backend():
    """
    Get the primary authentication backend for the project.
    
    Returns:
        str: The primary backend class path
    """
    backends = get_available_backends()
    
    # Prefer ModelBackend for standard auth
    model_backend = 'django.contrib.auth.backends.ModelBackend'
    if model_backend in backends:
        return model_backend
    
    # Fall back to first available backend
    return backends[0] if backends else model_backend


def format_backend_name(backend_path):
    """
    Format backend class path to human-readable name.
    
    Args:
        backend_path (str): Full backend class path
        
    Returns:
        str: Human-readable backend name
    """
    backend_names = {
        'django.contrib.auth.backends.ModelBackend': 'Django Model Backend',
        'allauth.account.auth_backends.AuthenticationBackend': 'Django Allauth Backend',
    }
    
    return backend_names.get(backend_path, backend_path.split('.')[-1])
