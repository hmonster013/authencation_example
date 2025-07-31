from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_logged_out
from allauth.socialaccount.signals import pre_social_login, social_account_added
from allauth.account.signals import user_signed_up
from .models import OAuthUserProfile, OAuthLoginSession, OAuthSecurityLog
from .views import get_client_ip, create_oauth_session


@receiver(pre_social_login)
def handle_pre_social_login(sender, request, sociallogin, **kwargs):
    """Handle pre-social login to check for existing accounts"""
    # Check if user already exists with this email
    if sociallogin.user.email:
        try:
            from django.contrib.auth.models import User
            existing_user = User.objects.get(email=sociallogin.user.email)
            if not sociallogin.is_existing:
                # Connect the social account to existing user
                sociallogin.connect(request, existing_user)
                
                # Log security event
                OAuthSecurityLog.log_event(
                    event_type='account_connected',
                    provider=sociallogin.account.provider,
                    ip_address=get_client_ip(request),
                    user=existing_user,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    event_data={
                        'email': sociallogin.user.email,
                        'auto_connected': True
                    }
                )
        except User.DoesNotExist:
            pass


@receiver(social_account_added)
def handle_social_account_added(sender, request, sociallogin, **kwargs):
    """Handle when a social account is added to existing user"""
    provider = sociallogin.account.provider
    user = sociallogin.user
    
    # Log security event
    OAuthSecurityLog.log_event(
        event_type='account_connected',
        provider=provider,
        ip_address=get_client_ip(request),
        user=user,
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        event_data={
            'provider_uid': sociallogin.account.uid,
            'manual_connection': True
        }
    )


@receiver(user_signed_up)
def handle_user_signed_up(sender, request, user, **kwargs):
    """Handle when user signs up via OAuth"""
    # Check if this is an OAuth signup
    if hasattr(request, 'sociallogin'):
        sociallogin = request.sociallogin
        provider = sociallogin.account.provider
        
        # Create OAuth profile
        oauth_profile = OAuthUserProfile.objects.create(
            user=user,
            preferred_provider=provider,
            profile_completed=True,
            profile_completion_date=timezone.now()
        )
        
        # Create OAuth session
        create_oauth_session(
            user=user,
            provider=provider,
            provider_uid=sociallogin.account.uid,
            request=request,
            login_method='oauth_new'
        )


@receiver(user_logged_in)
def handle_oauth_login(sender, request, user, **kwargs):
    """Handle OAuth login to create session tracking"""
    # Check if this is an OAuth login
    if hasattr(request, 'sociallogin'):
        sociallogin = request.sociallogin
        provider = sociallogin.account.provider
        provider_uid = sociallogin.account.uid
        
        # Create OAuth session
        session = create_oauth_session(
            user=user,
            provider=provider,
            provider_uid=provider_uid,
            request=request,
            login_method='oauth_existing'
        )
        
        # Store session ID in Django session
        request.session['oauth_session_id'] = str(session.session_id)
        
        # Update OAuth profile
        oauth_profile, created = OAuthUserProfile.objects.get_or_create(user=user)
        if not oauth_profile.preferred_provider:
            oauth_profile.preferred_provider = provider
            oauth_profile.save()


@receiver(user_logged_out)
def handle_oauth_logout(sender, request, user, **kwargs):
    """Handle OAuth logout to end sessions"""
    if user and user.is_authenticated:
        # End OAuth session if exists
        oauth_session_id = request.session.get('oauth_session_id')
        if oauth_session_id:
            try:
                session = OAuthLoginSession.objects.get(session_id=oauth_session_id)
                session.end_session()
                
                # Log security event
                OAuthSecurityLog.log_event(
                    event_type='login_success',  # Track as session end
                    provider=session.provider,
                    ip_address=get_client_ip(request),
                    user=user,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    session_id=session.session_id,
                    event_data={'action': 'logout'}
                )
            except OAuthLoginSession.DoesNotExist:
                pass
