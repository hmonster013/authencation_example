from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.socialaccount.models import SocialLogin
from django.contrib import messages
from django.shortcuts import redirect
import logging

logger = logging.getLogger(__name__)


class DebugSocialAccountAdapter(DefaultSocialAccountAdapter):
    """
    Custom adapter to debug OAuth login issues
    """
    
    def pre_social_login(self, request, sociallogin):
        """
        Called before social login
        """
        logger.info(f"Pre-social login: {sociallogin.account.provider} - {sociallogin.account.uid}")
        super().pre_social_login(request, sociallogin)
    
    def save_user(self, request, sociallogin, form=None):
        """
        Called when saving user
        """
        try:
            logger.info(f"Saving user: {sociallogin.account.provider} - {sociallogin.account.extra_data}")
            user = super().save_user(request, sociallogin, form)
            logger.info(f"User saved successfully: {user.username}")
            return user
        except Exception as e:
            logger.error(f"Error saving user: {str(e)}")
            raise
    
    def authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        """
        Called when authentication error occurs
        """
        logger.error(f"OAuth authentication error for {provider_id}: {error}")
        if exception:
            logger.error(f"Exception: {str(exception)}")
        if extra_context:
            logger.error(f"Extra context: {extra_context}")
        
        # Add detailed error message
        if error:
            messages.error(request, f"OAuth Error ({provider_id}): {error}")
        elif exception:
            messages.error(request, f"OAuth Exception ({provider_id}): {str(exception)}")
        else:
            messages.error(request, f"Unknown OAuth error for {provider_id}")
        
        # Redirect to OAuth home with error details
        return redirect('oauth_auth:home')
    
    def is_auto_signup_allowed(self, request, sociallogin):
        """
        Check if auto signup is allowed
        """
        allowed = super().is_auto_signup_allowed(request, sociallogin)
        logger.info(f"Auto signup allowed for {sociallogin.account.provider}: {allowed}")
        return allowed
    
    def populate_user(self, request, sociallogin, data):
        """
        Populate user data from social login
        """
        try:
            logger.info(f"Populating user data: {data}")
            user = super().populate_user(request, sociallogin, data)
            logger.info(f"User populated: {user.username} - {user.email}")
            return user
        except Exception as e:
            logger.error(f"Error populating user: {str(e)}")
            raise
