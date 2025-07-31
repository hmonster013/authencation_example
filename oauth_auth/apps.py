from django.apps import AppConfig


class OauthAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "oauth_auth"

    def ready(self):
        import oauth_auth.signals
