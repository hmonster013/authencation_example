from django.core.management.base import BaseCommand
from django.contrib.sites.models import Site
from allauth.socialaccount.models import SocialApp
from django.conf import settings


class Command(BaseCommand):
    help = 'Setup OAuth providers (Google, GitHub) in Django admin'

    def add_arguments(self, parser):
        parser.add_argument(
            '--google-client-id',
            type=str,
            help='Google OAuth Client ID'
        )
        parser.add_argument(
            '--google-client-secret',
            type=str,
            help='Google OAuth Client Secret'
        )
        parser.add_argument(
            '--github-client-id',
            type=str,
            help='GitHub OAuth Client ID'
        )
        parser.add_argument(
            '--github-client-secret',
            type=str,
            help='GitHub OAuth Client Secret'
        )
        parser.add_argument(
            '--update',
            action='store_true',
            help='Update existing providers if they exist'
        )

    def handle(self, *args, **options):
        # Use environment variables if command line options not provided
        google_client_id = options['google_client_id'] or getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '')
        google_client_secret = options['google_client_secret'] or getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', '')
        github_client_id = options['github_client_id'] or getattr(settings, 'GITHUB_OAUTH_CLIENT_ID', '')
        github_client_secret = options['github_client_secret'] or getattr(settings, 'GITHUB_OAUTH_CLIENT_SECRET', '')

        # Get the default site
        try:
            site = Site.objects.get(pk=settings.SITE_ID)
        except Site.DoesNotExist:
            domain = getattr(settings, 'DOMAIN', 'localhost:8000')
            site = Site.objects.create(
                pk=settings.SITE_ID,
                domain=domain,
                name='Development Site'
            )
            self.stdout.write(
                self.style.SUCCESS(f'Created site: {site.domain}')
            )

        # Setup Google OAuth
        if google_client_id and google_client_secret:
            google_app, created = SocialApp.objects.get_or_create(
                provider='google',
                defaults={
                    'name': 'Google OAuth',
                    'client_id': google_client_id,
                    'secret': google_client_secret,
                }
            )
            
            if not created and options['update']:
                google_app.client_id = google_client_id
                google_app.secret = google_client_secret
                google_app.save()
                self.stdout.write(
                    self.style.SUCCESS('Updated Google OAuth app')
                )
            elif created:
                self.stdout.write(
                    self.style.SUCCESS('Created Google OAuth app')
                )
            else:
                self.stdout.write(
                    self.style.WARNING('Google OAuth app already exists (use --update to update)')
                )
            
            # Add site to the app
            google_app.sites.add(site)

        # Setup GitHub OAuth
        if github_client_id and github_client_secret:
            github_app, created = SocialApp.objects.get_or_create(
                provider='github',
                defaults={
                    'name': 'GitHub OAuth',
                    'client_id': github_client_id,
                    'secret': github_client_secret,
                }
            )
            
            if not created and options['update']:
                github_app.client_id = github_client_id
                github_app.secret = github_client_secret
                github_app.save()
                self.stdout.write(
                    self.style.SUCCESS('Updated GitHub OAuth app')
                )
            elif created:
                self.stdout.write(
                    self.style.SUCCESS('Created GitHub OAuth app')
                )
            else:
                self.stdout.write(
                    self.style.WARNING('GitHub OAuth app already exists (use --update to update)')
                )
            
            # Add site to the app
            github_app.sites.add(site)

        # Show current providers
        self.stdout.write('\n' + self.style.SUCCESS('Current OAuth providers:'))
        providers = SocialApp.objects.all()
        if providers:
            for provider in providers:
                sites = ', '.join([s.domain for s in provider.sites.all()])
                self.stdout.write(f'  • {provider.provider}: {provider.name} (Sites: {sites})')
        else:
            self.stdout.write('  No OAuth providers configured')

        # Show setup instructions
        if not google_client_id or not google_client_secret:
            self.stdout.write('\n' + self.style.WARNING('Google OAuth Setup Instructions:'))
            self.stdout.write('1. Go to https://console.cloud.google.com/')
            self.stdout.write('2. Create a new project or select existing one')
            self.stdout.write('3. Enable Google+ API or Google Identity API')
            self.stdout.write('4. Create OAuth 2.0 credentials')
            self.stdout.write('5. Add authorized redirect URI: http://localhost:8000/accounts/google/login/callback/')
            self.stdout.write('6. Run: python manage.py setup_oauth_providers --google-client-id YOUR_ID --google-client-secret YOUR_SECRET')

        if not github_client_id or not github_client_secret:
            self.stdout.write('\n' + self.style.WARNING('GitHub OAuth Setup Instructions:'))
            self.stdout.write('1. Go to https://github.com/settings/developers')
            self.stdout.write('2. Create a new OAuth App')
            self.stdout.write('3. Set Authorization callback URL: http://localhost:8000/accounts/github/login/callback/')
            self.stdout.write('4. Run: python manage.py setup_oauth_providers --github-client-id YOUR_ID --github-client-secret YOUR_SECRET')
