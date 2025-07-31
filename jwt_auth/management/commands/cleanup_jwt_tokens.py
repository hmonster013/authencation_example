from django.core.management.base import BaseCommand
from django.utils import timezone
from jwt_auth.models import JWTBlacklist, JWTUserSession, JWTLoginAttempt
from datetime import timedelta


class Command(BaseCommand):
    help = 'Clean up expired JWT tokens, sessions, and old login attempts'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Remove login attempts older than this many days (default: 30)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        days = options['days']
        
        self.stdout.write(
            self.style.SUCCESS(f'Starting JWT cleanup (dry-run: {dry_run})...')
        )

        # Clean up expired blacklist entries
        expired_blacklist = JWTBlacklist.objects.filter(
            expires_at__lte=timezone.now()
        )
        blacklist_count = expired_blacklist.count()
        
        if not dry_run:
            expired_blacklist.delete()
        
        self.stdout.write(
            f'Expired blacklist entries: {blacklist_count} {"(would be deleted)" if dry_run else "deleted"}'
        )

        # Clean up expired sessions
        expired_sessions = JWTUserSession.objects.filter(
            expires_at__lte=timezone.now(),
            is_active=True
        )
        sessions_count = expired_sessions.count()
        
        if not dry_run:
            for session in expired_sessions:
                session.terminate(reason='expired')
        
        self.stdout.write(
            f'Expired sessions: {sessions_count} {"(would be terminated)" if dry_run else "terminated"}'
        )

        # Clean up old login attempts
        cutoff_date = timezone.now() - timedelta(days=days)
        old_attempts = JWTLoginAttempt.objects.filter(
            timestamp__lt=cutoff_date
        )
        attempts_count = old_attempts.count()
        
        if not dry_run:
            old_attempts.delete()
        
        self.stdout.write(
            f'Old login attempts (>{days} days): {attempts_count} {"(would be deleted)" if dry_run else "deleted"}'
        )

        # Statistics
        if not dry_run:
            total_blacklist = JWTBlacklist.objects.count()
            total_sessions = JWTUserSession.objects.count()
            active_sessions = JWTUserSession.objects.filter(is_active=True).count()
            total_attempts = JWTLoginAttempt.objects.count()
            
            self.stdout.write('\n' + self.style.SUCCESS('Cleanup completed!'))
            self.stdout.write(f'Remaining blacklist entries: {total_blacklist}')
            self.stdout.write(f'Total sessions: {total_sessions} (active: {active_sessions})')
            self.stdout.write(f'Total login attempts: {total_attempts}')
        else:
            self.stdout.write('\n' + self.style.WARNING('Dry run completed - no changes made'))
            self.stdout.write('Run without --dry-run to perform actual cleanup')
