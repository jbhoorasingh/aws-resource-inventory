"""
Management command to assign can_poll_accounts permission to users
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType
from resources.models import UserProfile


class Command(BaseCommand):
    help = 'Assign can_poll_accounts permission to users'

    def add_arguments(self, parser):
        parser.add_argument(
            'usernames',
            nargs='+',
            type=str,
            help='Username(s) to grant can_poll_accounts permission'
        )
        parser.add_argument(
            '--remove',
            action='store_true',
            help='Remove the permission instead of granting it'
        )

    def handle(self, *args, **options):
        usernames = options['usernames']
        remove = options.get('remove', False)

        # Get the can_poll_accounts permission
        try:
            content_type = ContentType.objects.get_for_model(UserProfile)
            permission = Permission.objects.get(
                codename='can_poll_accounts',
                content_type=content_type
            )
        except Permission.DoesNotExist:
            self.stdout.write(
                self.style.ERROR('Permission "can_poll_accounts" not found. Run migrations first.')
            )
            return

        # Process each username
        for username in usernames:
            try:
                user = User.objects.get(username=username)

                if remove:
                    # Remove permission
                    user.user_permissions.remove(permission)
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'✓ Removed can_poll_accounts permission from user "{username}"'
                        )
                    )
                else:
                    # Add permission
                    user.user_permissions.add(permission)
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'✓ Granted can_poll_accounts permission to user "{username}"'
                        )
                    )

            except User.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'✗ User "{username}" not found')
                )

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('Done!'))
