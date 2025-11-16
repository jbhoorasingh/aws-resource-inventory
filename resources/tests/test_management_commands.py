"""
Tests for management commands
"""
from django.test import TestCase
from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from io import StringIO
from resources.models import UserProfile


class AssignPollPermissionCommandTest(TestCase):
    """Test assign_poll_permission management command"""

    def setUp(self):
        self.user1 = User.objects.create_user(
            username='user1',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            password='testpass123'
        )
        self.user3 = User.objects.create_user(
            username='user3',
            password='testpass123'
        )

        # Get the permission
        content_type = ContentType.objects.get_for_model(UserProfile)
        self.permission = Permission.objects.get(
            codename='can_poll_accounts',
            content_type=content_type
        )

    def test_grant_permission_to_single_user(self):
        """Test granting permission to a single user"""
        out = StringIO()
        call_command('assign_poll_permission', 'user1', stdout=out)

        self.user1.refresh_from_db()
        self.assertTrue(self.user1.has_perm('resources.can_poll_accounts'))
        self.assertIn('user1', out.getvalue())
        self.assertIn('Granted', out.getvalue())

    def test_grant_permission_to_multiple_users(self):
        """Test granting permission to multiple users"""
        out = StringIO()
        call_command('assign_poll_permission', 'user1', 'user2', stdout=out)

        self.user1.refresh_from_db()
        self.user2.refresh_from_db()

        self.assertTrue(self.user1.has_perm('resources.can_poll_accounts'))
        self.assertTrue(self.user2.has_perm('resources.can_poll_accounts'))
        self.assertIn('user1', out.getvalue())
        self.assertIn('user2', out.getvalue())

    def test_remove_permission_from_user(self):
        """Test removing permission from a user"""
        # First grant permission
        self.user1.user_permissions.add(self.permission)
        self.assertTrue(self.user1.has_perm('resources.can_poll_accounts'))

        # Then remove it
        out = StringIO()
        call_command('assign_poll_permission', 'user1', '--remove', stdout=out)

        # Get fresh instance to avoid permission cache
        fresh_user = User.objects.get(pk=self.user1.pk)
        self.assertFalse(fresh_user.has_perm('resources.can_poll_accounts'))
        self.assertIn('Removed', out.getvalue())

    def test_remove_permission_from_multiple_users(self):
        """Test removing permission from multiple users"""
        # Grant permission to both users
        self.user1.user_permissions.add(self.permission)
        self.user2.user_permissions.add(self.permission)

        # Remove from both
        out = StringIO()
        call_command('assign_poll_permission', 'user1', 'user2', '--remove', stdout=out)

        self.user1.refresh_from_db()
        self.user2.refresh_from_db()

        self.assertFalse(self.user1.has_perm('resources.can_poll_accounts'))
        self.assertFalse(self.user2.has_perm('resources.can_poll_accounts'))

    def test_nonexistent_user_shows_error(self):
        """Test that command handles nonexistent users gracefully"""
        out = StringIO()
        call_command('assign_poll_permission', 'nonexistent_user', stdout=out)

        output = out.getvalue()
        self.assertIn('not found', output)
        self.assertIn('nonexistent_user', output)

    def test_mixed_existing_and_nonexistent_users(self):
        """Test command with mix of existing and nonexistent users"""
        out = StringIO()
        call_command('assign_poll_permission', 'user1', 'nonexistent', 'user2', stdout=out)

        output = out.getvalue()

        # Should grant to existing users
        self.user1.refresh_from_db()
        self.user2.refresh_from_db()
        self.assertTrue(self.user1.has_perm('resources.can_poll_accounts'))
        self.assertTrue(self.user2.has_perm('resources.can_poll_accounts'))

        # Should show error for nonexistent user
        self.assertIn('not found', output)
        self.assertIn('nonexistent', output)

    def test_granting_permission_is_idempotent(self):
        """Test that granting permission multiple times doesn't cause errors"""
        # Grant twice
        call_command('assign_poll_permission', 'user1', stdout=StringIO())
        out = StringIO()
        call_command('assign_poll_permission', 'user1', stdout=out)

        # Should still have permission and not error
        self.user1.refresh_from_db()
        self.assertTrue(self.user1.has_perm('resources.can_poll_accounts'))
        self.assertIn('Granted', out.getvalue())

    def test_removing_nonexistent_permission_doesnt_error(self):
        """Test that removing permission from user without it doesn't error"""
        # User doesn't have permission, try to remove it
        out = StringIO()
        call_command('assign_poll_permission', 'user1', '--remove', stdout=out)

        # Should complete without error
        self.assertIn('Removed', out.getvalue())

    def test_command_output_formatting(self):
        """Test that command output is properly formatted"""
        out = StringIO()
        call_command('assign_poll_permission', 'user1', 'user2', stdout=out)

        output = out.getvalue()

        # Should have check marks or success indicators
        self.assertTrue('✓' in output or 'success' in output.lower())
        # Should show "Done!" at the end
        self.assertIn('Done!', output)


class CommandSignalIntegrationTest(TestCase):
    """Test that commands work correctly with model signals"""

    def test_permission_granted_to_new_user(self):
        """Test granting permission to a newly created user"""
        # Create user
        new_user = User.objects.create_user(
            username='newuser',
            password='testpass123'
        )

        # User should have profile and DRF token automatically
        self.assertTrue(hasattr(new_user, 'profile'))
        self.assertTrue(new_user.profile.api_token)

        # Grant poll permission
        call_command('assign_poll_permission', 'newuser', stdout=StringIO())

        new_user.refresh_from_db()
        self.assertTrue(new_user.has_perm('resources.can_poll_accounts'))

    def test_superuser_doesnt_need_explicit_permission(self):
        """Test that superusers have permission without explicit grant"""
        superuser = User.objects.create_superuser(
            username='admin',
            password='testpass123'
        )

        # Superuser should have permission without explicit grant
        self.assertTrue(superuser.has_perm('resources.can_poll_accounts'))
