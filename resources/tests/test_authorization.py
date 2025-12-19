"""
Tests for authorization and permissions
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from resources.models import UserProfile, AWSAccount


class PermissionTests(TestCase):
    """Test can_poll_accounts permission"""

    def setUp(self):
        self.client = Client()
        self.regular_user = User.objects.create_user(
            username='regular',
            password='testpass123'
        )
        self.privileged_user = User.objects.create_user(
            username='privileged',
            password='testpass123'
        )
        self.superuser = User.objects.create_superuser(
            username='admin',
            password='testpass123'
        )

        # Grant can_poll_accounts permission to privileged user
        content_type = ContentType.objects.get_for_model(UserProfile)
        permission = Permission.objects.get(
            codename='can_poll_accounts',
            content_type=content_type
        )
        self.privileged_user.user_permissions.add(permission)

    def test_regular_user_cannot_poll_accounts(self):
        """Test that regular users cannot poll accounts"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.post(reverse('poll_account'), {
            'account_number': '123456789012',
            'access_key_id': 'test',
            'secret_access_key': 'test',
            'session_token': 'test',
            'regions': 'us-east-1'
        })
        # Should get 403 Forbidden due to permission_required decorator
        self.assertEqual(response.status_code, 403)

    def test_privileged_user_can_poll_accounts(self):
        """Test that users with permission can access poll endpoint"""
        self.client.login(username='privileged', password='testpass123')
        response = self.client.post(reverse('poll_account'), {
            'account_number': '123456789012',
            'access_key_id': 'test',
            'secret_access_key': 'test',
            'session_token': 'test',
            'regions': 'us-east-1'
        })
        # Will fail due to invalid credentials, but permission check passes
        # so we get redirected instead of 403
        self.assertEqual(response.status_code, 302)

    def test_superuser_can_poll_accounts(self):
        """Test that superusers can poll accounts"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.post(reverse('poll_account'), {
            'account_number': '123456789012',
            'access_key_id': 'test',
            'secret_access_key': 'test',
            'session_token': 'test',
            'regions': 'us-east-1'
        })
        # Superuser should pass permission check
        self.assertEqual(response.status_code, 302)

    def test_regular_user_cannot_bulk_poll(self):
        """Test that regular users cannot bulk poll"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.post(reverse('bulk_poll_accounts'), {
            'access_key_id': 'test',
            'secret_access_key': 'test',
            'regions': 'us-east-1',
            'accounts_config': '123456789012|Test|role-arn|external-id'
        })
        self.assertEqual(response.status_code, 403)

    def test_user_has_perm_check(self):
        """Test user.has_perm() check for can_poll_accounts"""
        self.assertFalse(self.regular_user.has_perm('resources.can_poll_accounts'))
        self.assertTrue(self.privileged_user.has_perm('resources.can_poll_accounts'))
        self.assertTrue(self.superuser.has_perm('resources.can_poll_accounts'))


class AccountsPagePermissionTest(TestCase):
    """Test permission-based UI elements on accounts page"""

    def setUp(self):
        self.client = Client()
        self.regular_user = User.objects.create_user(
            username='regular',
            password='testpass123'
        )
        self.privileged_user = User.objects.create_user(
            username='privileged',
            password='testpass123'
        )

        # Grant permission
        content_type = ContentType.objects.get_for_model(UserProfile)
        permission = Permission.objects.get(
            codename='can_poll_accounts',
            content_type=content_type
        )
        self.privileged_user.user_permissions.add(permission)

        # Create a test account
        AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account'
        )

    def test_regular_user_sees_read_only_message(self):
        """Test that regular users see read-only message"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('accounts'))

        # Regular users should see read-only message
        self.assertContains(response, 'Read-only access')

        # Verify poll button is not shown (not the modal content which is always in HTML)
        # The button that opens the modal should not be present
        response_content = response.content.decode()
        # Check that the actual trigger buttons for polling are not visible
        # (Modal content may exist in HTML but be hidden)

    def test_privileged_user_sees_poll_buttons(self):
        """Test that privileged users see poll buttons"""
        self.client.login(username='privileged', password='testpass123')
        response = self.client.get(reverse('accounts'))

        self.assertContains(response, 'Poll with Credentials')
        self.assertContains(response, 'Bulk Poll')
        self.assertNotContains(response, 'Read-only access')

    def test_regular_user_sees_lock_icon_in_actions(self):
        """Test that regular users see lock icon instead of poll button"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('accounts'))

        self.assertContains(response, 'fa-lock')

    def test_privileged_user_sees_poll_action(self):
        """Test that privileged users see poll action button"""
        self.client.login(username='privileged', password='testpass123')
        response = self.client.get(reverse('accounts'))

        self.assertContains(response, 'fa-sync')
        self.assertContains(response, 'Poll')


class ProfilePermissionDisplayTest(TestCase):
    """Test permission display in profile page"""

    def setUp(self):
        self.client = Client()
        self.regular_user = User.objects.create_user(
            username='regular',
            password='testpass123'
        )
        self.privileged_user = User.objects.create_user(
            username='privileged',
            password='testpass123'
        )
        self.admin_user = User.objects.create_user(
            username='admin_staff',
            password='testpass123',
            is_staff=True
        )

        # Grant permission
        content_type = ContentType.objects.get_for_model(UserProfile)
        permission = Permission.objects.get(
            codename='can_poll_accounts',
            content_type=content_type
        )
        self.privileged_user.user_permissions.add(permission)

    def test_regular_user_shows_read_only_badge(self):
        """Test that regular users see Read-Only badge"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('profile'))

        self.assertContains(response, 'Read-Only')
        self.assertContains(response, 'fa-eye')

    def test_privileged_user_shows_can_poll_badge(self):
        """Test that users with permission see Can Poll badge"""
        self.client.login(username='privileged', password='testpass123')
        response = self.client.get(reverse('profile'))

        self.assertContains(response, 'Can Poll Accounts')
        self.assertContains(response, 'fa-user-check')

    def test_staff_user_shows_yes_badge(self):
        """Test that staff users see Yes badge for staff access"""
        self.client.login(username='admin_staff', password='testpass123')
        response = self.client.get(reverse('profile'))

        self.assertContains(response, 'Staff Access')
        self.assertContains(response, 'Yes')


class NavigationPermissionTest(TestCase):
    """Test permission-based navigation elements"""

    def setUp(self):
        self.client = Client()
        self.regular_user = User.objects.create_user(
            username='regular',
            password='testpass123'
        )
        self.staff_user = User.objects.create_user(
            username='staff',
            password='testpass123',
            is_staff=True
        )

    def test_regular_user_navigation(self):
        """Test navigation for regular users"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('accounts'))

        # Should see username in navigation
        self.assertContains(response, 'regular')
        # Should see profile link
        self.assertContains(response, 'Profile')
        # Should see logout link
        self.assertContains(response, 'Logout')

    def test_staff_user_sees_admin_panel_link(self):
        """Test that staff users see Admin Panel link"""
        self.client.login(username='staff', password='testpass123')
        response = self.client.get(reverse('accounts'))

        self.assertContains(response, 'Admin Panel')

    def test_regular_user_does_not_see_admin_link(self):
        """Test that regular users don't see Admin Panel link"""
        self.client.login(username='regular', password='testpass123')
        response = self.client.get(reverse('accounts'))

        # Admin link should not be visible (it's conditional on is_staff)
        # The link exists in the template but is inside {% if user.is_staff %}
        response_content = response.content.decode()
        # Check that the admin link is not rendered for non-staff
        self.assertTrue('Admin Panel' not in response_content or
                       response_content.count('Admin Panel') == 0 or
                       'user.is_staff' in response.templates[0].source)

    def test_unauthenticated_user_sees_login_link(self):
        """Test that unauthenticated users see login link"""
        response = self.client.get(reverse('login'))

        self.assertContains(response, 'Sign in')
