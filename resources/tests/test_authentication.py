"""
Tests for authentication views and functionality
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.authtoken.models import Token
from resources.models import UserProfile


class UserProfileModelTest(TestCase):
    """Test UserProfile model and signals"""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )

    def test_user_profile_created_on_user_creation(self):
        """Test that UserProfile is automatically created when User is created"""
        self.assertTrue(hasattr(self.user, 'profile'))
        self.assertIsInstance(self.user.profile, UserProfile)

    def test_api_token_generated_on_profile_creation(self):
        """Test that API token is automatically generated"""
        self.assertTrue(self.user.profile.api_token)
        self.assertEqual(len(self.user.profile.api_token), 64)

    def test_drf_token_created_on_user_creation(self):
        """Test that DRF auth token is automatically created"""
        token = Token.objects.filter(user=self.user).first()
        self.assertIsNotNone(token)
        self.assertEqual(token.user, self.user)

    def test_regenerate_token_creates_new_token(self):
        """Test token regeneration"""
        old_token = self.user.profile.api_token
        new_token = self.user.profile.regenerate_token()

        self.assertNotEqual(old_token, new_token)
        self.assertEqual(self.user.profile.api_token, new_token)
        self.assertEqual(len(new_token), 64)

    def test_can_poll_accounts_permission_exists(self):
        """Test that can_poll_accounts permission exists"""
        from django.contrib.contenttypes.models import ContentType
        from django.contrib.auth.models import Permission

        content_type = ContentType.objects.get_for_model(UserProfile)
        permission = Permission.objects.filter(
            codename='can_poll_accounts',
            content_type=content_type
        ).first()

        self.assertIsNotNone(permission)
        self.assertEqual(permission.name, 'Can poll AWS accounts for resource discovery')


class LoginViewTest(TestCase):
    """Test login functionality"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.login_url = reverse('login')

    def test_login_page_loads(self):
        """Test that login page loads successfully"""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/login.html')

    def test_login_with_valid_credentials(self):
        """Test login with valid credentials"""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'testpass123'
        })
        self.assertRedirects(response, reverse('accounts'))
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_login_with_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = self.client.post(self.login_url, {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.wsgi_request.user.is_authenticated)
        self.assertContains(response, 'Invalid username or password')

    def test_login_redirect_when_already_authenticated(self):
        """Test that authenticated users are redirected from login page"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.login_url)
        self.assertRedirects(response, reverse('accounts'))

    def test_login_with_next_parameter(self):
        """Test login redirect to next parameter"""
        response = self.client.post(self.login_url + '?next=/enis/', {
            'username': 'testuser',
            'password': 'testpass123'
        })
        self.assertRedirects(response, '/enis/')


class LogoutViewTest(TestCase):
    """Test logout functionality"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.logout_url = reverse('logout')

    def test_logout_redirects_to_login(self):
        """Test that logout redirects to login page"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.logout_url)
        self.assertRedirects(response, reverse('login'))

    def test_user_is_logged_out(self):
        """Test that user session is cleared after logout"""
        self.client.login(username='testuser', password='testpass123')
        self.client.get(self.logout_url)

        # Check that user is not authenticated in next request
        response = self.client.get(reverse('accounts'))
        self.assertRedirects(response, '/login/?next=/accounts/')


class ProfileViewTest(TestCase):
    """Test user profile view"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        self.profile_url = reverse('profile')

    def test_profile_requires_login(self):
        """Test that profile view requires authentication"""
        response = self.client.get(self.profile_url)
        self.assertRedirects(response, '/login/?next=/profile/')

    def test_profile_displays_user_info(self):
        """Test that profile page displays user information"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.profile_url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'testuser')
        self.assertContains(response, 'test@example.com')
        self.assertContains(response, 'Test')
        self.assertContains(response, 'User')

    def test_profile_displays_edl_api_token(self):
        """Test that profile displays EDL API token"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.profile_url)

        self.assertContains(response, self.user.profile.api_token)
        self.assertContains(response, 'EDL API Token')

    def test_profile_displays_drf_token(self):
        """Test that profile displays DRF auth token"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.profile_url)

        drf_token = Token.objects.get(user=self.user)
        self.assertContains(response, drf_token.key)
        self.assertContains(response, 'REST API Token')

    def test_profile_shows_permissions(self):
        """Test that profile displays user permissions"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.profile_url)

        self.assertContains(response, 'Read-Only')


class RegenerateTokenViewTest(TestCase):
    """Test token regeneration"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.regenerate_url = reverse('regenerate_token')

    def test_regenerate_requires_login(self):
        """Test that regenerate token requires authentication"""
        response = self.client.post(self.regenerate_url)
        self.assertRedirects(response, '/login/?next=/profile/regenerate-token/')

    def test_regenerate_requires_post(self):
        """Test that regenerate token requires POST method"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(self.regenerate_url)
        self.assertEqual(response.status_code, 405)  # Method not allowed

    def test_regenerate_creates_new_token(self):
        """Test that regenerate creates a new token"""
        self.client.login(username='testuser', password='testpass123')
        old_token = self.user.profile.api_token

        response = self.client.post(self.regenerate_url)

        self.user.profile.refresh_from_db()
        new_token = self.user.profile.api_token

        self.assertNotEqual(old_token, new_token)
        self.assertRedirects(response, reverse('profile'))

    def test_regenerate_shows_success_message(self):
        """Test that regenerate shows success message"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post(self.regenerate_url, follow=True)

        messages = list(response.context['messages'])
        self.assertEqual(len(messages), 1)
        self.assertIn('regenerated', str(messages[0]).lower())


class FrontendViewAuthenticationTest(TestCase):
    """Test that all frontend views require authentication"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )

    def test_accounts_view_requires_login(self):
        """Test accounts view requires authentication"""
        response = self.client.get(reverse('accounts'))
        self.assertRedirects(response, '/login/?next=/accounts/')

    def test_enis_view_requires_login(self):
        """Test ENIs view requires authentication"""
        response = self.client.get(reverse('enis'))
        self.assertRedirects(response, '/login/?next=/enis/')

    def test_security_groups_view_requires_login(self):
        """Test security groups view requires authentication"""
        response = self.client.get(reverse('security_groups'))
        self.assertRedirects(response, '/login/?next=/security-groups/')

    def test_ec2_instances_view_requires_login(self):
        """Test EC2 instances view requires authentication"""
        response = self.client.get(reverse('ec2_instances'))
        self.assertRedirects(response, '/login/?next=/ec2-instances/')

    def test_edl_summary_requires_login(self):
        """Test EDL summary view requires authentication"""
        response = self.client.get(reverse('edl_summary'))
        self.assertRedirects(response, '/login/?next=/edl/')

    def test_authenticated_user_can_access_accounts(self):
        """Test that authenticated users can access accounts view"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('accounts'))
        self.assertEqual(response.status_code, 200)
