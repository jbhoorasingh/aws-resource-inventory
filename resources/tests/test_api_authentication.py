"""
Tests for REST API authentication (Session + Token)
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from resources.models import AWSAccount, VPC, Subnet, ENI


class APITokenObtainTest(TestCase):
    """Test token obtain endpoint"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )

    def test_obtain_token_with_valid_credentials(self):
        """Test obtaining token with valid credentials"""
        url = reverse('api_token_auth')
        response = self.client.post(url, {
            'username': 'testuser',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.data)

        # Verify token matches user's DRF token
        user_token = Token.objects.get(user=self.user)
        self.assertEqual(response.data['token'], user_token.key)

    def test_obtain_token_with_invalid_credentials(self):
        """Test obtaining token with invalid credentials"""
        url = reverse('api_token_auth')
        response = self.client.post(url, {
            'username': 'testuser',
            'password': 'wrongpassword'
        })

        self.assertEqual(response.status_code, 400)
        self.assertNotIn('token', response.data)

    def test_obtain_token_without_credentials(self):
        """Test obtaining token without credentials"""
        url = reverse('api_token_auth')
        response = self.client.post(url, {})

        self.assertEqual(response.status_code, 400)


class APISessionAuthenticationTest(TestCase):
    """Test Session authentication for API endpoints"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )

        # Create test data
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account'
        )

    def test_api_requires_authentication(self):
        """Test that API endpoints require authentication"""
        url = '/api/accounts/'
        response = self.client.get(url)

        # DRF returns 403 with IsAuthenticated permission class
        self.assertIn(response.status_code, [401, 403])
        self.assertIn('detail', response.data)

    def test_api_accessible_with_session_auth(self):
        """Test that logged-in users can access API via session"""
        self.client.force_authenticate(user=self.user)
        url = '/api/accounts/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)

    def test_api_accounts_endpoint_with_session(self):
        """Test accounts endpoint with session authentication"""
        self.client.force_authenticate(user=self.user)
        url = '/api/accounts/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['account_id'], '123456789012')

    def test_api_vpcs_endpoint_with_session(self):
        """Test VPCs endpoint with session authentication"""
        VPC.objects.create(
            vpc_id='vpc-12345',
            region='us-east-1',
            cidr_block='10.0.0.0/16',
            owner_account='123456789012',
            state='available'
        )

        self.client.force_authenticate(user=self.user)
        url = '/api/vpcs/'
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)


class APITokenAuthenticationTest(TestCase):
    """Test Token authentication for API endpoints"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.get(user=self.user)

        # Create test data
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account'
        )
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345',
            region='us-east-1',
            cidr_block='10.0.0.0/16',
            owner_account='123456789012',
            state='available'
        )

    def test_api_accessible_with_token_in_header(self):
        """Test that API accepts token in Authorization header"""
        url = '/api/accounts/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)

    def test_api_rejects_invalid_token(self):
        """Test that API rejects invalid tokens"""
        url = '/api/accounts/'
        self.client.credentials(HTTP_AUTHORIZATION='Token invalid_token_here')
        response = self.client.get(url)

        # Can be 401 (invalid credentials) or 403 (not authenticated)
        self.assertIn(response.status_code, [401, 403])

    def test_api_rejects_malformed_auth_header(self):
        """Test that API rejects malformed Authorization header"""
        url = '/api/accounts/'
        self.client.credentials(HTTP_AUTHORIZATION='Bearer wrong_format')
        response = self.client.get(url)

        # Can be 401 (invalid credentials) or 403 (not authenticated)
        self.assertIn(response.status_code, [401, 403])

    def test_api_accounts_with_token(self):
        """Test accounts endpoint with token authentication"""
        url = '/api/accounts/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)

    def test_api_vpcs_with_token(self):
        """Test VPCs endpoint with token authentication"""
        url = '/api/vpcs/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)

    def test_api_enis_with_token(self):
        """Test ENIs endpoint with token authentication"""
        subnet = Subnet.objects.create(
            subnet_id='subnet-12345',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            owner_account='123456789012',
            state='available'
        )
        ENI.objects.create(
            eni_id='eni-12345',
            subnet=subnet,
            interface_type='interface',
            status='in-use',
            private_ip_address='10.0.1.10',
            owner_account='123456789012'
        )

        url = '/api/enis/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)


class APICustomActionsAuthTest(TestCase):
    """Test authentication on custom API actions"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.get(user=self.user)

        # Create test data
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345',
            region='us-east-1',
            cidr_block='10.0.0.0/16',
            owner_account='123456789012',
            state='available'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            owner_account='123456789012',
            state='available'
        )
        self.eni = ENI.objects.create(
            eni_id='eni-12345',
            subnet=self.subnet,
            interface_type='interface',
            status='in-use',
            private_ip_address='10.0.1.10',
            public_ip_address='54.1.2.3',
            owner_account='123456789012'
        )

    def test_enis_by_ip_requires_auth(self):
        """Test that by_ip action requires authentication"""
        url = '/api/enis/by_ip/?ip=10.0.1.10'
        response = self.client.get(url)

        self.assertIn(response.status_code, [401, 403])

    def test_enis_by_ip_with_token(self):
        """Test by_ip action with token authentication"""
        url = '/api/enis/by_ip/?ip=10.0.1.10'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['private_ip_address'], '10.0.1.10')

    def test_enis_with_public_ip_requires_auth(self):
        """Test that with_public_ip action requires authentication"""
        url = '/api/enis/with_public_ip/'
        response = self.client.get(url)

        self.assertIn(response.status_code, [401, 403])

    def test_enis_with_public_ip_with_token(self):
        """Test with_public_ip action with token authentication"""
        url = '/api/enis/with_public_ip/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['public_ip_address'], '54.1.2.3')

    def test_enis_summary_requires_auth(self):
        """Test that summary action requires authentication"""
        url = '/api/enis/summary/'
        response = self.client.get(url)

        self.assertIn(response.status_code, [401, 403])

    def test_enis_summary_with_token(self):
        """Test summary action with token authentication"""
        url = '/api/enis/summary/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertIn('total_enis', response.data)
        self.assertEqual(response.data['total_enis'], 1)

    def test_enis_by_region_requires_auth(self):
        """Test that by_region action requires authentication"""
        url = '/api/enis/by_region/?region=us-east-1'
        response = self.client.get(url)

        self.assertIn(response.status_code, [401, 403])

    def test_enis_by_region_with_token(self):
        """Test by_region action with token authentication"""
        url = '/api/enis/by_region/?region=us-east-1'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)


class APIPaginationAuthTest(TestCase):
    """Test that pagination works with authentication"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.get(user=self.user)

        # Create multiple accounts for pagination testing
        for i in range(5):
            AWSAccount.objects.create(
                account_id=f'12345678901{i}',
                account_name=f'Test Account {i}'
            )

    def test_pagination_works_with_token_auth(self):
        """Test that pagination works with token authentication"""
        url = '/api/accounts/'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertIn('count', response.data)
        self.assertIn('results', response.data)
        self.assertEqual(response.data['count'], 5)


class APIFilteringAuthTest(TestCase):
    """Test that filtering works with authentication"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = Token.objects.get(user=self.user)

        # Create VPCs with different states
        VPC.objects.create(
            vpc_id='vpc-active',
            region='us-east-1',
            cidr_block='10.0.0.0/16',
            owner_account='123456789012',
            state='available',
            is_default=True
        )
        VPC.objects.create(
            vpc_id='vpc-pending',
            region='us-west-2',
            cidr_block='10.1.0.0/16',
            owner_account='123456789012',
            state='pending',
            is_default=False
        )

    def test_filtering_works_with_token_auth(self):
        """Test that filtering works with token authentication"""
        url = '/api/vpcs/?state=available'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['vpc_id'], 'vpc-active')

    def test_multiple_filters_with_token_auth(self):
        """Test multiple filters with token authentication"""
        url = '/api/vpcs/?region=us-east-1&is_default=true'
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['vpc_id'], 'vpc-active')
