"""
Tests for EDL endpoint token authentication
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from resources.models import UserProfile, AWSAccount, VPC, Subnet, ENI, SecurityGroup


class EDLTokenAuthenticationTest(TestCase):
    """Test EDL endpoint token authentication"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = self.user.profile.api_token

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
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            owner_account='123456789012',
            state='available'
        )
        self.security_group = SecurityGroup.objects.create(
            sg_id='sg-12345',
            vpc=self.vpc,
            name='test-sg',
            description='Test security group'
        )
        self.eni = ENI.objects.create(
            eni_id='eni-12345',
            subnet=self.subnet,
            interface_type='interface',
            status='in-use',
            private_ip_address='10.0.1.10',
            owner_account='123456789012'
        )

    def test_edl_account_endpoint_without_token_returns_401(self):
        """Test that EDL account endpoint requires token"""
        url = reverse('edl_account_ips', kwargs={'account_id': '123456789012'})
        response = self.client.get(url)

        self.assertEqual(response.status_code, 401)
        self.assertIn('token required', response.content.decode().lower())

    def test_edl_account_endpoint_with_invalid_token_returns_401(self):
        """Test that EDL account endpoint rejects invalid token"""
        url = reverse('edl_account_ips', kwargs={'account_id': '123456789012'})
        response = self.client.get(url + '?token=invalid_token_here')

        self.assertEqual(response.status_code, 401)
        self.assertIn('invalid', response.content.decode().lower())

    def test_edl_account_endpoint_with_valid_token_returns_200(self):
        """Test that EDL account endpoint accepts valid token"""
        url = reverse('edl_account_ips', kwargs={'account_id': '123456789012'})
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')

    def test_edl_account_endpoint_returns_ip_list(self):
        """Test that EDL account endpoint returns IP addresses"""
        url = reverse('edl_account_ips', kwargs={'account_id': '123456789012'})
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('10.0.1.10', content)
        self.assertIn('eni-12345', content)
        self.assertIn('primary', content)

    def test_edl_security_group_endpoint_without_token_returns_401(self):
        """Test that EDL security group endpoint requires token"""
        url = reverse('edl_security_group_ips', kwargs={'sg_id': 'sg-12345'})
        response = self.client.get(url)

        self.assertEqual(response.status_code, 401)

    def test_edl_security_group_endpoint_with_valid_token_returns_200(self):
        """Test that EDL security group endpoint accepts valid token"""
        # First associate ENI with security group
        from resources.models import ENISecurityGroup
        ENISecurityGroup.objects.create(
            eni=self.eni,
            security_group=self.security_group
        )

        url = reverse('edl_security_group_ips', kwargs={'sg_id': 'sg-12345'})
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')

    def test_edl_enis_by_tags_without_token_returns_401(self):
        """Test that EDL ENIs by tags endpoint requires token"""
        url = reverse('edl_enis_by_tags')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 401)

    def test_edl_enis_by_tags_with_valid_token_returns_200(self):
        """Test that EDL ENIs by tags endpoint accepts valid token"""
        url = reverse('edl_enis_by_tags')
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)

    def test_edl_enis_by_tags_filters_correctly(self):
        """Test that EDL ENIs by tags filters by tag parameters"""
        # Update ENI with tags
        self.eni.tags = {'Environment': 'PROD', 'Team': 'DevOps'}
        self.eni.save()

        url = reverse('edl_enis_by_tags')
        response = self.client.get(url + f'?token={self.token}&Environment=PROD')

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('10.0.1.10', content)

    def test_edl_enis_by_tags_excludes_token_from_filters(self):
        """Test that token parameter is not used as tag filter"""
        self.eni.tags = {'token': 'should_not_match'}
        self.eni.save()

        url = reverse('edl_enis_by_tags')
        response = self.client.get(url + f'?token={self.token}')

        # Should return the ENI since token is excluded from tag filters
        self.assertEqual(response.status_code, 200)

    def test_token_regeneration_invalidates_old_token(self):
        """Test that regenerating token invalidates the old one"""
        old_token = self.token
        new_token = self.user.profile.regenerate_token()

        url = reverse('edl_account_ips', kwargs={'account_id': '123456789012'})

        # Old token should fail
        response_old = self.client.get(url + f'?token={old_token}')
        self.assertEqual(response_old.status_code, 401)

        # New token should work
        response_new = self.client.get(url + f'?token={new_token}')
        self.assertEqual(response_new.status_code, 200)


class EDLSummaryPageTest(TestCase):
    """Test EDL summary page authentication and token display"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = self.user.profile.api_token

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
            owner_account='123456789012'
        )

    def test_edl_summary_requires_login(self):
        """Test that EDL summary page requires authentication"""
        response = self.client.get(reverse('edl_summary'))
        self.assertRedirects(response, '/login/?next=/edl/')

    def test_edl_summary_displays_user_token_in_urls(self):
        """Test that EDL summary page includes user's token in URLs"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('edl_summary'))

        self.assertEqual(response.status_code, 200)
        # Check that token is included in account URLs
        self.assertContains(response, f'?token={self.token}')
        # Check that it appears in the account EDL URL
        self.assertContains(response, f'/edl/account/123456789012?token={self.token}')

    def test_edl_summary_shows_security_groups_with_token(self):
        """Test that security group URLs include token"""
        from resources.models import SecurityGroup, ENISecurityGroup

        sg = SecurityGroup.objects.create(
            sg_id='sg-12345',
            vpc=self.vpc,
            name='test-sg',
            description='Test'
        )
        ENISecurityGroup.objects.create(eni=self.eni, security_group=sg)

        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('edl_summary'))

        self.assertContains(response, f'/edl/sg/sg-12345?token={self.token}')

    def test_edl_summary_filter_builder_includes_token(self):
        """Test that filter builder generates URLs with token"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(reverse('edl_summary'))

        # Check that the generated URL input has token
        self.assertContains(response, f'?token={self.token}')
        # Check that JavaScript includes token in params
        self.assertContains(response, "['token=")


class EDLCachingTest(TestCase):
    """Test EDL endpoint caching"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.token = self.user.profile.api_token

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
            owner_account='123456789012'
        )

    def test_edl_endpoints_have_cache_header(self):
        """Test that EDL endpoints include X-Content-Type-Options header"""
        url = reverse('edl_account_ips', kwargs={'account_id': '123456789012'})
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
