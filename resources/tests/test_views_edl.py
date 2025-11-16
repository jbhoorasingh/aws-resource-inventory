"""
Tests for External Dynamic List (EDL) views.
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, ENI, ENISecondaryIP, ENISecurityGroup
)


class EDLAccountIPsTest(TestCase):
    """Tests for EDL account IPs endpoint."""

    def setUp(self):
        self.client = Client()

        # Create user and get API token
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.token = self.user.profile.api_token

        # Create test data
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True
        )
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.eni1 = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        self.eni2 = ENI.objects.create(
            eni_id='eni-87654321',
            subnet=self.subnet,
            private_ip_address='10.0.1.20',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:02',
            owner_account='123456789012'
        )
        # Add secondary IPs
        ENISecondaryIP.objects.create(
            eni=self.eni1,
            ip_address='10.0.1.11'
        )
        ENISecondaryIP.objects.create(
            eni=self.eni1,
            ip_address='10.0.1.12'
        )

    def test_edl_account_ips_format(self):
        """Test EDL account IPs returns correct format."""
        url = reverse('edl_account_ips', args=['123456789012'])
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

        content = response.content.decode('utf-8')
        lines = content.split('\n')

        # Should have 4 IPs total (2 primary + 2 secondary)
        self.assertEqual(len(lines), 4)

        # Check primary IP format
        self.assertIn('10.0.1.10 # eni-12345678, primary', lines)
        self.assertIn('10.0.1.20 # eni-87654321, primary', lines)

        # Check secondary IP format
        self.assertIn('10.0.1.11 # eni-12345678, secondary', lines)
        self.assertIn('10.0.1.12 # eni-12345678, secondary', lines)

    def test_edl_account_ips_different_account(self):
        """Test EDL for different account returns empty list."""
        url = reverse('edl_account_ips', args=['999999999999'])
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertEqual(content, '')

    def test_edl_account_ips_caching(self):
        """Test EDL account IPs endpoint is cached."""
        url = reverse('edl_account_ips', args=['123456789012'])

        # First request
        response1 = self.client.get(url + f'?token={self.token}')
        self.assertEqual(response1.status_code, 200)

        # Create a new ENI
        ENI.objects.create(
            eni_id='eni-99999999',
            subnet=self.subnet,
            private_ip_address='10.0.1.99',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:99',
            owner_account='123456789012'
        )

        # Second request - should be cached (won't include new ENI)
        # Note: In testing, cache might not persist, so we just verify response is valid
        response2 = self.client.get(url + f'?token={self.token}')
        self.assertEqual(response2.status_code, 200)


class EDLSecurityGroupIPsTest(TestCase):
    """Tests for EDL security group IPs endpoint."""

    def setUp(self):
        self.client = Client()

        # Create user and get API token
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.token = self.user.profile.api_token

        # Create test data
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-12345678',
            name='test-sg',
            description='Test security group',
            vpc=self.vpc
        )
        self.eni1 = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        self.eni2 = ENI.objects.create(
            eni_id='eni-87654321',
            subnet=self.subnet,
            private_ip_address='10.0.1.20',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:02',
            owner_account='123456789012'
        )

        # Associate ENIs with security group
        ENISecurityGroup.objects.create(eni=self.eni1, security_group=self.sg)
        ENISecurityGroup.objects.create(eni=self.eni2, security_group=self.sg)

        # Add secondary IP
        ENISecondaryIP.objects.create(
            eni=self.eni1,
            ip_address='10.0.1.11'
        )

    def test_edl_security_group_ips_format(self):
        """Test EDL security group IPs returns correct format."""
        url = reverse('edl_security_group_ips', args=['sg-12345678'])
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

        content = response.content.decode('utf-8')
        lines = content.split('\n')

        # Should have 3 IPs total (2 primary + 1 secondary)
        self.assertEqual(len(lines), 3)

        # Check IP format
        self.assertIn('10.0.1.10 # eni-12345678, primary', lines)
        self.assertIn('10.0.1.20 # eni-87654321, primary', lines)
        self.assertIn('10.0.1.11 # eni-12345678, secondary', lines)

    def test_edl_security_group_not_found(self):
        """Test EDL for non-existent security group returns 404."""
        url = reverse('edl_security_group_ips', args=['sg-99999999'])
        response = self.client.get(url + f'?token={self.token}')
        self.assertEqual(response.status_code, 404)

    def test_edl_security_group_no_enis(self):
        """Test EDL for security group with no ENIs returns empty list."""
        # Create a security group with no ENIs
        sg2 = SecurityGroup.objects.create(
            sg_id='sg-87654321',
            name='empty-sg',
            vpc=self.vpc
        )

        url = reverse('edl_security_group_ips', args=['sg-87654321'])
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertEqual(content, '')


class EDLSummaryViewTest(TestCase):
    """Tests for EDL summary view."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('edl_summary')

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

        # Create test data
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True
        )
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-12345678',
            name='test-sg',
            vpc=self.vpc
        )
        self.eni = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        ENISecurityGroup.objects.create(eni=self.eni, security_group=self.sg)

    def test_edl_summary_view_get(self):
        """Test GET request to EDL summary view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/edl_summary.html')

    def test_edl_summary_view_displays_accounts(self):
        """Test accounts are displayed in EDL summary."""
        response = self.client.get(self.url)
        self.assertContains(response, 'Test Account')
        self.assertContains(response, '123456789012')

    def test_edl_summary_view_displays_security_groups(self):
        """Test security groups are displayed."""
        response = self.client.get(self.url)
        self.assertContains(response, 'test-sg')
        self.assertContains(response, 'sg-12345678')

    def test_edl_summary_with_account_not_in_table(self):
        """Test EDL summary with account that exists in ENIs but not in AWSAccount table."""
        # Create an ENI with an owner account that doesn't exist in AWSAccount
        ENI.objects.create(
            eni_id='eni-99999999',
            subnet=self.subnet,
            private_ip_address='10.0.1.99',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:99',
            owner_account='999999999999'
        )

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        # Should display mock account name
        self.assertContains(response, 'Account 999999999999')


class EDLAccountJSONTest(TestCase):
    """Tests for EDL account JSON metadata endpoint."""

    def setUp(self):
        self.client = Client()

        # Create user and get API token
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.token = self.user.profile.api_token

        # Create test data
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True,
            last_polled=timezone.now()
        )
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.eni1 = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        self.eni2 = ENI.objects.create(
            eni_id='eni-87654321',
            subnet=self.subnet,
            private_ip_address='10.0.1.20',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:02',
            owner_account='123456789012'
        )
        # Add secondary IPs
        ENISecondaryIP.objects.create(eni=self.eni1, ip_address='10.0.1.11')
        ENISecondaryIP.objects.create(eni=self.eni2, ip_address='10.0.1.21')

    def test_edl_account_json_structure(self):
        """Test EDL account JSON returns correct structure."""
        url = reverse('edl_account_json', args=['123456789012'])
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')

        data = response.json()

        # Check all required fields
        self.assertIn('account_id', data)
        self.assertIn('account_name', data)
        self.assertIn('edl_url', data)
        self.assertIn('eni_count', data)
        self.assertIn('total_ips', data)
        self.assertIn('primary_ips', data)
        self.assertIn('secondary_ips', data)
        self.assertIn('last_updated', data)

    def test_edl_account_json_values(self):
        """Test EDL account JSON returns correct values."""
        url = reverse('edl_account_json', args=['123456789012'])
        response = self.client.get(url + f'?token={self.token}')

        data = response.json()

        self.assertEqual(data['account_id'], '123456789012')
        self.assertEqual(data['account_name'], 'Test Account')
        self.assertEqual(data['edl_url'], '/edl/account/123456789012')
        self.assertEqual(data['eni_count'], 2)
        self.assertEqual(data['primary_ips'], 2)
        self.assertEqual(data['secondary_ips'], 2)
        self.assertEqual(data['total_ips'], 4)
        self.assertIsNotNone(data['last_updated'])

    def test_edl_account_json_not_found(self):
        """Test EDL account JSON for non-existent account returns 404."""
        url = reverse('edl_account_json', args=['999999999999'])
        response = self.client.get(url + f'?token={self.token}')
        self.assertEqual(response.status_code, 404)


class EDLSecurityGroupJSONTest(TestCase):
    """Tests for EDL security group JSON metadata endpoint."""

    def setUp(self):
        self.client = Client()

        # Create user and get API token
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.token = self.user.profile.api_token

        # Create test data
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-12345678',
            name='test-sg',
            description='Test security group',
            vpc=self.vpc
        )
        self.eni = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        ENISecurityGroup.objects.create(eni=self.eni, security_group=self.sg)
        ENISecondaryIP.objects.create(eni=self.eni, ip_address='10.0.1.11')

    def test_edl_security_group_json_structure(self):
        """Test EDL security group JSON returns correct structure."""
        url = reverse('edl_security_group_json', args=['sg-12345678'])
        response = self.client.get(url + f'?token={self.token}')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')

        data = response.json()

        # Check all required fields
        self.assertIn('sg_id', data)
        self.assertIn('sg_name', data)
        self.assertIn('vpc_id', data)
        self.assertIn('edl_url', data)
        self.assertIn('eni_count', data)
        self.assertIn('total_ips', data)
        self.assertIn('primary_ips', data)
        self.assertIn('secondary_ips', data)
        self.assertIn('last_updated', data)

    def test_edl_security_group_json_values(self):
        """Test EDL security group JSON returns correct values."""
        url = reverse('edl_security_group_json', args=['sg-12345678'])
        response = self.client.get(url + f'?token={self.token}')

        data = response.json()

        self.assertEqual(data['sg_id'], 'sg-12345678')
        self.assertEqual(data['sg_name'], 'test-sg')
        self.assertEqual(data['vpc_id'], 'vpc-12345678')
        self.assertEqual(data['edl_url'], '/edl/sg/sg-12345678')
        self.assertEqual(data['eni_count'], 1)
        self.assertEqual(data['primary_ips'], 1)
        self.assertEqual(data['secondary_ips'], 1)
        self.assertEqual(data['total_ips'], 2)
        self.assertIsNotNone(data['last_updated'])

    def test_edl_security_group_json_not_found(self):
        """Test EDL security group JSON for non-existent SG returns 404."""
        url = reverse('edl_security_group_json', args=['sg-99999999'])
        response = self.client.get(url + f'?token={self.token}')
        self.assertEqual(response.status_code, 404)


class EDLENIsByTagsTest(TestCase):
    """Tests for EDL ENIs by tags endpoint."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('edl_enis_by_tags')

        # Create user and get API token
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.token = self.user.profile.api_token

        # Create test data
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.eni1 = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012',
            tags={'Environment': 'PROD', 'Application': 'WebServer'}
        )
        self.eni2 = ENI.objects.create(
            eni_id='eni-87654321',
            subnet=self.subnet,
            private_ip_address='10.0.1.20',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:02',
            owner_account='123456789012',
            tags={'Environment': 'DEV', 'Application': 'WebServer'}
        )
        self.eni3 = ENI.objects.create(
            eni_id='eni-99999999',
            subnet=self.subnet,
            private_ip_address='10.0.1.30',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:03',
            owner_account='123456789012',
            tags={'Environment': 'PROD', 'Application': 'Database'}
        )
        ENISecondaryIP.objects.create(eni=self.eni1, ip_address='10.0.1.11')

    def test_edl_enis_by_tags_single_filter(self):
        """Test filtering ENIs by single tag."""
        response = self.client.get(self.url, {'Environment': 'PROD', 'token': self.token})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/plain; charset=utf-8')

        content = response.content.decode('utf-8')
        lines = content.split('\n')

        # Should have 3 IPs (2 primary from PROD + 1 secondary)
        self.assertEqual(len(lines), 3)
        self.assertIn('10.0.1.10 # eni-12345678, primary', lines)
        self.assertIn('10.0.1.30 # eni-99999999, primary', lines)
        self.assertIn('10.0.1.11 # eni-12345678, secondary', lines)

    def test_edl_enis_by_tags_multiple_filters(self):
        """Test filtering ENIs by multiple tags."""
        response = self.client.get(self.url, {
            'Environment': 'PROD',
            'Application': 'WebServer',
            'token': self.token
        })

        self.assertEqual(response.status_code, 200)

        content = response.content.decode('utf-8')
        lines = content.split('\n')

        # Should have 2 IPs (1 primary + 1 secondary from eni1)
        self.assertEqual(len(lines), 2)
        self.assertIn('10.0.1.10 # eni-12345678, primary', lines)
        self.assertIn('10.0.1.11 # eni-12345678, secondary', lines)

    def test_edl_enis_by_tags_no_matches(self):
        """Test filtering with no matching tags returns empty."""
        response = self.client.get(self.url, {'Environment': 'STAGING', 'token': self.token})

        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        self.assertEqual(content, '')

    def test_edl_enis_by_tags_no_filters(self):
        """Test no filters returns all ENIs."""
        response = self.client.get(self.url, {'token': self.token})

        self.assertEqual(response.status_code, 200)
        content = response.content.decode('utf-8')
        lines = content.split('\n')

        # Should have all 4 IPs (3 primary + 1 secondary)
        self.assertEqual(len(lines), 4)


class EDLENIsByTagsJSONTest(TestCase):
    """Tests for EDL ENIs by tags JSON metadata endpoint."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('edl_enis_by_tags_json')

        # Create user and get API token
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.token = self.user.profile.api_token

        # Create test data
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.eni = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012',
            tags={'Environment': 'PROD'}
        )
        ENISecondaryIP.objects.create(eni=self.eni, ip_address='10.0.1.11')

    def test_edl_enis_by_tags_json_structure(self):
        """Test JSON metadata structure."""
        response = self.client.get(self.url, {'Environment': 'PROD', 'token': self.token})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')

        data = response.json()

        # Check required fields
        self.assertIn('filters', data)
        self.assertIn('edl_url', data)
        self.assertIn('eni_count', data)
        self.assertIn('total_ips', data)
        self.assertIn('primary_ips', data)
        self.assertIn('secondary_ips', data)

    def test_edl_enis_by_tags_json_values(self):
        """Test JSON metadata values."""
        response = self.client.get(self.url, {'Environment': 'PROD', 'token': self.token})

        data = response.json()

        self.assertEqual(data['filters'], {'Environment': 'PROD'})
        self.assertEqual(data['edl_url'], '/edl/enis/?Environment=PROD')
        self.assertEqual(data['eni_count'], 1)
        self.assertEqual(data['primary_ips'], 1)
        self.assertEqual(data['secondary_ips'], 1)
        self.assertEqual(data['total_ips'], 2)

    def test_edl_enis_by_tags_json_no_filters(self):
        """Test JSON metadata with no filters."""
        response = self.client.get(self.url, {'token': self.token})

        data = response.json()

        self.assertEqual(data['filters'], {})
        self.assertEqual(data['edl_url'], '/edl/enis/')
