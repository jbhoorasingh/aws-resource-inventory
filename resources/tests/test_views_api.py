"""
Tests for REST API views.
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance
)


class AWSAccountAPITest(TestCase):
    """Tests for AWSAccount API endpoints."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('awsaccount-list')

        # Create and authenticate user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

        self.account1 = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account 1',
            is_active=True
        )
        self.account2 = AWSAccount.objects.create(
            account_id='987654321098',
            account_name='Test Account 2',
            is_active=False
        )

    def test_list_accounts(self):
        """Test GET request to list accounts."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_retrieve_account(self):
        """Test GET request to retrieve single account."""
        url = reverse('awsaccount-detail', args=[self.account1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['account_id'], '123456789012')
        self.assertEqual(response.data['account_name'], 'Test Account 1')

    def test_filter_active_accounts(self):
        """Test filtering by is_active status."""
        url = f'{self.url}?is_active=true'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['account_id'], '123456789012')


class VPCAPITest(TestCase):
    """Tests for VPC API endpoints."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('vpc-list')

        # Create and authenticate user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

        self.vpc1 = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.vpc2 = VPC.objects.create(
            vpc_id='vpc-87654321',
            cidr_block='172.16.0.0/16',
            region='us-west-2',
            state='available',
            owner_account='987654321098'
        )

    def test_list_vpcs(self):
        """Test GET request to list VPCs."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_retrieve_vpc(self):
        """Test GET request to retrieve single VPC."""
        url = reverse('vpc-detail', args=[self.vpc1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['vpc_id'], 'vpc-12345678')

    def test_filter_vpcs_by_region(self):
        """Test filtering VPCs by region."""
        url = f'{self.url}?region=us-east-1'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['vpc_id'], 'vpc-12345678')

    def test_filter_vpcs_by_owner_account(self):
        """Test filtering VPCs by owner account."""
        url = f'{self.url}?owner_account=123456789012'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)


class SubnetAPITest(TestCase):
    """Tests for Subnet API endpoints."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('subnet-list')

        # Create and authenticate user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.subnet1 = Subnet.objects.create(
            subnet_id='subnet-12345678',
            vpc=self.vpc,
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available'
        )
        self.subnet2 = Subnet.objects.create(
            subnet_id='subnet-87654321',
            vpc=self.vpc,
            cidr_block='10.0.2.0/24',
            availability_zone='us-east-1b',
            state='available'
        )

    def test_list_subnets(self):
        """Test GET request to list subnets."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_retrieve_subnet(self):
        """Test GET request to retrieve single subnet."""
        url = reverse('subnet-detail', args=[self.subnet1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['subnet_id'], 'subnet-12345678')

    def test_filter_subnets_by_vpc(self):
        """Test filtering subnets by VPC."""
        url = f'{self.url}?vpc={self.vpc.id}'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)


class SecurityGroupAPITest(TestCase):
    """Tests for SecurityGroup API endpoints."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('securitygroup-list')

        # Create and authenticate user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-12345678',
            name='test-sg',
            description='Test security group',
            vpc=self.vpc
        )
        SecurityGroupRule.objects.create(
            security_group=self.sg,
            rule_type='ingress',
            protocol='tcp',
            from_port=80,
            to_port=80,
            source_type='cidr',
            source_value='0.0.0.0/0'
        )
        SecurityGroupRule.objects.create(
            security_group=self.sg,
            rule_type='egress',
            protocol='-1',
            from_port=-1,
            to_port=-1,
            source_type='cidr',
            source_value='0.0.0.0/0'
        )

    def test_list_security_groups(self):
        """Test GET request to list security groups."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

    def test_retrieve_security_group(self):
        """Test GET request to retrieve single security group."""
        url = reverse('securitygroup-detail', args=[self.sg.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['sg_id'], 'sg-12345678')
        self.assertEqual(response.data['name'], 'test-sg')

    def test_security_group_includes_rules(self):
        """Test security group response includes rules."""
        url = reverse('securitygroup-detail', args=[self.sg.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should have rules in the response
        self.assertIn('ingress_rules', response.data)
        self.assertIn('egress_rules', response.data)


class ENIAPITest(TestCase):
    """Tests for ENI API endpoints."""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('eni-list')

        # Create and authenticate user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

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
            public_ip_address='54.1.2.3',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        self.eni2 = ENI.objects.create(
            eni_id='eni-87654321',
            subnet=self.subnet,
            private_ip_address='10.0.1.20',
            status='available',
            interface_type='interface',
            mac_address='02:00:00:00:00:02',
            owner_account='123456789012'
        )
        ENISecondaryIP.objects.create(
            eni=self.eni1,
            ip_address='10.0.1.11'
        )

    def test_list_enis(self):
        """Test GET request to list ENIs."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_retrieve_eni(self):
        """Test GET request to retrieve single ENI."""
        url = reverse('eni-detail', args=[self.eni1.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['eni_id'], 'eni-12345678')
        self.assertEqual(response.data['private_ip_address'], '10.0.1.10')

    def test_by_ip_action_primary(self):
        """Test finding ENI by primary IP."""
        url = reverse('eni-by-ip')
        response = self.client.get(url, {'ip': '10.0.1.10'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['eni_id'], 'eni-12345678')

    def test_by_ip_action_public(self):
        """Test finding ENI by public IP."""
        url = reverse('eni-by-ip')
        response = self.client.get(url, {'ip': '54.1.2.3'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['eni_id'], 'eni-12345678')

    def test_by_ip_action_secondary(self):
        """Test finding ENI by secondary IP."""
        url = reverse('eni-by-ip')
        response = self.client.get(url, {'ip': '10.0.1.11'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['eni_id'], 'eni-12345678')

    def test_by_ip_action_not_found(self):
        """Test by_ip with non-existent IP."""
        url = reverse('eni-by-ip')
        response = self.client.get(url, {'ip': '192.168.1.1'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_with_public_ip_action(self):
        """Test filtering ENIs with public IPs."""
        url = reverse('eni-with-public-ip')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['eni_id'], 'eni-12345678')

    def test_summary_action(self):
        """Test ENI summary statistics."""
        url = reverse('eni-summary')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_enis', response.data)
        self.assertIn('total_private_ips', response.data)
        self.assertIn('total_public_ips', response.data)
        self.assertEqual(response.data['total_enis'], 2)
        self.assertEqual(response.data['total_public_ips'], 1)

    def test_by_region_action(self):
        """Test filtering ENIs by region."""
        url = reverse('eni-by-region')
        response = self.client.get(url, {'region': 'us-east-1'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_by_owner_account_action(self):
        """Test filtering ENIs by owner account."""
        url = reverse('eni-by-owner-account')
        response = self.client.get(url, {'owner_account': '123456789012'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)


class APIPaginationTest(TestCase):
    """Tests for API pagination."""

    def setUp(self):
        self.client = APIClient()

        # Create and authenticate user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.force_authenticate(user=self.user)

        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )
        # Create more than 100 security groups to test pagination
        for i in range(150):
            SecurityGroup.objects.create(
                sg_id=f'sg-{str(i).zfill(8)}',
                name=f'test-sg-{i}',
                vpc=self.vpc
            )

    def test_pagination(self):
        """Test API returns paginated results."""
        url = reverse('securitygroup-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('count', response.data)
        self.assertIn('next', response.data)
        self.assertIn('previous', response.data)
        self.assertIn('results', response.data)
        self.assertEqual(len(response.data['results']), 100)  # Default page size
        self.assertEqual(response.data['count'], 150)

    def test_pagination_next_page(self):
        """Test accessing next page of results."""
        url = reverse('securitygroup-list')
        response = self.client.get(url)
        next_url = response.data['next']
        self.assertIsNotNone(next_url)

        # Get next page
        response2 = self.client.get(next_url)
        self.assertEqual(response2.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response2.data['results']), 50)  # Remaining items
