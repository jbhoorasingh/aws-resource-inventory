"""
Tests for frontend views.
"""
from django.test import TestCase, TransactionTestCase, Client
from django.contrib.auth.models import User, Permission
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils import timezone
from unittest.mock import patch, MagicMock
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance, UserProfile, DiscoveryTask
)


class AccountsViewTest(TestCase):
    """Tests for accounts list view."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('accounts')

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

        self.account1 = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account 1',
            is_active=True
        )
        self.account2 = AWSAccount.objects.create(
            account_id='987654321098',
            account_name='Test Account 2',
            is_active=True,
            last_polled=timezone.now()
        )

    def test_accounts_view_get(self):
        """Test GET request to accounts view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/accounts.html')

    def test_accounts_view_displays_accounts(self):
        """Test accounts are displayed in view."""
        response = self.client.get(self.url)
        self.assertContains(response, 'Test Account 1')
        self.assertContains(response, 'Test Account 2')
        self.assertContains(response, '123456789012')
        self.assertContains(response, '987654321098')

    def test_accounts_view_context(self):
        """Test context data."""
        response = self.client.get(self.url)
        self.assertIn('accounts', response.context)
        self.assertEqual(len(response.context['accounts']), 2)


class PollAccountViewTest(TransactionTestCase):
    """Tests for poll account view."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('poll_account')

        # Create user with can_poll_accounts permission
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        content_type = ContentType.objects.get_for_model(UserProfile)
        permission = Permission.objects.get(
            codename='can_poll_accounts',
            content_type=content_type
        )
        self.user.user_permissions.add(permission)
        self.client.login(username='testuser', password='testpass123')

    @patch('resources.tasks.discover_account_resources.delay')
    def test_poll_account_with_direct_credentials(self, mock_task):
        """Test polling account with direct credentials queues Celery task."""
        mock_task.return_value = MagicMock(id='test-task-id')

        response = self.client.post(self.url, {
            'account_number': '123456789012',
            'account_name': 'Test Account',
            'access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'session_token': 'token123',
            'regions': 'us-east-1,us-west-2'
        })

        self.assertEqual(response.status_code, 302)  # Redirect after success
        # Verify DiscoveryTask was created
        self.assertEqual(DiscoveryTask.objects.count(), 1)
        task = DiscoveryTask.objects.first()
        self.assertEqual(task.status, 'pending')
        self.assertEqual(task.task_type, 'single')
        # Verify Celery task was queued
        mock_task.assert_called_once()

    @patch('resources.tasks.discover_account_resources.delay')
    def test_poll_account_with_role_assumption(self, mock_task):
        """Test polling account with role assumption queues Celery task."""
        mock_task.return_value = MagicMock(id='test-task-id')

        response = self.client.post(self.url, {
            'account_number': '123456789012',
            'account_name': 'Test Account',
            'access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'session_token': 'token123',
            'regions': 'us-east-1',
            'role_arn': 'arn:aws:iam::123456789012:role/TestRole',
            'external_id': 'test-id'
        })

        self.assertEqual(response.status_code, 302)
        # Verify DiscoveryTask was created
        self.assertEqual(DiscoveryTask.objects.count(), 1)
        mock_task.assert_called_once()

    def test_poll_account_requires_post(self):
        """Test GET request is not allowed."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 405)


class ENIsViewTest(TestCase):
    """Tests for ENIs list view."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('enis')

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

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
            public_ip_address='54.1.2.3',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012',
            tags={'Name': 'Test ENI'}
        )

    def test_enis_view_get(self):
        """Test GET request to ENIs view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/enis.html')

    def test_enis_view_displays_enis(self):
        """Test ENIs are displayed in view."""
        response = self.client.get(self.url)
        self.assertContains(response, 'eni-12345678')
        self.assertContains(response, '10.0.1.10')
        self.assertContains(response, '54.1.2.3')

    def test_enis_view_context(self):
        """Test context data."""
        response = self.client.get(self.url)
        self.assertIn('enis', response.context)
        self.assertIn('total_enis', response.context)
        self.assertIn('total_private_ips', response.context)
        self.assertIn('total_public_ips', response.context)
        self.assertIn('total_regions', response.context)


class EC2InstancesViewTest(TestCase):
    """Tests for EC2 instances list view."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('ec2_instances')

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

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
        self.instance = EC2Instance.objects.create(
            instance_id='i-12345678',
            name='Test Instance',
            instance_type='t3.micro',
            state='running',
            region='us-east-1',
            availability_zone='us-east-1a',
            vpc=self.vpc,
            subnet=self.subnet,
            private_ip_address='10.0.1.50',
            owner_account='123456789012',
            launch_time=timezone.now()
        )

    def test_ec2_instances_view_get(self):
        """Test GET request to EC2 instances view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/ec2_instances.html')

    def test_ec2_instances_view_displays_instances(self):
        """Test instances are displayed in view."""
        response = self.client.get(self.url)
        self.assertContains(response, 'i-12345678')
        self.assertContains(response, 'Test Instance')
        self.assertContains(response, 't3.micro')

    def test_ec2_instances_view_context(self):
        """Test context data."""
        response = self.client.get(self.url)
        self.assertIn('instances', response.context)
        self.assertIn('total_instances', response.context)
        self.assertIn('running_instances', response.context)
        self.assertIn('stopped_instances', response.context)


class EC2InstanceDetailViewTest(TestCase):
    """Tests for EC2 instance detail view."""

    def setUp(self):
        self.client = Client()

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

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
        self.instance = EC2Instance.objects.create(
            instance_id='i-12345678',
            name='Test Instance',
            instance_type='t3.micro',
            state='running',
            region='us-east-1',
            availability_zone='us-east-1a',
            vpc=self.vpc,
            subnet=self.subnet,
            private_ip_address='10.0.1.50',
            owner_account='123456789012',
            launch_time=timezone.now()
        )
        self.url = reverse('ec2_instance_detail', args=[self.instance.id])

    def test_instance_detail_view_get(self):
        """Test GET request to instance detail view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/ec2_instance_detail.html')

    def test_instance_detail_view_displays_instance(self):
        """Test instance details are displayed."""
        response = self.client.get(self.url)
        self.assertContains(response, 'i-12345678')
        self.assertContains(response, 'Test Instance')
        self.assertContains(response, 't3.micro')
        self.assertContains(response, 'running')

    def test_instance_detail_view_404(self):
        """Test redirect for non-existent instance."""
        url = reverse('ec2_instance_detail', args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('ec2_instances'))


class SecurityGroupsViewTest(TestCase):
    """Tests for security groups list view."""

    def setUp(self):
        self.client = Client()
        self.url = reverse('security_groups')

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

        # Create test data
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

    def test_security_groups_view_get(self):
        """Test GET request to security groups view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/security_groups.html')

    def test_security_groups_view_displays_groups(self):
        """Test security groups are displayed."""
        response = self.client.get(self.url)
        self.assertContains(response, 'sg-12345678')
        self.assertContains(response, 'test-sg')

    def test_security_groups_view_context(self):
        """Test context data."""
        response = self.client.get(self.url)
        self.assertIn('security_groups', response.context)
        self.assertIn('total_security_groups', response.context)
        self.assertIn('total_ingress_rules', response.context)
        self.assertIn('total_egress_rules', response.context)


class SecurityGroupDetailViewTest(TestCase):
    """Tests for security group detail view."""

    def setUp(self):
        self.client = Client()

        # Create and login user
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

        # Create test data
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
            from_port=443,
            to_port=443,
            source_type='cidr',
            source_value='0.0.0.0/0',
            description='Allow HTTPS'
        )
        self.url = reverse('security_group_detail', args=[self.sg.id])

    def test_security_group_detail_view_get(self):
        """Test GET request to security group detail view."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/security_group_detail.html')

    def test_security_group_detail_view_displays_group(self):
        """Test security group details are displayed."""
        response = self.client.get(self.url)
        self.assertContains(response, 'sg-12345678')
        self.assertContains(response, 'test-sg')
        self.assertContains(response, 'Allow HTTPS')

    def test_security_group_detail_view_404(self):
        """Test redirect for non-existent security group."""
        url = reverse('security_group_detail', args=[99999])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('security_groups'))


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
        # Create ENI so the account and security group appear in EDL summary
        self.eni = ENI.objects.create(
            eni_id='eni-12345678',
            subnet=self.subnet,
            private_ip_address='10.0.1.10',
            status='in-use',
            interface_type='interface',
            mac_address='02:00:00:00:00:01',
            owner_account='123456789012'
        )
        # Associate ENI with security group
        ENISecurityGroup.objects.create(
            eni=self.eni,
            security_group=self.sg
        )

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
