"""
Tests for DiscoveryLog model, API endpoints, and frontend views.
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.authtoken.models import Token
from resources.models import (
    AWSAccount, VPC, Subnet, ENI, EC2Instance, DiscoveryTask, DiscoveryLog
)


class DiscoveryLogModelTest(TestCase):
    """Tests for DiscoveryLog model."""

    def setUp(self):
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True,
        )
        self.task = DiscoveryTask.objects.create(
            task_type='single',
            status='running',
            account=self.account,
            regions=['us-east-1'],
        )

    def test_create_log_entry(self):
        log = DiscoveryLog.objects.create(
            task=self.task,
            account=self.account,
            level='info',
            category='resource_created',
            message='Created ENI eni-abc123',
            resource_type='eni',
            resource_id='eni-abc123',
            region='us-east-1',
        )
        self.assertEqual(log.level, 'info')
        self.assertEqual(log.category, 'resource_created')
        self.assertIn('eni-abc123', log.message)
        self.assertIsNotNone(log.created_at)

    def test_log_str_representation(self):
        log = DiscoveryLog.objects.create(
            task=self.task,
            account=self.account,
            level='warning',
            category='ec2_link_preserved',
            message='EC2 i-abc123 not found for ENI eni-abc123 — preserving existing link',
        )
        self.assertIn('[warning]', str(log))
        self.assertIn('ec2_link_preserved', str(log))

    def test_log_ordering_is_newest_first(self):
        log1 = DiscoveryLog.objects.create(
            task=self.task, account=self.account,
            level='info', category='resource_created',
            message='First log',
        )
        log2 = DiscoveryLog.objects.create(
            task=self.task, account=self.account,
            level='info', category='resource_updated',
            message='Second log',
        )
        logs = list(DiscoveryLog.objects.all())
        self.assertEqual(logs[0].id, log2.id)
        self.assertEqual(logs[1].id, log1.id)

    def test_log_with_context_json(self):
        log = DiscoveryLog.objects.create(
            task=self.task,
            account=self.account,
            level='warning',
            category='ec2_link_preserved',
            message='EC2 not found',
            context={'ec2_id': 'i-abc123', 'reason': 'cross-account'},
        )
        log.refresh_from_db()
        self.assertEqual(log.context['ec2_id'], 'i-abc123')

    def test_log_nullable_task_and_account(self):
        log = DiscoveryLog.objects.create(
            level='error',
            category='account_error',
            message='Orphan log entry',
        )
        self.assertIsNone(log.task)
        self.assertIsNone(log.account)

    def test_cascade_delete_with_task(self):
        DiscoveryLog.objects.create(
            task=self.task,
            level='info',
            category='resource_created',
            message='Will be cascade deleted',
        )
        self.assertEqual(DiscoveryLog.objects.count(), 1)
        self.task.delete()
        self.assertEqual(DiscoveryLog.objects.count(), 0)

    def test_set_null_on_account_delete(self):
        log = DiscoveryLog.objects.create(
            task=self.task,
            account=self.account,
            level='info',
            category='resource_created',
            message='Account will be deleted',
        )
        self.account.delete()
        log.refresh_from_db()
        self.assertIsNone(log.account)


class DiscoveryLogAPITest(TestCase):
    """Tests for DiscoveryLog REST API endpoints."""

    def setUp(self):
        self.user = User.objects.create_user(username='apiuser', password='testpass123')
        # Token is auto-created by UserProfile signal
        self.token = Token.objects.get(user=self.user)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')

        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True,
        )
        self.task = DiscoveryTask.objects.create(
            task_type='single',
            status='success',
            account=self.account,
            regions=['us-east-1'],
            initiated_by=self.user,
        )

        # Create sample logs
        for i in range(5):
            DiscoveryLog.objects.create(
                task=self.task,
                account=self.account,
                level='info',
                category='resource_created',
                message=f'Created ENI eni-{i:04d}',
                resource_type='eni',
                resource_id=f'eni-{i:04d}',
                region='us-east-1',
            )
        DiscoveryLog.objects.create(
            task=self.task,
            account=self.account,
            level='warning',
            category='ec2_link_preserved',
            message='EC2 not found for ENI eni-warn',
            resource_type='eni',
            resource_id='eni-warn',
            region='us-east-1',
        )
        DiscoveryLog.objects.create(
            task=self.task,
            account=self.account,
            level='error',
            category='account_error',
            message='Access denied',
            region='us-west-2',
        )

    def test_list_logs(self):
        response = self.client.get('/api/discovery-logs/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 7)

    def test_filter_by_level(self):
        response = self.client.get('/api/discovery-logs/', {'level': 'warning'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)

    def test_filter_by_category(self):
        response = self.client.get('/api/discovery-logs/', {'category': 'resource_created'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 5)

    def test_filter_by_resource_type(self):
        response = self.client.get('/api/discovery-logs/', {'resource_type': 'eni'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 6)

    def test_filter_by_region(self):
        response = self.client.get('/api/discovery-logs/', {'region': 'us-west-2'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)

    def test_search_by_message(self):
        response = self.client.get('/api/discovery-logs/', {'search': 'Access denied'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)

    def test_search_by_resource_id(self):
        response = self.client.get('/api/discovery-logs/', {'search': 'eni-0002'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)

    def test_unauthenticated_returns_401_or_403(self):
        client = APIClient()
        response = client.get('/api/discovery-logs/')
        self.assertIn(response.status_code, [401, 403])

    def test_task_logs_action(self):
        response = self.client.get(f'/api/discovery-tasks/{self.task.id}/logs/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 7)

    def test_task_logs_action_filter_by_level(self):
        response = self.client.get(f'/api/discovery-tasks/{self.task.id}/logs/', {'level': 'error'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['count'], 1)


class DiscoveryLogsFrontendViewTest(TestCase):
    """Tests for the discovery_logs_view frontend page."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='testpass123')
        self.client.login(username='testuser', password='testpass123')

        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True,
        )
        self.task = DiscoveryTask.objects.create(
            task_type='single',
            status='success',
            account=self.account,
            regions=['us-east-1'],
            initiated_by=self.user,
        )

        # Create sample logs
        DiscoveryLog.objects.create(
            task=self.task, account=self.account,
            level='info', category='resource_created',
            message='Created VPC vpc-test', resource_type='vpc',
            resource_id='vpc-test', region='us-east-1',
        )
        DiscoveryLog.objects.create(
            task=self.task, account=self.account,
            level='warning', category='ec2_link_preserved',
            message='EC2 not found', resource_type='eni',
            resource_id='eni-test', region='us-east-1',
        )

    def test_discovery_logs_page_loads(self):
        response = self.client.get(reverse('discovery_logs'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'resources/discovery_logs.html')

    def test_discovery_logs_page_contains_log_entries(self):
        response = self.client.get(reverse('discovery_logs'))
        self.assertContains(response, 'Created VPC vpc-test')
        self.assertContains(response, 'EC2 not found')

    def test_discovery_logs_filter_by_level(self):
        response = self.client.get(reverse('discovery_logs'), {'level': 'warning'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'EC2 not found')
        self.assertNotContains(response, 'Created VPC vpc-test')

    def test_discovery_logs_filter_by_category(self):
        response = self.client.get(reverse('discovery_logs'), {'category': 'resource_created'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Created VPC vpc-test')
        self.assertNotContains(response, 'EC2 not found')

    def test_discovery_logs_filter_by_account(self):
        response = self.client.get(reverse('discovery_logs'), {'account': '123456789012'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Created VPC vpc-test')

    def test_discovery_logs_search(self):
        response = self.client.get(reverse('discovery_logs'), {'search': 'vpc-test'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Created VPC vpc-test')

    def test_discovery_logs_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse('discovery_logs'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('login', response.url)

    def test_discovery_logs_context_variables(self):
        response = self.client.get(reverse('discovery_logs'))
        self.assertIn('logs', response.context)
        self.assertIn('accounts', response.context)
        self.assertIn('categories', response.context)
        self.assertIn('resource_types', response.context)


class TaskDetailWithLogsTest(TestCase):
    """Tests for task detail view including logs section."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_superuser(
            username='admin', password='testpass123'
        )
        self.client.login(username='admin', password='testpass123')

        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True,
        )
        self.task = DiscoveryTask.objects.create(
            task_type='single',
            status='success',
            account=self.account,
            regions=['us-east-1'],
            initiated_by=self.user,
        )

        DiscoveryLog.objects.create(
            task=self.task, account=self.account,
            level='info', category='resource_created',
            message='Created ENI eni-test',
            resource_type='eni', resource_id='eni-test', region='us-east-1',
        )
        DiscoveryLog.objects.create(
            task=self.task, account=self.account,
            level='warning', category='ec2_link_preserved',
            message='EC2 link preserved for eni-warn',
            resource_type='eni', resource_id='eni-warn', region='us-east-1',
        )

    def test_task_detail_includes_logs(self):
        response = self.client.get(reverse('task_detail', args=[self.task.id]))
        self.assertEqual(response.status_code, 200)
        self.assertIn('logs', response.context)
        self.assertEqual(len(response.context['logs']), 2)

    def test_task_detail_log_counts(self):
        response = self.client.get(reverse('task_detail', args=[self.task.id]))
        self.assertEqual(response.context['log_counts']['info'], 1)
        self.assertEqual(response.context['log_counts']['warning'], 1)
        self.assertEqual(response.context['log_counts']['error'], 0)

    def test_task_detail_filter_logs_by_level(self):
        response = self.client.get(
            reverse('task_detail', args=[self.task.id]),
            {'log_level': 'warning'}
        )
        self.assertEqual(response.status_code, 200)
        logs = response.context['logs']
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].level, 'warning')

    def test_task_detail_renders_logs_section(self):
        response = self.client.get(reverse('task_detail', args=[self.task.id]))
        self.assertContains(response, 'Discovery Logs')
        self.assertContains(response, 'Created ENI eni-test')


class SaveResourcesEC2PreservationTest(TestCase):
    """Tests for the ec2_instance preservation bug fix in _save_resources."""

    def setUp(self):
        self.account = AWSAccount.objects.create(
            account_id='111111111111',
            account_name='VPC Owner',
            is_active=True,
        )
        self.sharing_account = AWSAccount.objects.create(
            account_id='222222222222',
            account_name='Shared VPC User',
            is_active=True,
        )

        # Create VPC, subnet, and EC2 as if the VPC owner polled first
        self.vpc = VPC.objects.create(
            vpc_id='vpc-shared',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='111111111111',
        )
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-shared',
            vpc=self.vpc,
            name='Shared Subnet',
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account='111111111111',
        )
        self.ec2_instance = EC2Instance.objects.create(
            instance_id='i-owner123',
            vpc=self.vpc,
            subnet=self.subnet,
            name='Owner Instance',
            instance_type='t3.micro',
            state='running',
            availability_zone='us-east-1a',
            region='us-east-1',
            owner_account='111111111111',
        )
        # ENI linked to the EC2 instance (set by VPC owner's poll)
        self.eni = ENI.objects.create(
            eni_id='eni-shared',
            subnet=self.subnet,
            ec2_instance=self.ec2_instance,
            name='Shared ENI',
            description='ENI in shared VPC',
            interface_type='interface',
            status='in-use',
            mac_address='00:11:22:33:44:55',
            private_ip_address='10.0.1.10',
            owner_account='111111111111',
        )

    def test_ec2_link_preserved_when_cross_account_poll(self):
        """Test that ec2_instance link is preserved when sharing account polls
        and cannot see the EC2 instance (cross-account scenario).

        The attached_resource_id references an EC2 that doesn't exist in the DB
        (simulating that the owning account hasn't polled yet or it was removed).
        The ENI's existing ec2_instance link should be preserved.
        """
        from resources.tasks import _save_resources

        # Simulate the sharing account polling - ENI references an EC2 that
        # doesn't exist in our DB (cross-account, not yet discovered)
        results = {
            'regions': {
                'us-east-1': {
                    'vpcs': [],
                    'subnets': [],
                    'security_groups': [],
                    'ec2_instances': [],
                    'enis': [{
                        'eni_id': 'eni-shared',
                        'subnet_id': 'subnet-shared',
                        'name': 'Shared ENI',
                        'description': 'ENI in shared VPC',
                        'interface_type': 'interface',
                        'status': 'in-use',
                        'mac_address': '00:11:22:33:44:55',
                        'private_ip_address': '10.0.1.10',
                        'public_ip_address': '',
                        'attached_resource_id': 'i-crossaccount999',
                        'attached_resource_type': 'instance',
                        'owner_id': '111111111111',
                        'tags': {},
                        'secondary_ips': [],
                        'security_group_ids': [],
                    }],
                }
            }
        }

        _save_resources(self.sharing_account, results)

        # The ec2_instance link should be PRESERVED (not cleared to None)
        self.eni.refresh_from_db()
        self.assertIsNotNone(self.eni.ec2_instance)
        self.assertEqual(self.eni.ec2_instance.instance_id, 'i-owner123')

    def test_ec2_link_set_when_ec2_exists(self):
        """Test that ec2_instance link is correctly set when EC2 exists."""
        from resources.tasks import _save_resources

        # Create a new EC2 instance that the polling account CAN see
        new_ec2 = EC2Instance.objects.create(
            instance_id='i-new123',
            vpc=self.vpc,
            subnet=self.subnet,
            name='New Instance',
            instance_type='t3.micro',
            state='running',
            availability_zone='us-east-1a',
            region='us-east-1',
            owner_account='111111111111',
        )

        results = {
            'regions': {
                'us-east-1': {
                    'vpcs': [],
                    'subnets': [],
                    'security_groups': [],
                    'ec2_instances': [],
                    'enis': [{
                        'eni_id': 'eni-shared',
                        'subnet_id': 'subnet-shared',
                        'name': 'Shared ENI',
                        'description': 'ENI in shared VPC',
                        'interface_type': 'interface',
                        'status': 'in-use',
                        'mac_address': '00:11:22:33:44:55',
                        'private_ip_address': '10.0.1.10',
                        'public_ip_address': '',
                        'attached_resource_id': 'i-new123',
                        'attached_resource_type': 'instance',
                        'owner_id': '111111111111',
                        'tags': {},
                        'secondary_ips': [],
                        'security_group_ids': [],
                    }],
                }
            }
        }

        _save_resources(self.account, results)

        self.eni.refresh_from_db()
        self.assertIsNotNone(self.eni.ec2_instance)
        self.assertEqual(self.eni.ec2_instance.instance_id, 'i-new123')

    def test_ec2_link_preserved_generates_warning_log(self):
        """Test that a warning log is generated when EC2 link can't be resolved."""
        from resources.tasks import _save_resources

        task = DiscoveryTask.objects.create(
            task_type='single',
            status='running',
            account=self.sharing_account,
            regions=['us-east-1'],
        )

        results = {
            'regions': {
                'us-east-1': {
                    'vpcs': [],
                    'subnets': [],
                    'security_groups': [],
                    'ec2_instances': [],
                    'enis': [{
                        'eni_id': 'eni-shared',
                        'subnet_id': 'subnet-shared',
                        'name': 'Shared ENI',
                        'description': 'ENI in shared VPC',
                        'interface_type': 'interface',
                        'status': 'in-use',
                        'mac_address': '00:11:22:33:44:55',
                        'private_ip_address': '10.0.1.10',
                        'public_ip_address': '',
                        'attached_resource_id': 'i-crossaccount999',
                        'attached_resource_type': 'instance',
                        'owner_id': '111111111111',
                        'tags': {},
                        'secondary_ips': [],
                        'security_group_ids': [],
                    }],
                }
            }
        }

        _save_resources(self.sharing_account, results, task_record=task)

        # Should have a warning log about preserved EC2 link
        warning_logs = DiscoveryLog.objects.filter(
            task=task,
            level='warning',
            category='ec2_link_preserved',
        )
        self.assertEqual(warning_logs.count(), 1)
        self.assertIn('i-crossaccount999', warning_logs.first().message)

    def test_save_resources_creates_info_logs(self):
        """Test that _save_resources creates info-level logs for resources."""
        from resources.tasks import _save_resources

        task = DiscoveryTask.objects.create(
            task_type='single',
            status='running',
            account=self.account,
            regions=['us-east-1'],
        )

        results = {
            'regions': {
                'us-east-1': {
                    'vpcs': [{
                        'vpc_id': 'vpc-new',
                        'cidr_block': '172.16.0.0/16',
                        'owner_id': '111111111111',
                        'is_default': False,
                        'state': 'available',
                        'tags': {},
                    }],
                    'subnets': [],
                    'security_groups': [],
                    'ec2_instances': [],
                    'enis': [],
                }
            }
        }

        _save_resources(self.account, results, task_record=task)

        info_logs = DiscoveryLog.objects.filter(task=task, level='info')
        self.assertGreaterEqual(info_logs.count(), 1)
        vpc_log = info_logs.filter(resource_type='vpc').first()
        self.assertIsNotNone(vpc_log)
        self.assertIn('vpc-new', vpc_log.message)

    def test_save_resources_without_task_record(self):
        """Test that _save_resources works without task_record (logs have null task)."""
        from resources.tasks import _save_resources

        results = {
            'regions': {
                'us-east-1': {
                    'vpcs': [{
                        'vpc_id': 'vpc-notask',
                        'cidr_block': '172.16.0.0/16',
                        'owner_id': '111111111111',
                        'is_default': False,
                        'state': 'available',
                        'tags': {},
                    }],
                    'subnets': [],
                    'security_groups': [],
                    'ec2_instances': [],
                    'enis': [],
                }
            }
        }

        _save_resources(self.account, results)

        # Logs should still be created with null task
        logs = DiscoveryLog.objects.filter(resource_id='vpc-notask')
        self.assertEqual(logs.count(), 1)
        self.assertIsNone(logs.first().task)
