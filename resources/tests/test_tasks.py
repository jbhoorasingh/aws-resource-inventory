"""
Tests for Celery tasks including soft delete resource cleanup and scheduled polling.
"""
from datetime import timedelta
from unittest.mock import patch, MagicMock
from celery.exceptions import SoftTimeLimitExceeded
from django.test import TestCase, override_settings
from django.utils import timezone
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance, DiscoveryTask
)
from resources.tasks import (
    _mark_resources_for_cleanup,
    _extract_discovered_ids,
    _get_polling_order,
    repoll_account_with_instance_role,
    scheduled_poll_instance_role_accounts,
    check_stuck_tasks,
    cleanup_old_tasks,
    hard_delete_old_soft_deleted_resources,
    MISSED_POLLS_THRESHOLD,
    TASK_TIMEOUT_HOURS,
    TASK_RETENTION_DAYS,
    SOFT_DELETE_RETENTION_DAYS,
)


class MarkResourcesForCleanupTest(TestCase):
    """Tests for _mark_resources_for_cleanup helper function (soft delete)."""

    def setUp(self):
        """Set up test data with a complete resource hierarchy."""
        self.account_id = '123456789012'
        self.other_account_id = '987654321098'
        self.now = timezone.now()

        # Create VPC for our test account
        self.vpc = VPC.objects.create(
            vpc_id='vpc-test123',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account=self.account_id,
            tags={'Name': 'Test VPC'},
            last_seen_at=self.now,
        )

        # Create Subnet
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-test123',
            vpc=self.vpc,
            name='Test Subnet',
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account=self.account_id,
            last_seen_at=self.now,
        )

        # Create Security Group
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-test123',
            vpc=self.vpc,
            name='Test Security Group',
            description='Test security group',
            last_seen_at=self.now,
        )

        # Create Security Group Rule
        self.sg_rule = SecurityGroupRule.objects.create(
            security_group=self.sg,
            rule_type='ingress',
            protocol='tcp',
            from_port=443,
            to_port=443,
            source_type='cidr',
            source_value='0.0.0.0/0',
            description='HTTPS'
        )

        # Create EC2 Instance
        self.ec2_instance = EC2Instance.objects.create(
            instance_id='i-test123',
            vpc=self.vpc,
            subnet=self.subnet,
            name='Test Instance',
            instance_type='t3.micro',
            state='running',
            availability_zone='us-east-1a',
            region='us-east-1',
            owner_account=self.account_id,
            last_seen_at=self.now,
        )

        # Create ENI
        self.eni = ENI.objects.create(
            eni_id='eni-test123',
            subnet=self.subnet,
            ec2_instance=self.ec2_instance,
            name='Test ENI',
            description='Test ENI',
            interface_type='interface',
            status='in-use',
            mac_address='00:11:22:33:44:55',
            private_ip_address='10.0.1.10',
            owner_account=self.account_id,
            last_seen_at=self.now,
        )

        # Create Secondary IP
        self.secondary_ip = ENISecondaryIP.objects.create(
            eni=self.eni,
            ip_address='10.0.1.11'
        )

        # Create ENI-SecurityGroup relationship
        self.eni_sg = ENISecurityGroup.objects.create(
            eni=self.eni,
            security_group=self.sg
        )

        # Create resources for another account (should not be affected)
        self.other_vpc = VPC.objects.create(
            vpc_id='vpc-other123',
            cidr_block='172.16.0.0/16',
            region='us-west-2',
            state='available',
            owner_account=self.other_account_id,
            last_seen_at=self.now,
        )

        self.other_subnet = Subnet.objects.create(
            subnet_id='subnet-other123',
            vpc=self.other_vpc,
            name='Other Subnet',
            cidr_block='172.16.1.0/24',
            availability_zone='us-west-2a',
            state='available',
            owner_account=self.other_account_id,
            last_seen_at=self.now,
        )

        self.other_eni = ENI.objects.create(
            eni_id='eni-other123',
            subnet=self.other_subnet,
            name='Other ENI',
            description='Other ENI',
            interface_type='interface',
            status='available',
            mac_address='00:11:22:33:44:66',
            private_ip_address='172.16.1.10',
            owner_account=self.other_account_id,
            last_seen_at=self.now,
        )

    def test_mark_seen_resources_resets_missed_polls(self):
        """Test that seen resources have missed_polls reset to 0."""
        # Set up ENI with missed polls
        self.eni.missed_polls = 2
        self.eni.save()

        # Call with the ENI in discovered IDs
        discovered_ids = {
            'eni_ids': ['eni-test123'],
            'ec2_ids': ['i-test123'],
            'vpc_ids': ['vpc-test123'],
            'subnet_ids': ['subnet-test123'],
            'sg_ids': ['sg-test123'],
        }

        result = _mark_resources_for_cleanup(self.account_id, discovered_ids)

        # ENI should have missed_polls reset
        self.eni.refresh_from_db()
        self.assertEqual(self.eni.missed_polls, 0)
        self.assertIsNotNone(self.eni.last_seen_at)
        self.assertIsNone(self.eni.deleted_at)
        self.assertEqual(result['enis_seen'], 1)

    def test_mark_unseen_resources_increments_missed_polls(self):
        """Test that unseen resources have missed_polls incremented."""
        # Call with empty discovered IDs (resource not seen)
        discovered_ids = {
            'eni_ids': [],
            'ec2_ids': [],
            'vpc_ids': [],
            'subnet_ids': [],
            'sg_ids': [],
        }

        result = _mark_resources_for_cleanup(self.account_id, discovered_ids)

        # ENI should have missed_polls incremented
        self.eni.refresh_from_db()
        self.assertEqual(self.eni.missed_polls, 1)
        self.assertEqual(result['enis_missed'], 1)

    def test_soft_delete_after_threshold_missed_polls(self):
        """Test that resources are soft-deleted after threshold missed polls."""
        # Set ENI to threshold - 1 missed polls
        self.eni.missed_polls = MISSED_POLLS_THRESHOLD - 1
        self.eni.save()

        # Call with empty discovered IDs
        discovered_ids = {
            'eni_ids': [],
            'ec2_ids': [],
            'vpc_ids': [],
            'subnet_ids': [],
            'sg_ids': [],
        }

        result = _mark_resources_for_cleanup(self.account_id, discovered_ids)

        # ENI should now be soft-deleted (missed_polls >= threshold)
        self.eni.refresh_from_db()
        self.assertEqual(self.eni.missed_polls, MISSED_POLLS_THRESHOLD)
        self.assertIsNotNone(self.eni.deleted_at)
        self.assertEqual(result['enis_soft_deleted'], 1)

    def test_resurrect_soft_deleted_resource_when_seen(self):
        """Test that a soft-deleted resource is resurrected when seen again."""
        # Soft delete the ENI
        self.eni.deleted_at = timezone.now()
        self.eni.missed_polls = 5
        self.eni.save()

        # Call with the ENI in discovered IDs
        discovered_ids = {
            'eni_ids': ['eni-test123'],
            'ec2_ids': [],
            'vpc_ids': [],
            'subnet_ids': [],
            'sg_ids': [],
        }

        result = _mark_resources_for_cleanup(self.account_id, discovered_ids)

        # ENI should be resurrected
        self.eni.refresh_from_db()
        self.assertIsNone(self.eni.deleted_at)
        self.assertEqual(self.eni.missed_polls, 0)
        self.assertEqual(result['enis_seen'], 1)

    def test_does_not_affect_other_accounts(self):
        """Test that resources from other accounts are not affected."""
        discovered_ids = {
            'eni_ids': [],
            'ec2_ids': [],
            'vpc_ids': [],
            'subnet_ids': [],
            'sg_ids': [],
        }

        _mark_resources_for_cleanup(self.account_id, discovered_ids)

        # Other account's resources should be unaffected
        self.other_eni.refresh_from_db()
        self.assertEqual(self.other_eni.missed_polls, 0)
        self.assertIsNone(self.other_eni.deleted_at)


class GetPollingOrderTest(TestCase):
    """Tests for _get_polling_order helper function."""

    def setUp(self):
        """Set up test accounts and shared VPC scenario."""
        # VPC-owning account
        self.vpc_owner = AWSAccount.objects.create(
            account_id='111111111111',
            account_name='VPC Owner',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )

        # Account with resources in shared VPC
        self.shared_vpc_user = AWSAccount.objects.create(
            account_id='222222222222',
            account_name='Shared VPC User',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )

        # Standalone account (no shared resources)
        self.standalone = AWSAccount.objects.create(
            account_id='333333333333',
            account_name='Standalone',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )

        # Create shared VPC infrastructure
        self.shared_vpc = VPC.objects.create(
            vpc_id='vpc-shared',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account=self.vpc_owner.account_id
        )

        self.shared_subnet = Subnet.objects.create(
            subnet_id='subnet-shared',
            vpc=self.shared_vpc,
            name='Shared Subnet',
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account=self.vpc_owner.account_id
        )

        # ENI in shared VPC owned by different account
        self.shared_eni = ENI.objects.create(
            eni_id='eni-inshared',
            subnet=self.shared_subnet,
            name='ENI in Shared VPC',
            description='ENI owned by user in shared VPC',
            interface_type='interface',
            status='in-use',
            mac_address='00:11:22:33:44:88',
            private_ip_address='10.0.1.50',
            owner_account=self.shared_vpc_user.account_id  # Different from VPC owner
        )

    def test_vpc_owners_polled_first(self):
        """Test that VPC-owning accounts are ordered before shared VPC users."""
        accounts = [self.shared_vpc_user, self.vpc_owner, self.standalone]

        ordered = _get_polling_order(accounts)

        # VPC owner and standalone should come before shared VPC user
        user_index = next(i for i, a in enumerate(ordered) if a.account_id == '222222222222')
        owner_index = next(i for i, a in enumerate(ordered) if a.account_id == '111111111111')

        self.assertLess(owner_index, user_index)

    def test_empty_accounts_returns_empty(self):
        """Test that empty account list returns empty."""
        self.assertEqual(_get_polling_order([]), [])


class ScheduledPollInstanceRoleAccountsTest(TestCase):
    """Tests for scheduled_poll_instance_role_accounts task."""

    def setUp(self):
        """Set up test accounts."""
        # Account eligible for scheduled polling
        self.eligible_account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Eligible Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1', 'us-west-2'],
            is_active=True
        )

        # Account with credentials auth (not eligible)
        self.credentials_account = AWSAccount.objects.create(
            account_id='111111111111',
            account_name='Credentials Account',
            auth_method='credentials',
            default_regions=['us-east-1'],
            is_active=True
        )

        # Inactive instance_role account (not eligible)
        self.inactive_account = AWSAccount.objects.create(
            account_id='222222222222',
            account_name='Inactive Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=False
        )

        # Account without regions (not eligible)
        self.no_regions_account = AWSAccount.objects.create(
            account_id='333333333333',
            account_name='No Regions Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=[],
            is_active=True
        )

        # Account without role name (not eligible)
        self.no_role_account = AWSAccount.objects.create(
            account_id='444444444444',
            account_name='No Role Account',
            auth_method='instance_role',
            default_role_name='',
            default_regions=['us-east-1'],
            is_active=True
        )

        # Auto-poll disabled account (not eligible)
        self.disabled_account = AWSAccount.objects.create(
            account_id='555555555555',
            account_name='Disabled Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True,
            auto_poll_disabled=True,
            consecutive_failures=3
        )

        # Second eligible account
        self.eligible_account2 = AWSAccount.objects.create(
            account_id='666666666666',
            account_name='Second Eligible Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )

    def test_eligible_accounts_query_excludes_auto_poll_disabled(self):
        """Test that the eligibility query excludes auto_poll_disabled accounts."""
        eligible = AWSAccount.objects.filter(
            auth_method='instance_role',
            is_active=True,
            auto_poll_disabled=False,
        ).exclude(
            default_regions=[]
        ).exclude(
            default_role_name=''
        )

        # Should only include 2 accounts
        self.assertEqual(eligible.count(), 2)
        account_ids = list(eligible.values_list('account_id', flat=True))
        self.assertIn('123456789012', account_ids)
        self.assertIn('666666666666', account_ids)

        # Should not include ineligible accounts
        self.assertNotIn('555555555555', account_ids)  # auto_poll_disabled

    @override_settings(
        SCHEDULED_POLLING_ENABLED=True,
        SCHEDULED_POLLING_MAX_CONCURRENT=2,
        SCHEDULED_POLLING_STAGGER_SECONDS=30
    )
    @patch('resources.tasks.repoll_account_with_instance_role.apply_async')
    def test_task_queues_eligible_accounts(self, mock_apply_async):
        """Test that the task queues eligible accounts with staggered countdowns."""
        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()

        # Should queue exactly 2 accounts
        self.assertEqual(result['status'], 'started')
        self.assertEqual(result['total_accounts'], 2)
        self.assertEqual(result['queued'], 2)
        self.assertEqual(mock_apply_async.call_count, 2)

    @override_settings(SCHEDULED_POLLING_ENABLED=False)
    def test_task_disabled_returns_disabled_status(self):
        """Test task returns disabled status when polling is disabled."""
        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()
        self.assertEqual(result['status'], 'disabled')

    def test_task_no_eligible_accounts_returns_skipped(self):
        """Test task returns skipped when no accounts are eligible."""
        AWSAccount.objects.filter(auth_method='instance_role').delete()

        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()
        self.assertEqual(result['status'], 'skipped')


class AccountFailureTrackingTest(TestCase):
    """Tests for account failure tracking and auto-disable."""

    def setUp(self):
        """Set up test account."""
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )

    def test_record_poll_success_resets_failures(self):
        """Test that successful poll resets failure counters."""
        self.account.consecutive_failures = 2
        self.account.last_failure_reason = 'Previous error'
        self.account.save()

        self.account.record_poll_success()

        self.account.refresh_from_db()
        self.assertEqual(self.account.consecutive_failures, 0)
        self.assertEqual(self.account.last_failure_reason, '')
        self.assertFalse(self.account.auto_poll_disabled)

    def test_record_poll_failure_increments_counter(self):
        """Test that failure increments counter."""
        self.account.record_poll_failure('Test error')

        self.account.refresh_from_db()
        self.assertEqual(self.account.consecutive_failures, 1)
        self.assertEqual(self.account.last_failure_reason, 'Test error')
        self.assertFalse(self.account.auto_poll_disabled)

    def test_auto_disable_after_three_failures(self):
        """Test that account is auto-disabled after 3 consecutive failures."""
        for i in range(3):
            self.account.record_poll_failure(f'Error {i+1}')

        self.account.refresh_from_db()
        self.assertEqual(self.account.consecutive_failures, 3)
        self.assertTrue(self.account.auto_poll_disabled)

    def test_can_repoll_false_when_disabled(self):
        """Test that can_repoll returns False when auto_poll_disabled."""
        self.account.auto_poll_disabled = True
        self.account.save()

        self.assertFalse(self.account.can_repoll)


class CheckStuckTasksTest(TestCase):
    """Tests for check_stuck_tasks periodic task."""

    def setUp(self):
        """Set up test tasks."""
        self.now = timezone.now()

        # Running task that's not stuck
        self.recent_task = DiscoveryTask.objects.create(
            task_type='single',
            status='running',
        )
        # Manually set created_at (auto_now_add prevents setting during create)
        DiscoveryTask.objects.filter(id=self.recent_task.id).update(
            created_at=self.now - timedelta(hours=1)
        )
        self.recent_task.refresh_from_db()

        # Running task that's stuck (older than timeout)
        self.stuck_task = DiscoveryTask.objects.create(
            task_type='single',
            status='running',
        )
        DiscoveryTask.objects.filter(id=self.stuck_task.id).update(
            created_at=self.now - timedelta(hours=TASK_TIMEOUT_HOURS + 1)
        )
        self.stuck_task.refresh_from_db()

        # Pending task that's stuck
        self.stuck_pending = DiscoveryTask.objects.create(
            task_type='single',
            status='pending',
        )
        DiscoveryTask.objects.filter(id=self.stuck_pending.id).update(
            created_at=self.now - timedelta(hours=TASK_TIMEOUT_HOURS + 1)
        )
        self.stuck_pending.refresh_from_db()

        # Completed task (should not be affected)
        self.completed_task = DiscoveryTask.objects.create(
            task_type='single',
            status='success',
        )
        DiscoveryTask.objects.filter(id=self.completed_task.id).update(
            created_at=self.now - timedelta(hours=TASK_TIMEOUT_HOURS + 1)
        )
        self.completed_task.refresh_from_db()

    def test_marks_stuck_tasks_as_failed(self):
        """Test that stuck tasks are marked as failed."""
        result = check_stuck_tasks.apply(throw=True).get()

        self.stuck_task.refresh_from_db()
        self.stuck_pending.refresh_from_db()

        self.assertEqual(self.stuck_task.status, 'failed')
        self.assertEqual(self.stuck_pending.status, 'failed')
        self.assertIn('timed out', self.stuck_task.error_message)
        self.assertEqual(result['stuck_tasks_found'], 2)

    def test_does_not_affect_recent_tasks(self):
        """Test that recent tasks are not affected."""
        check_stuck_tasks.apply(throw=True).get()

        self.recent_task.refresh_from_db()
        self.assertEqual(self.recent_task.status, 'running')

    def test_does_not_affect_completed_tasks(self):
        """Test that completed tasks are not affected."""
        check_stuck_tasks.apply(throw=True).get()

        self.completed_task.refresh_from_db()
        self.assertEqual(self.completed_task.status, 'success')


class CleanupOldTasksTest(TestCase):
    """Tests for cleanup_old_tasks periodic task."""

    def setUp(self):
        """Set up test tasks."""
        self.now = timezone.now()

        # Recent task (should be kept)
        self.recent_task = DiscoveryTask.objects.create(
            task_type='single',
            status='success',
        )
        # Manually set created_at (auto_now_add prevents setting during create)
        DiscoveryTask.objects.filter(id=self.recent_task.id).update(
            created_at=self.now - timedelta(days=10)
        )
        self.recent_task.refresh_from_db()

        # Old task (should be deleted)
        self.old_task = DiscoveryTask.objects.create(
            task_type='single',
            status='success',
        )
        DiscoveryTask.objects.filter(id=self.old_task.id).update(
            created_at=self.now - timedelta(days=TASK_RETENTION_DAYS + 1)
        )
        self.old_task.refresh_from_db()

    def test_deletes_old_tasks(self):
        """Test that old tasks are deleted."""
        result = cleanup_old_tasks.apply(throw=True).get()

        self.assertFalse(DiscoveryTask.objects.filter(id=self.old_task.id).exists())
        self.assertTrue(DiscoveryTask.objects.filter(id=self.recent_task.id).exists())
        self.assertGreater(result['tasks_deleted'], 0)


class HardDeleteOldSoftDeletedResourcesTest(TestCase):
    """Tests for hard_delete_old_soft_deleted_resources periodic task."""

    def setUp(self):
        """Set up test resources."""
        self.now = timezone.now()
        self.old_deleted_at = self.now - timedelta(days=SOFT_DELETE_RETENTION_DAYS + 1)
        self.recent_deleted_at = self.now - timedelta(days=1)

        # Create VPC
        self.vpc = VPC.objects.create(
            vpc_id='vpc-test',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012'
        )

        # Create Subnet
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-test',
            vpc=self.vpc,
            name='Test Subnet',
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account='123456789012'
        )

        # Old soft-deleted ENI (should be hard deleted)
        self.old_deleted_eni = ENI.all_objects.create(
            eni_id='eni-old-deleted',
            subnet=self.subnet,
            name='Old Deleted ENI',
            description='Should be hard deleted',
            interface_type='interface',
            status='available',
            mac_address='00:11:22:33:44:55',
            private_ip_address='10.0.1.10',
            owner_account='123456789012',
            deleted_at=self.old_deleted_at,
            missed_polls=3
        )

        # Recently soft-deleted ENI (should be kept)
        self.recent_deleted_eni = ENI.all_objects.create(
            eni_id='eni-recent-deleted',
            subnet=self.subnet,
            name='Recent Deleted ENI',
            description='Should be kept',
            interface_type='interface',
            status='available',
            mac_address='00:11:22:33:44:66',
            private_ip_address='10.0.1.11',
            owner_account='123456789012',
            deleted_at=self.recent_deleted_at,
            missed_polls=3
        )

        # Active ENI (should be kept)
        self.active_eni = ENI.objects.create(
            eni_id='eni-active',
            subnet=self.subnet,
            name='Active ENI',
            description='Not deleted',
            interface_type='interface',
            status='in-use',
            mac_address='00:11:22:33:44:77',
            private_ip_address='10.0.1.12',
            owner_account='123456789012'
        )

    def test_hard_deletes_old_soft_deleted_resources(self):
        """Test that old soft-deleted resources are permanently deleted."""
        result = hard_delete_old_soft_deleted_resources.apply(throw=True).get()

        # Old deleted ENI should be gone
        self.assertFalse(ENI.all_objects.filter(eni_id='eni-old-deleted').exists())

        # Recent deleted ENI should still exist
        self.assertTrue(ENI.all_objects.filter(eni_id='eni-recent-deleted').exists())

        # Active ENI should still exist
        self.assertTrue(ENI.all_objects.filter(eni_id='eni-active').exists())

        self.assertGreater(result['total_deleted'], 0)


class RepollAccountTaskProgressTest(TestCase):
    """Ensure parent tasks are updated when repoll child tasks finish."""

    def setUp(self):
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Instance Role Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )
        self.parent_task = DiscoveryTask.objects.create(
            task_type='bulk',
            status='running',
            total_accounts=1
        )
        self.child_task = DiscoveryTask.objects.create(
            task_type='single',
            status='pending',
            account=self.account,
            regions=['us-east-1'],
            parent_task=self.parent_task,
            total_accounts=1
        )

    def _mock_discovery(self, mock_discovery):
        discovery_instance = MagicMock()
        mock_discovery.return_value = discovery_instance
        discovery_instance.get_account_id.return_value = self.account.account_id
        return discovery_instance

    @patch('resources.tasks.AWSResourceDiscovery')
    def test_repoll_updates_parent_progress_on_success(self, mock_discovery):
        discovery_instance = self._mock_discovery(mock_discovery)
        discovery_instance.discover_all_resources.return_value = {
            'summary': {'accounts': 1},
            'regions': {
                'us-east-1': {
                    'vpcs': [],
                    'subnets': [],
                    'security_groups': [],
                    'enis': [],
                    'ec2_instances': [],
                }
            }
        }

        result = repoll_account_with_instance_role.apply(
            kwargs={
                'task_record_id': self.child_task.id,
                'account_id': self.account.id
            },
            throw=True
        ).get()

        self.assertEqual(result['status'], 'success')
        self.parent_task.refresh_from_db()
        self.assertEqual(self.parent_task.completed_accounts, 1)
        self.assertEqual(self.parent_task.failed_accounts, 0)
        self.assertEqual(self.parent_task.status, 'success')
        self.assertIsNotNone(self.parent_task.completed_at)

    @patch('resources.tasks.AWSResourceDiscovery')
    def test_repoll_failure_updates_parent_progress(self, mock_discovery):
        discovery_instance = self._mock_discovery(mock_discovery)
        discovery_instance.discover_all_resources.side_effect = SoftTimeLimitExceeded()

        with self.assertRaises(SoftTimeLimitExceeded):
            repoll_account_with_instance_role.apply(
                kwargs={
                    'task_record_id': self.child_task.id,
                    'account_id': self.account.id
                },
                throw=True
            ).get()

        self.parent_task.refresh_from_db()
        self.assertEqual(self.parent_task.completed_accounts, 0)
        self.assertEqual(self.parent_task.failed_accounts, 1)
        self.assertEqual(self.parent_task.status, 'failed')

    @patch('resources.tasks.AWSResourceDiscovery')
    def test_repoll_failure_records_account_failure(self, mock_discovery):
        """Test that poll failure updates account failure tracking."""
        discovery_instance = self._mock_discovery(mock_discovery)
        discovery_instance.discover_all_resources.side_effect = Exception('Test error')

        repoll_account_with_instance_role.apply(
            kwargs={
                'task_record_id': self.child_task.id,
                'account_id': self.account.id
            },
            throw=True
        ).get()

        self.account.refresh_from_db()
        self.assertEqual(self.account.consecutive_failures, 1)
        self.assertEqual(self.account.last_failure_reason, 'Test error')
