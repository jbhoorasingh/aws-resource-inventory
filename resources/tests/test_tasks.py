"""
Tests for Celery tasks including resource cleanup and scheduled polling.
"""
from unittest.mock import patch, MagicMock
from django.test import TestCase, override_settings
from django.utils import timezone
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance, DiscoveryTask
)
from resources.tasks import (
    _delete_account_enis_and_ec2,
    _cleanup_orphaned_vpcs,
    scheduled_poll_instance_role_accounts,
)


class DeleteAccountEnisAndEc2Test(TestCase):
    """Tests for _delete_account_enis_and_ec2 helper function."""

    def setUp(self):
        """Set up test data with a complete resource hierarchy."""
        self.account_id = '123456789012'
        self.other_account_id = '987654321098'

        # Create VPC for our test account
        self.vpc = VPC.objects.create(
            vpc_id='vpc-test123',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account=self.account_id,
            tags={'Name': 'Test VPC'}
        )

        # Create Subnet
        self.subnet = Subnet.objects.create(
            subnet_id='subnet-test123',
            vpc=self.vpc,
            name='Test Subnet',
            cidr_block='10.0.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account=self.account_id
        )

        # Create Security Group
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-test123',
            vpc=self.vpc,
            name='Test Security Group',
            description='Test security group'
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
            owner_account=self.account_id
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
            owner_account=self.account_id
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

        # Create resources for another account (should not be deleted)
        self.other_vpc = VPC.objects.create(
            vpc_id='vpc-other123',
            cidr_block='172.16.0.0/16',
            region='us-west-2',
            state='available',
            owner_account=self.other_account_id
        )

        self.other_subnet = Subnet.objects.create(
            subnet_id='subnet-other123',
            vpc=self.other_vpc,
            name='Other Subnet',
            cidr_block='172.16.1.0/24',
            availability_zone='us-west-2a',
            state='available',
            owner_account=self.other_account_id
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
            owner_account=self.other_account_id
        )

    def test_delete_removes_enis_and_ec2_for_account(self):
        """Test that ENIs and EC2 instances for an account are deleted."""
        # Verify resources exist before deletion
        self.assertEqual(ENI.objects.filter(owner_account=self.account_id).count(), 1)
        self.assertEqual(EC2Instance.objects.filter(owner_account=self.account_id).count(), 1)
        self.assertEqual(ENISecondaryIP.objects.count(), 1)
        self.assertEqual(ENISecurityGroup.objects.filter(eni=self.eni).count(), 1)

        # Delete resources
        result = _delete_account_enis_and_ec2(self.account_id)

        # Verify ENIs and EC2 are deleted
        self.assertEqual(ENI.objects.filter(owner_account=self.account_id).count(), 0)
        self.assertEqual(EC2Instance.objects.filter(owner_account=self.account_id).count(), 0)
        self.assertEqual(ENISecondaryIP.objects.count(), 0)
        self.assertEqual(ENISecurityGroup.objects.filter(eni=self.eni).count(), 0)

        # Verify counts in result
        self.assertEqual(result['enis'], 1)
        self.assertEqual(result['ec2_instances'], 1)
        self.assertEqual(result['eni_secondary_ips'], 1)
        self.assertEqual(result['eni_security_groups'], 1)

    def test_delete_preserves_vpcs_subnets_sgs(self):
        """Test that VPCs, Subnets, and Security Groups are preserved."""
        # Delete ENIs and EC2
        _delete_account_enis_and_ec2(self.account_id)

        # Verify VPCs, Subnets, and Security Groups still exist
        self.assertTrue(VPC.objects.filter(vpc_id='vpc-test123').exists())
        self.assertTrue(Subnet.objects.filter(subnet_id='subnet-test123').exists())
        self.assertTrue(SecurityGroup.objects.filter(sg_id='sg-test123').exists())
        self.assertTrue(SecurityGroupRule.objects.filter(security_group=self.sg).exists())

    def test_delete_does_not_affect_other_accounts(self):
        """Test that resources from other accounts are not deleted."""
        # Delete resources for our test account
        _delete_account_enis_and_ec2(self.account_id)

        # Verify other account's resources still exist
        self.assertTrue(VPC.objects.filter(vpc_id='vpc-other123').exists())
        self.assertTrue(ENI.objects.filter(eni_id='eni-other123').exists())
        self.assertEqual(ENI.objects.filter(owner_account=self.other_account_id).count(), 1)

    def test_delete_nonexistent_account_returns_zeros(self):
        """Test deleting resources for non-existent account returns zero counts."""
        result = _delete_account_enis_and_ec2('000000000000')
        self.assertEqual(result['enis'], 0)
        self.assertEqual(result['ec2_instances'], 0)


class CleanupOrphanedVpcsTest(TestCase):
    """Tests for _cleanup_orphaned_vpcs helper function."""

    def setUp(self):
        """Set up test data."""
        self.account_id = '123456789012'

        # Create VPC that will be in discovery results
        self.active_vpc = VPC.objects.create(
            vpc_id='vpc-active',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account=self.account_id
        )

        # Create orphaned VPC (not in discovery, no ENIs)
        self.orphaned_vpc = VPC.objects.create(
            vpc_id='vpc-orphaned',
            cidr_block='10.1.0.0/16',
            region='us-east-1',
            state='available',
            owner_account=self.account_id
        )

        self.orphaned_subnet = Subnet.objects.create(
            subnet_id='subnet-orphaned',
            vpc=self.orphaned_vpc,
            name='Orphaned Subnet',
            cidr_block='10.1.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account=self.account_id
        )

        self.orphaned_sg = SecurityGroup.objects.create(
            sg_id='sg-orphaned',
            vpc=self.orphaned_vpc,
            name='Orphaned SG',
            description='Orphaned security group'
        )

        # Create VPC with remaining ENIs (should not be deleted)
        self.vpc_with_enis = VPC.objects.create(
            vpc_id='vpc-with-enis',
            cidr_block='10.2.0.0/16',
            region='us-east-1',
            state='available',
            owner_account=self.account_id
        )

        self.subnet_with_enis = Subnet.objects.create(
            subnet_id='subnet-with-enis',
            vpc=self.vpc_with_enis,
            name='Subnet with ENIs',
            cidr_block='10.2.1.0/24',
            availability_zone='us-east-1a',
            state='available',
            owner_account=self.account_id
        )

        # ENI from a different account using shared VPC
        self.shared_eni = ENI.objects.create(
            eni_id='eni-shared',
            subnet=self.subnet_with_enis,
            name='Shared ENI',
            description='ENI from different account in shared VPC',
            interface_type='interface',
            status='in-use',
            mac_address='00:11:22:33:44:77',
            private_ip_address='10.2.1.10',
            owner_account='999999999999'  # Different account
        )

    def test_cleanup_deletes_orphaned_vpc(self):
        """Test that orphaned VPCs without ENIs are deleted."""
        # Active VPC is in discovery results
        discovered_vpc_ids = {'vpc-active'}

        result = _cleanup_orphaned_vpcs(self.account_id, discovered_vpc_ids)

        # Orphaned VPC should be deleted
        self.assertFalse(VPC.objects.filter(vpc_id='vpc-orphaned').exists())
        self.assertFalse(Subnet.objects.filter(subnet_id='subnet-orphaned').exists())
        self.assertFalse(SecurityGroup.objects.filter(sg_id='sg-orphaned').exists())

        # Counts should reflect deletion
        self.assertEqual(result['vpcs'], 1)
        self.assertEqual(result['subnets'], 1)
        self.assertEqual(result['security_groups'], 1)

    def test_cleanup_preserves_active_vpc(self):
        """Test that VPCs in discovery results are preserved."""
        discovered_vpc_ids = {'vpc-active', 'vpc-with-enis'}

        _cleanup_orphaned_vpcs(self.account_id, discovered_vpc_ids)

        # Active VPC should still exist
        self.assertTrue(VPC.objects.filter(vpc_id='vpc-active').exists())

    def test_cleanup_preserves_vpc_with_remaining_enis(self):
        """Test that VPCs with remaining ENIs are preserved even if not in discovery."""
        # vpc-with-enis is NOT in discovery results but has ENIs
        discovered_vpc_ids = {'vpc-active'}

        _cleanup_orphaned_vpcs(self.account_id, discovered_vpc_ids)

        # VPC with ENIs should still exist
        self.assertTrue(VPC.objects.filter(vpc_id='vpc-with-enis').exists())
        self.assertTrue(ENI.objects.filter(eni_id='eni-shared').exists())

    def test_cleanup_with_no_orphans(self):
        """Test cleanup when all VPCs are in discovery results."""
        discovered_vpc_ids = {'vpc-active', 'vpc-orphaned', 'vpc-with-enis'}

        result = _cleanup_orphaned_vpcs(self.account_id, discovered_vpc_ids)

        # Nothing should be deleted
        self.assertEqual(result['vpcs'], 0)
        self.assertEqual(VPC.objects.filter(owner_account=self.account_id).count(), 3)


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

        # Second eligible account
        self.eligible_account2 = AWSAccount.objects.create(
            account_id='555555555555',
            account_name='Second Eligible Account',
            auth_method='instance_role',
            default_role_name='TestRole',
            default_regions=['us-east-1'],
            is_active=True
        )

    def test_eligible_accounts_query(self):
        """Test that the eligibility query returns correct accounts."""
        # This is the same query used in the task
        eligible = AWSAccount.objects.filter(
            auth_method='instance_role',
            is_active=True,
        ).exclude(
            default_regions=[]
        ).exclude(
            default_role_name=''
        )

        # Should only include 2 accounts
        self.assertEqual(eligible.count(), 2)
        account_ids = list(eligible.values_list('account_id', flat=True))
        self.assertIn('123456789012', account_ids)
        self.assertIn('555555555555', account_ids)

        # Should not include ineligible accounts
        self.assertNotIn('111111111111', account_ids)  # credentials auth
        self.assertNotIn('222222222222', account_ids)  # inactive
        self.assertNotIn('333333333333', account_ids)  # no regions
        self.assertNotIn('444444444444', account_ids)  # no role name

    @override_settings(
        SCHEDULED_POLLING_ENABLED=True,
        SCHEDULED_POLLING_MAX_CONCURRENT=2,
        SCHEDULED_POLLING_STAGGER_SECONDS=30
    )
    @patch('resources.tasks.repoll_account_with_instance_role.apply_async')
    def test_task_queues_eligible_accounts(self, mock_apply_async):
        """Test that the task queues eligible accounts with staggered countdowns."""
        # Import and call the task
        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()

        # Should queue exactly 2 accounts
        self.assertEqual(result['status'], 'started')
        self.assertEqual(result['total_accounts'], 2)
        self.assertEqual(result['queued'], 2)
        self.assertEqual(mock_apply_async.call_count, 2)

        # Verify countdowns in apply_async calls
        calls = mock_apply_async.call_args_list
        countdowns = [call[1]['countdown'] for call in calls]
        self.assertIn(0, countdowns)
        self.assertIn(30, countdowns)

    @override_settings(
        SCHEDULED_POLLING_ENABLED=True,
        SCHEDULED_POLLING_MAX_CONCURRENT=2,
        SCHEDULED_POLLING_STAGGER_SECONDS=30
    )
    @patch('resources.tasks.repoll_account_with_instance_role.apply_async')
    def test_task_creates_discovery_tasks(self, mock_apply_async):
        """Test that DiscoveryTask records are created for tracking."""
        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()

        # Verify parent task was created
        parent_task = DiscoveryTask.objects.get(id=result['parent_task_id'])
        self.assertEqual(parent_task.task_type, 'bulk')
        self.assertEqual(parent_task.status, 'running')
        self.assertEqual(parent_task.total_accounts, 2)

        # Verify child tasks were created
        child_tasks = DiscoveryTask.objects.filter(parent_task=parent_task)
        self.assertEqual(child_tasks.count(), 2)

    @override_settings(SCHEDULED_POLLING_ENABLED=False)
    def test_task_disabled_returns_disabled_status(self):
        """Test task returns disabled status when polling is disabled."""
        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()
        self.assertEqual(result['status'], 'disabled')

    def test_task_no_eligible_accounts_returns_skipped(self):
        """Test task returns skipped when no accounts are eligible."""
        # Delete all instance_role accounts
        AWSAccount.objects.filter(auth_method='instance_role').delete()

        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()
        self.assertEqual(result['status'], 'skipped')

    @override_settings(
        SCHEDULED_POLLING_ENABLED=True,
        SCHEDULED_POLLING_MAX_CONCURRENT=1,
        SCHEDULED_POLLING_STAGGER_SECONDS=60
    )
    @patch('resources.tasks.repoll_account_with_instance_role.apply_async')
    def test_rate_limiting_configuration(self, mock_apply_async):
        """Test that rate limiting respects configuration."""
        result = scheduled_poll_instance_role_accounts.apply(throw=True).get()

        # With max_concurrent=1 and stagger=60, countdowns should be 0 and 60
        calls = mock_apply_async.call_args_list
        countdowns = sorted([call[1]['countdown'] for call in calls])
        self.assertEqual(countdowns, [0, 60])
