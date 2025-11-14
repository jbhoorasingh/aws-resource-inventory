"""
Tests for Django management commands.
"""
from django.test import TestCase
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone
from io import StringIO
from unittest.mock import Mock, MagicMock, patch
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance
)


class DiscoverAWSResourcesCommandTest(TestCase):
    """Tests for discover_aws_resources management command."""

    def setUp(self):
        """Set up test data."""
        self.test_account_id = '123456789012'
        self.test_access_key = 'AKIAIOSFODNN7EXAMPLE'
        self.test_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        self.test_session_token = 'test-session-token'
        self.test_regions = ['us-east-1', 'us-west-2']

        # Mock discovery results
        self.mock_discovery_results = {
            'account_id': self.test_account_id,
            'regions': {
                'us-east-1': {
                    'vpcs': [
                        {
                            'vpc_id': 'vpc-12345678',
                            'cidr_block': '10.0.0.0/16',
                            'state': 'available',
                            'is_default': False,
                            'owner_id': self.test_account_id,
                            'tags': {'Name': 'Test VPC'}
                        }
                    ],
                    'subnets': [
                        {
                            'subnet_id': 'subnet-12345678',
                            'vpc_id': 'vpc-12345678',
                            'cidr_block': '10.0.1.0/24',
                            'availability_zone': 'us-east-1a',
                            'state': 'available',
                            'owner_id': self.test_account_id,
                            'tags': {'Name': 'Test Subnet'}
                        }
                    ],
                    'security_groups': [
                        {
                            'sg_id': 'sg-12345678',
                            'vpc_id': 'vpc-12345678',
                            'name': 'test-sg',
                            'description': 'Test security group',
                            'region': 'us-east-1',
                            'rules': [
                                {
                                    'rule_type': 'ingress',
                                    'protocol': 'tcp',
                                    'from_port': 80,
                                    'to_port': 80,
                                    'source_type': 'cidr',
                                    'source_value': '0.0.0.0/0',
                                    'description': 'Allow HTTP'
                                }
                            ],
                            'tags': {}
                        }
                    ],
                    'ec2_instances': [
                        {
                            'instance_id': 'i-12345678',
                            'vpc_id': 'vpc-12345678',
                            'subnet_id': 'subnet-12345678',
                            'name': 'Test Instance',
                            'instance_type': 't3.micro',
                            'state': 'running',
                            'availability_zone': 'us-east-1a',
                            'private_ip_address': '10.0.1.50',
                            'public_ip_address': None,
                            'platform': 'linux',
                            'launch_time': timezone.now(),
                            'owner_id': self.test_account_id,
                            'tags': {}
                        }
                    ],
                    'enis': [
                        {
                            'eni_id': 'eni-12345678',
                            'subnet_id': 'subnet-12345678',
                            'name': 'Test ENI',
                            'description': 'Test ENI description',
                            'interface_type': 'interface',
                            'status': 'in-use',
                            'mac_address': '02:00:00:00:00:01',
                            'private_ip_address': '10.0.1.10',
                            'public_ip_address': None,
                            'attached_resource_id': 'i-12345678',
                            'attached_resource_type': 'instance',
                            'owner_id': self.test_account_id,
                            'secondary_ips': ['10.0.1.11'],
                            'security_group_ids': ['sg-12345678'],
                            'tags': {}
                        }
                    ]
                }
            },
            'summary': {
                'total_vpcs': 1,
                'total_subnets': 1,
                'total_security_groups': 1,
                'total_ec2_instances': 1,
                'total_enis': 1
            }
        }

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_dry_run_mode(self, mock_discovery_class):
        """Test command in dry-run mode."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        out = StringIO()

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1',
            '--dry-run',
            stdout=out
        )

        # Verify discovery was initialized with correct credentials
        mock_discovery_class.assert_called_once_with(
            access_key_id=self.test_access_key,
            secret_access_key=self.test_secret_key,
            session_token=self.test_session_token,
            role_arn=None,
            external_id=None
        )

        # Verify account ID was verified
        mock_discovery.get_account_id.assert_called_once()

        # Verify discovery was called
        mock_discovery.discover_all_resources.assert_called_once_with(['us-east-1'])

        # Check output contains dry-run message
        output = out.getvalue()
        self.assertIn('DRY RUN MODE', output)
        self.assertIn('DISCOVERY SUMMARY', output)

        # Verify no database records were created
        self.assertEqual(AWSAccount.objects.count(), 0)
        self.assertEqual(VPC.objects.count(), 0)

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_saves_to_database(self, mock_discovery_class):
        """Test command saves resources to database."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        out = StringIO()

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1',
            '--account-name', 'Test Account',
            stdout=out
        )

        # Verify resources were saved to database
        self.assertEqual(AWSAccount.objects.count(), 1)
        self.assertEqual(VPC.objects.count(), 1)
        self.assertEqual(Subnet.objects.count(), 1)
        self.assertEqual(SecurityGroup.objects.count(), 1)
        self.assertEqual(SecurityGroupRule.objects.count(), 1)
        self.assertEqual(EC2Instance.objects.count(), 1)
        self.assertEqual(ENI.objects.count(), 1)
        self.assertEqual(ENISecondaryIP.objects.count(), 1)
        self.assertEqual(ENISecurityGroup.objects.count(), 1)

        # Verify account details
        account = AWSAccount.objects.get(account_id=self.test_account_id)
        self.assertEqual(account.account_name, 'Test Account')
        self.assertIsNotNone(account.last_polled)

        # Verify VPC details
        vpc = VPC.objects.get(vpc_id='vpc-12345678')
        self.assertEqual(vpc.cidr_block, '10.0.0.0/16')
        self.assertEqual(vpc.tags['Name'], 'Test VPC')

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_with_role_assumption(self, mock_discovery_class):
        """Test command with role assumption."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        out = StringIO()

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1',
            '--role-arn', 'arn:aws:iam::123456789012:role/TestRole',
            '--external-id', 'test-external-id',
            '--dry-run',
            stdout=out
        )

        # Verify discovery was initialized with role assumption
        mock_discovery_class.assert_called_once_with(
            access_key_id=self.test_access_key,
            secret_access_key=self.test_secret_key,
            session_token=self.test_session_token,
            role_arn='arn:aws:iam::123456789012:role/TestRole',
            external_id='test-external-id'
        )

        output = out.getvalue()
        self.assertIn('Using role assumption', output)
        self.assertIn('Successfully assumed role', output)

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_account_id_mismatch_without_role(self, mock_discovery_class):
        """Test command fails with account ID mismatch (no role assumption)."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = '999999999999'  # Different account

        with self.assertRaises(CommandError) as context:
            call_command(
                'discover_aws_resources',
                self.test_account_id,
                self.test_access_key,
                self.test_secret_key,
                self.test_session_token,
                'us-east-1',
                '--dry-run'
            )

        self.assertIn('Account ID mismatch', str(context.exception))
        self.assertIn('999999999999', str(context.exception))

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_account_id_mismatch_with_role(self, mock_discovery_class):
        """Test command fails with account ID mismatch (with role assumption)."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = '999999999999'  # Different account

        with self.assertRaises(CommandError) as context:
            call_command(
                'discover_aws_resources',
                self.test_account_id,
                self.test_access_key,
                self.test_secret_key,
                self.test_session_token,
                'us-east-1',
                '--role-arn', 'arn:aws:iam::123456789012:role/TestRole',
                '--dry-run'
            )

        self.assertIn('Role assumption failed', str(context.exception))

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_multiple_regions(self, mock_discovery_class):
        """Test command with multiple regions."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id

        # Mock results for multiple regions
        multi_region_results = {
            'account_id': self.test_account_id,
            'regions': {
                'us-east-1': {'vpcs': [], 'subnets': [], 'security_groups': [], 'ec2_instances': [], 'enis': []},
                'us-west-2': {'vpcs': [], 'subnets': [], 'security_groups': [], 'ec2_instances': [], 'enis': []}
            },
            'summary': {
                'total_vpcs': 0,
                'total_subnets': 0,
                'total_security_groups': 0,
                'total_ec2_instances': 0,
                'total_enis': 0
            }
        }
        mock_discovery.discover_all_resources.return_value = multi_region_results

        out = StringIO()

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1', 'us-west-2',
            '--dry-run',
            stdout=out
        )

        # Verify discovery was called with both regions
        mock_discovery.discover_all_resources.assert_called_once_with(['us-east-1', 'us-west-2'])

        output = out.getvalue()
        self.assertIn('us-east-1', output)
        self.assertIn('us-west-2', output)

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_updates_existing_account(self, mock_discovery_class):
        """Test command updates existing account."""
        # Create existing account
        existing_account = AWSAccount.objects.create(
            account_id=self.test_account_id,
            account_name='Old Name',
            is_active=True
        )

        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1',
            '--account-name', 'New Name'
        )

        # Verify account was updated
        existing_account.refresh_from_db()
        self.assertEqual(existing_account.account_name, 'New Name')
        self.assertIsNotNone(existing_account.last_polled)

        # Should still only have one account
        self.assertEqual(AWSAccount.objects.count(), 1)

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_handles_api_errors(self, mock_discovery_class):
        """Test command handles AWS API errors."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.side_effect = Exception("AWS API Error")

        with self.assertRaises(CommandError) as context:
            call_command(
                'discover_aws_resources',
                self.test_account_id,
                self.test_access_key,
                self.test_secret_key,
                self.test_session_token,
                'us-east-1'
            )

        self.assertIn('Discovery failed', str(context.exception))
        self.assertIn('AWS API Error', str(context.exception))

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_saves_role_arn_to_account(self, mock_discovery_class):
        """Test command saves role ARN to account."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        role_arn = 'arn:aws:iam::123456789012:role/TestRole'
        external_id = 'test-external-id'

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1',
            '--role-arn', role_arn,
            '--external-id', external_id
        )

        # Verify account has role ARN saved
        account = AWSAccount.objects.get(account_id=self.test_account_id)
        self.assertEqual(account.role_arn, role_arn)
        self.assertEqual(account.external_id, external_id)

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_updates_last_polled(self, mock_discovery_class):
        """Test command updates last_polled timestamp."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        before_time = timezone.now()

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1'
        )

        after_time = timezone.now()

        account = AWSAccount.objects.get(account_id=self.test_account_id)
        self.assertIsNotNone(account.last_polled)
        self.assertGreaterEqual(account.last_polled, before_time)
        self.assertLessEqual(account.last_polled, after_time)

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_clears_and_recreates_rules(self, mock_discovery_class):
        """Test command clears and recreates security group rules on each poll."""
        # First poll - create initial data
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1'
        )

        # Verify initial rule count
        self.assertEqual(SecurityGroupRule.objects.count(), 1)
        initial_rule = SecurityGroupRule.objects.first()
        initial_rule_id = initial_rule.id

        # Second poll - with different rules
        new_results = self.mock_discovery_results.copy()
        new_results['regions']['us-east-1']['security_groups'][0]['rules'] = [
            {
                'rule_type': 'ingress',
                'protocol': 'tcp',
                'from_port': 443,
                'to_port': 443,
                'source_type': 'cidr',
                'source_value': '0.0.0.0/0',
                'description': 'Allow HTTPS'
            },
            {
                'rule_type': 'egress',
                'protocol': '-1',
                'from_port': None,
                'to_port': None,
                'source_type': 'cidr',
                'source_value': '0.0.0.0/0',
                'description': 'Allow all outbound'
            }
        ]
        mock_discovery.discover_all_resources.return_value = new_results

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1'
        )

        # Verify old rules were deleted and new ones created
        self.assertEqual(SecurityGroupRule.objects.count(), 2)
        # Old rule should not exist anymore
        self.assertFalse(SecurityGroupRule.objects.filter(id=initial_rule_id).exists())

        # Verify new rules exist
        https_rule = SecurityGroupRule.objects.filter(from_port=443).first()
        self.assertIsNotNone(https_rule)
        self.assertEqual(https_rule.description, 'Allow HTTPS')

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_links_eni_to_ec2_instance(self, mock_discovery_class):
        """Test command properly links ENI to EC2 instance."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id
        mock_discovery.discover_all_resources.return_value = self.mock_discovery_results

        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1'
        )

        # Verify ENI is linked to EC2 instance
        eni = ENI.objects.get(eni_id='eni-12345678')
        self.assertIsNotNone(eni.ec2_instance)
        self.assertEqual(eni.ec2_instance.instance_id, 'i-12345678')
        self.assertEqual(eni.attached_resource_id, 'i-12345678')
        self.assertEqual(eni.attached_resource_type, 'instance')

    @patch('resources.management.commands.discover_aws_resources.AWSResourceDiscovery')
    def test_command_handles_missing_vpc(self, mock_discovery_class):
        """Test command handles missing VPC gracefully."""
        mock_discovery = MagicMock()
        mock_discovery_class.return_value = mock_discovery
        mock_discovery.get_account_id.return_value = self.test_account_id

        # Results with subnet referencing non-existent VPC
        bad_results = {
            'account_id': self.test_account_id,
            'regions': {
                'us-east-1': {
                    'vpcs': [],  # No VPCs
                    'subnets': [
                        {
                            'subnet_id': 'subnet-12345678',
                            'vpc_id': 'vpc-nonexistent',  # References non-existent VPC
                            'cidr_block': '10.0.1.0/24',
                            'availability_zone': 'us-east-1a',
                            'state': 'available',
                            'owner_id': self.test_account_id,
                            'tags': {}
                        }
                    ],
                    'security_groups': [],
                    'ec2_instances': [],
                    'enis': []
                }
            },
            'summary': {'total_vpcs': 0, 'total_subnets': 1, 'total_security_groups': 0, 'total_ec2_instances': 0, 'total_enis': 0}
        }
        mock_discovery.discover_all_resources.return_value = bad_results

        out = StringIO()

        # Should not raise exception, but warn
        call_command(
            'discover_aws_resources',
            self.test_account_id,
            self.test_access_key,
            self.test_secret_key,
            self.test_session_token,
            'us-east-1',
            stdout=out
        )

        output = out.getvalue()
        self.assertIn('VPC vpc-nonexistent not found', output)

        # Verify subnet was not created
        self.assertEqual(Subnet.objects.count(), 0)
