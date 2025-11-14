"""
Tests for AWS resource discovery services.
"""
from django.test import TestCase
from django.conf import settings
from unittest.mock import Mock, MagicMock, patch, call
from resources.services import AWSResourceDiscovery


class AWSResourceDiscoveryInitTest(TestCase):
    """Tests for AWSResourceDiscovery initialization."""

    @patch('resources.services.boto3.Session')
    def test_initialization_with_credentials(self, mock_session):
        """Test initialization with provided credentials."""
        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret',
            session_token='test_token',
            region='us-west-2'
        )

        # Verify session was created with correct credentials
        mock_session.assert_called_with(
            aws_access_key_id='test_key',
            aws_secret_access_key='test_secret',
            aws_session_token='test_token',
            region_name='us-west-2'
        )

    @patch('resources.services.boto3.Session')
    def test_initialization_with_role_assumption(self, mock_session):
        """Test initialization with role assumption."""
        # Mock the base session
        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session

        # Mock STS client and assume_role response
        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client
        mock_sts_client.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'assumed_key',
                'SecretAccessKey': 'assumed_secret',
                'SessionToken': 'assumed_token'
            }
        }

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret',
            region='us-east-1',
            role_arn='arn:aws:iam::123456789012:role/TestRole',
            external_id='test-external-id'
        )

        # Verify assume_role was called with correct parameters
        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn='arn:aws:iam::123456789012:role/TestRole',
            RoleSessionName='AWSResourceInventoryDiscovery',
            ExternalId='test-external-id'
        )

        # Verify a new session was created with assumed credentials
        self.assertEqual(mock_session.call_count, 2)  # Base session + assumed session

    @patch('resources.services.boto3.Session')
    def test_initialization_without_external_id(self, mock_session):
        """Test role assumption without external ID."""
        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session

        mock_sts_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client
        mock_sts_client.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'assumed_key',
                'SecretAccessKey': 'assumed_secret',
                'SessionToken': 'assumed_token'
            }
        }

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret',
            role_arn='arn:aws:iam::123456789012:role/TestRole'
        )

        # Verify assume_role was called without ExternalId
        call_kwargs = mock_sts_client.assume_role.call_args[1]
        self.assertNotIn('ExternalId', call_kwargs)


class AWSResourceDiscoveryAccountIDTest(TestCase):
    """Tests for get_account_id method."""

    @patch('resources.services.boto3.Session')
    def test_get_account_id_success(self, mock_session):
        """Test successfully getting account ID."""
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.return_value = {
            'Account': '123456789012'
        }

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_sts_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        account_id = service.get_account_id()

        self.assertEqual(account_id, '123456789012')
        mock_sts_client.get_caller_identity.assert_called_once()

    @patch('resources.services.boto3.Session')
    def test_get_account_id_failure(self, mock_session):
        """Test get_account_id with API error."""
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.side_effect = Exception("API Error")

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_sts_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        with self.assertRaises(Exception):
            service.get_account_id()


class AWSResourceDiscoveryVPCTest(TestCase):
    """Tests for discover_vpcs method."""

    @patch('resources.services.boto3.Session')
    def test_discover_vpcs_success(self, mock_session):
        """Test successfully discovering VPCs."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()

        # Mock VPC response
        mock_paginator.paginate.return_value = [
            {
                'Vpcs': [
                    {
                        'VpcId': 'vpc-12345678',
                        'CidrBlock': '10.0.0.0/16',
                        'State': 'available',
                        'IsDefault': False,
                        'OwnerId': '123456789012',
                        'Tags': [{'Key': 'Name', 'Value': 'Test VPC'}]
                    }
                ]
            }
        ]

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        vpcs = service.discover_vpcs('us-east-1')

        self.assertEqual(len(vpcs), 1)
        self.assertEqual(vpcs[0]['vpc_id'], 'vpc-12345678')
        self.assertEqual(vpcs[0]['cidr_block'], '10.0.0.0/16')
        self.assertEqual(vpcs[0]['state'], 'available')
        self.assertEqual(vpcs[0]['region'], 'us-east-1')
        self.assertEqual(vpcs[0]['tags']['Name'], 'Test VPC')

    @patch('resources.services.boto3.Session')
    def test_discover_vpcs_with_error(self, mock_session):
        """Test discover_vpcs with API error."""
        mock_ec2_client = MagicMock()
        mock_ec2_client.get_paginator.side_effect = Exception("API Error")

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        vpcs = service.discover_vpcs('us-east-1')

        # Should return empty list on error
        self.assertEqual(vpcs, [])


class AWSResourceDiscoverySubnetTest(TestCase):
    """Tests for discover_subnets method."""

    @patch('resources.services.boto3.Session')
    def test_discover_subnets_success(self, mock_session):
        """Test successfully discovering subnets."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()

        mock_paginator.paginate.return_value = [
            {
                'Subnets': [
                    {
                        'SubnetId': 'subnet-12345678',
                        'VpcId': 'vpc-12345678',
                        'CidrBlock': '10.0.1.0/24',
                        'AvailabilityZone': 'us-east-1a',
                        'State': 'available',
                        'OwnerId': '123456789012',
                        'Tags': [{'Key': 'Name', 'Value': 'Test Subnet'}]
                    }
                ]
            }
        ]

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        subnets = service.discover_subnets('us-east-1', 'vpc-12345678')

        self.assertEqual(len(subnets), 1)
        self.assertEqual(subnets[0]['subnet_id'], 'subnet-12345678')
        self.assertEqual(subnets[0]['vpc_id'], 'vpc-12345678')
        self.assertEqual(subnets[0]['cidr_block'], '10.0.1.0/24')

    @patch('resources.services.boto3.Session')
    def test_discover_subnets_filters_by_vpc(self, mock_session):
        """Test subnet discovery filters by VPC."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = []

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        service.discover_subnets('us-east-1', 'vpc-12345678')

        # Verify paginate was called with VPC filter
        mock_paginator.paginate.assert_called_once()
        call_kwargs = mock_paginator.paginate.call_args[1]
        self.assertIn('Filters', call_kwargs)
        self.assertEqual(
            call_kwargs['Filters'],
            [{'Name': 'vpc-id', 'Values': ['vpc-12345678']}]
        )


class AWSResourceDiscoverySecurityGroupTest(TestCase):
    """Tests for discover_security_groups method."""

    @patch('resources.services.boto3.Session')
    def test_discover_security_groups_with_rules(self, mock_session):
        """Test discovering security groups with rules."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()

        mock_paginator.paginate.return_value = [
            {
                'SecurityGroups': [
                    {
                        'GroupId': 'sg-12345678',
                        'GroupName': 'test-sg',
                        'Description': 'Test security group',
                        'VpcId': 'vpc-12345678',
                        'IpPermissions': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 80,
                                'ToPort': 80,
                                'IpRanges': [
                                    {
                                        'CidrIp': '0.0.0.0/0',
                                        'Description': 'Allow HTTP'
                                    }
                                ]
                            }
                        ],
                        'IpPermissionsEgress': [
                            {
                                'IpProtocol': '-1',
                                'IpRanges': [
                                    {'CidrIp': '0.0.0.0/0'}
                                ]
                            }
                        ],
                        'Tags': [{'Key': 'Environment', 'Value': 'PROD'}]
                    }
                ]
            }
        ]

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        sgs = service.discover_security_groups('us-east-1', 'vpc-12345678')

        self.assertEqual(len(sgs), 1)
        self.assertEqual(sgs[0]['sg_id'], 'sg-12345678')
        self.assertEqual(sgs[0]['name'], 'test-sg')

        # Check rules were parsed correctly
        self.assertEqual(len(sgs[0]['rules']), 2)  # 1 ingress + 1 egress

        # Check ingress rule
        ingress_rule = next(r for r in sgs[0]['rules'] if r['rule_type'] == 'ingress')
        self.assertEqual(ingress_rule['protocol'], 'tcp')
        self.assertEqual(ingress_rule['from_port'], 80)
        self.assertEqual(ingress_rule['source_value'], '0.0.0.0/0')
        self.assertEqual(ingress_rule['description'], 'Allow HTTP')

    @patch('resources.services.boto3.Session')
    def test_discover_security_groups_with_sg_references(self, mock_session):
        """Test security group rules with security group references."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()

        mock_paginator.paginate.return_value = [
            {
                'SecurityGroups': [
                    {
                        'GroupId': 'sg-12345678',
                        'GroupName': 'test-sg',
                        'Description': 'Test',
                        'VpcId': 'vpc-12345678',
                        'IpPermissions': [
                            {
                                'IpProtocol': 'tcp',
                                'FromPort': 443,
                                'ToPort': 443,
                                'UserIdGroupPairs': [
                                    {
                                        'GroupId': 'sg-87654321',
                                        'Description': 'Allow from other SG'
                                    }
                                ]
                            }
                        ],
                        'IpPermissionsEgress': [],
                        'Tags': []
                    }
                ]
            }
        ]

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        sgs = service.discover_security_groups('us-east-1')

        # Check security group reference was parsed
        rule = sgs[0]['rules'][0]
        self.assertEqual(rule['source_type'], 'security_group')
        self.assertEqual(rule['source_value'], 'sg-87654321')


class AWSResourceDiscoveryENITest(TestCase):
    """Tests for discover_enis method."""

    @patch('resources.services.boto3.Session')
    def test_discover_enis_with_secondary_ips(self, mock_session):
        """Test discovering ENIs with secondary IPs."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()

        mock_paginator.paginate.return_value = [
            {
                'NetworkInterfaces': [
                    {
                        'NetworkInterfaceId': 'eni-12345678',
                        'SubnetId': 'subnet-12345678',
                        'Status': 'in-use',
                        'MacAddress': '02:00:00:00:00:01',
                        'PrivateIpAddress': '10.0.1.10',
                        'PrivateIpAddresses': [
                            {'PrivateIpAddress': '10.0.1.10', 'Primary': True},
                            {'PrivateIpAddress': '10.0.1.11', 'Primary': False},
                            {'PrivateIpAddress': '10.0.1.12', 'Primary': False}
                        ],
                        'Association': {'PublicIp': '54.1.2.3'},
                        'Attachment': {'InstanceId': 'i-12345678'},
                        'Groups': [{'GroupId': 'sg-12345678'}],
                        'InterfaceType': 'interface',
                        'OwnerId': '123456789012',
                        'TagSet': [{'Key': 'Name', 'Value': 'Test ENI'}]
                    }
                ]
            }
        ]

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        enis = service.discover_enis('us-east-1', 'subnet-12345678')

        self.assertEqual(len(enis), 1)
        self.assertEqual(enis[0]['eni_id'], 'eni-12345678')
        self.assertEqual(enis[0]['private_ip_address'], '10.0.1.10')
        self.assertEqual(enis[0]['public_ip_address'], '54.1.2.3')

        # Check secondary IPs
        self.assertEqual(len(enis[0]['secondary_ips']), 2)
        self.assertIn('10.0.1.11', enis[0]['secondary_ips'])
        self.assertIn('10.0.1.12', enis[0]['secondary_ips'])

        # Check attachment
        self.assertEqual(enis[0]['attached_resource_id'], 'i-12345678')
        self.assertEqual(enis[0]['attached_resource_type'], 'instance')

        # Check security groups
        self.assertEqual(enis[0]['security_group_ids'], ['sg-12345678'])


class AWSResourceDiscoveryEC2Test(TestCase):
    """Tests for discover_ec2_instances method."""

    @patch('resources.services.boto3.Session')
    def test_discover_ec2_instances_success(self, mock_session):
        """Test successfully discovering EC2 instances."""
        mock_ec2_client = MagicMock()
        mock_paginator = MagicMock()

        from datetime import datetime
        launch_time = datetime(2024, 1, 1, 12, 0, 0)

        mock_paginator.paginate.return_value = [
            {
                'Reservations': [
                    {
                        'OwnerId': '123456789012',
                        'Instances': [
                            {
                                'InstanceId': 'i-12345678',
                                'InstanceType': 't3.micro',
                                'State': {'Name': 'running'},
                                'VpcId': 'vpc-12345678',
                                'SubnetId': 'subnet-12345678',
                                'PrivateIpAddress': '10.0.1.50',
                                'PublicIpAddress': '54.1.2.3',
                                'Placement': {'AvailabilityZone': 'us-east-1a'},
                                'LaunchTime': launch_time,
                                'Platform': 'linux',
                                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}]
                            }
                        ]
                    }
                ]
            }
        ]

        mock_ec2_client.get_paginator.return_value = mock_paginator

        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session
        mock_base_session.client.return_value = mock_ec2_client

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        instances = service.discover_ec2_instances('us-east-1', 'vpc-12345678')

        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0]['instance_id'], 'i-12345678')
        self.assertEqual(instances[0]['instance_type'], 't3.micro')
        self.assertEqual(instances[0]['state'], 'running')
        self.assertEqual(instances[0]['name'], 'Test Instance')
        self.assertEqual(instances[0]['launch_time'], launch_time)


class AWSResourceDiscoveryAllResourcesTest(TestCase):
    """Tests for discover_all_resources method."""

    @patch('resources.services.boto3.Session')
    def test_discover_all_resources_orchestration(self, mock_session):
        """Test discover_all_resources orchestrates all discovery methods."""
        # Setup mocks
        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session

        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}

        mock_ec2_client = MagicMock()
        mock_base_session.client.return_value = mock_sts_client

        # Create a service and mock its methods
        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        # Mock all discovery methods
        service.get_account_id = Mock(return_value='123456789012')
        service.discover_vpcs = Mock(return_value=[
            {'vpc_id': 'vpc-1', 'region': 'us-east-1'}
        ])
        service.discover_subnets = Mock(return_value=[
            {'subnet_id': 'subnet-1', 'vpc_id': 'vpc-1'}
        ])
        service.discover_security_groups = Mock(return_value=[
            {'sg_id': 'sg-1', 'vpc_id': 'vpc-1'}
        ])
        service.discover_ec2_instances = Mock(return_value=[
            {'instance_id': 'i-1', 'vpc_id': 'vpc-1'}
        ])
        service.discover_enis = Mock(return_value=[
            {'eni_id': 'eni-1', 'subnet_id': 'subnet-1'}
        ])

        # Run discovery
        results = service.discover_all_resources(['us-east-1'])

        # Verify structure
        self.assertEqual(results['account_id'], '123456789012')
        self.assertIn('us-east-1', results['regions'])
        self.assertIn('summary', results)

        # Verify summary counts
        self.assertEqual(results['summary']['total_vpcs'], 1)
        self.assertEqual(results['summary']['total_subnets'], 1)
        self.assertEqual(results['summary']['total_security_groups'], 1)
        self.assertEqual(results['summary']['total_ec2_instances'], 1)
        self.assertEqual(results['summary']['total_enis'], 1)

        # Verify all methods were called
        service.discover_vpcs.assert_called_once_with('us-east-1')
        service.discover_subnets.assert_called_once_with('us-east-1', 'vpc-1')
        service.discover_security_groups.assert_called_once_with('us-east-1', 'vpc-1')
        service.discover_ec2_instances.assert_called_once_with('us-east-1', 'vpc-1')
        service.discover_enis.assert_called_once_with('us-east-1', 'subnet-1')

    @patch('resources.services.boto3.Session')
    def test_discover_all_resources_multiple_regions(self, mock_session):
        """Test discovery across multiple regions."""
        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        # Mock methods
        service.get_account_id = Mock(return_value='123456789012')
        service.discover_vpcs = Mock(return_value=[])
        service.discover_subnets = Mock(return_value=[])
        service.discover_security_groups = Mock(return_value=[])
        service.discover_ec2_instances = Mock(return_value=[])
        service.discover_enis = Mock(return_value=[])

        # Run discovery for multiple regions
        results = service.discover_all_resources(['us-east-1', 'us-west-2'])

        # Verify both regions are in results
        self.assertIn('us-east-1', results['regions'])
        self.assertIn('us-west-2', results['regions'])

        # Verify VPC discovery was called for both regions
        self.assertEqual(service.discover_vpcs.call_count, 2)
        service.discover_vpcs.assert_any_call('us-east-1')
        service.discover_vpcs.assert_any_call('us-west-2')


class AWSResourceDiscoveryHelperMethodsTest(TestCase):
    """Tests for helper methods."""

    @patch('resources.services.boto3.Session')
    def test_get_tag_value(self, mock_session):
        """Test _get_tag_value helper method."""
        mock_base_session = MagicMock()
        mock_session.return_value = mock_base_session

        service = AWSResourceDiscovery(
            access_key_id='test_key',
            secret_access_key='test_secret'
        )

        tags = [
            {'Key': 'Name', 'Value': 'Test Resource'},
            {'Key': 'Environment', 'Value': 'PROD'}
        ]

        # Test getting existing tag
        self.assertEqual(service._get_tag_value(tags, 'Name'), 'Test Resource')
        self.assertEqual(service._get_tag_value(tags, 'Environment'), 'PROD')

        # Test getting non-existent tag with default
        self.assertEqual(service._get_tag_value(tags, 'Missing', 'default'), 'default')

        # Test empty tags list
        self.assertEqual(service._get_tag_value([], 'Name', 'none'), 'none')
