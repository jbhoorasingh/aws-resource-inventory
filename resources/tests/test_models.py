"""
Tests for AWS Resource Inventory models.
"""
from django.test import TestCase
from django.utils import timezone
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance
)


class AWSAccountModelTest(TestCase):
    """Tests for AWSAccount model."""

    def setUp(self):
        self.account = AWSAccount.objects.create(
            account_id='123456789012',
            account_name='Test Account',
            is_active=True
        )

    def test_account_creation(self):
        """Test account is created successfully."""
        self.assertEqual(self.account.account_id, '123456789012')
        self.assertEqual(self.account.account_name, 'Test Account')
        self.assertTrue(self.account.is_active)
        self.assertIsNotNone(self.account.created_at)

    def test_account_str(self):
        """Test string representation."""
        expected = 'Test Account (123456789012)'
        self.assertEqual(str(self.account), expected)

    def test_account_str_without_name(self):
        """Test string representation without name."""
        account = AWSAccount.objects.create(
            account_id='987654321098',
            account_name='',
            is_active=True
        )
        self.assertEqual(str(account), '987654321098')

    def test_last_polled_nullable(self):
        """Test last_polled can be null."""
        self.assertIsNone(self.account.last_polled)
        self.account.last_polled = timezone.now()
        self.account.save()
        self.assertIsNotNone(self.account.last_polled)

    def test_role_assumption_fields(self):
        """Test role assumption configuration fields."""
        self.account.role_arn = 'arn:aws:iam::123456789012:role/TestRole'
        self.account.external_id = 'test-external-id'
        self.account.save()

        self.assertEqual(self.account.role_arn, 'arn:aws:iam::123456789012:role/TestRole')
        self.assertEqual(self.account.external_id, 'test-external-id')


class VPCModelTest(TestCase):
    """Tests for VPC model."""

    def setUp(self):
        self.vpc = VPC.objects.create(
            vpc_id='vpc-12345678',
            cidr_block='10.0.0.0/16',
            region='us-east-1',
            state='available',
            owner_account='123456789012',
            tags={'Name': 'Test VPC', 'Environment': 'Test'}
        )

    def test_vpc_creation(self):
        """Test VPC is created successfully."""
        self.assertEqual(self.vpc.vpc_id, 'vpc-12345678')
        self.assertEqual(self.vpc.cidr_block, '10.0.0.0/16')
        self.assertEqual(self.vpc.region, 'us-east-1')
        self.assertEqual(self.vpc.state, 'available')
        self.assertEqual(self.vpc.owner_account, '123456789012')

    def test_vpc_str(self):
        """Test string representation."""
        self.assertEqual(str(self.vpc), 'vpc-12345678 (us-east-1)')

    def test_vpc_tags(self):
        """Test tags are stored correctly."""
        self.assertEqual(self.vpc.tags['Name'], 'Test VPC')
        self.assertEqual(self.vpc.tags['Environment'], 'Test')

    def test_vpc_unique_constraint(self):
        """Test VPC ID must be unique."""
        with self.assertRaises(Exception):
            VPC.objects.create(
                vpc_id='vpc-12345678',  # Duplicate
                cidr_block='172.16.0.0/16',
                region='us-west-2',
                state='available',
                owner_account='123456789012'
            )


class SubnetModelTest(TestCase):
    """Tests for Subnet model."""

    def setUp(self):
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
            state='available',
            tags={'Name': 'Test Subnet'}
        )

    def test_subnet_creation(self):
        """Test subnet is created successfully."""
        self.assertEqual(self.subnet.subnet_id, 'subnet-12345678')
        self.assertEqual(self.subnet.vpc, self.vpc)
        self.assertEqual(self.subnet.cidr_block, '10.0.1.0/24')
        self.assertEqual(self.subnet.availability_zone, 'us-east-1a')

    def test_subnet_str(self):
        """Test string representation."""
        expected = 'subnet-12345678 (us-east-1a)'
        self.assertEqual(str(self.subnet), expected)

    def test_subnet_vpc_relationship(self):
        """Test subnet belongs to VPC."""
        self.assertEqual(self.subnet.vpc.vpc_id, 'vpc-12345678')

    def test_subnet_cascade_delete(self):
        """Test deleting VPC cascades to subnets."""
        subnet_id = self.subnet.id
        self.vpc.delete()
        self.assertFalse(Subnet.objects.filter(id=subnet_id).exists())


class SecurityGroupModelTest(TestCase):
    """Tests for SecurityGroup model."""

    def setUp(self):
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
            vpc=self.vpc,
            tags={'Name': 'Test SG'}
        )

    def test_security_group_creation(self):
        """Test security group is created successfully."""
        self.assertEqual(self.sg.sg_id, 'sg-12345678')
        self.assertEqual(self.sg.name, 'test-sg')
        self.assertEqual(self.sg.description, 'Test security group')
        self.assertEqual(self.sg.vpc, self.vpc)

    def test_security_group_str(self):
        """Test string representation."""
        expected = 'test-sg (sg-12345678)'
        self.assertEqual(str(self.sg), expected)

    def test_security_group_vpc_relationship(self):
        """Test security group belongs to VPC."""
        self.assertEqual(self.sg.vpc.vpc_id, 'vpc-12345678')


class SecurityGroupRuleModelTest(TestCase):
    """Tests for SecurityGroupRule model."""

    def setUp(self):
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
            vpc=self.vpc
        )
        self.rule = SecurityGroupRule.objects.create(
            security_group=self.sg,
            rule_type='ingress',
            protocol='tcp',
            from_port=80,
            to_port=80,
            source_type='cidr',
            source_value='0.0.0.0/0',
            description='Allow HTTP'
        )

    def test_rule_creation(self):
        """Test security group rule is created successfully."""
        self.assertEqual(self.rule.security_group, self.sg)
        self.assertEqual(self.rule.rule_type, 'ingress')
        self.assertEqual(self.rule.protocol, 'tcp')
        self.assertEqual(self.rule.from_port, 80)
        self.assertEqual(self.rule.to_port, 80)

    def test_rule_str(self):
        """Test string representation."""
        expected = 'INGRESS TCP 80 from 0.0.0.0/0'
        self.assertEqual(str(self.rule), expected)

    def test_egress_rule(self):
        """Test egress rule creation."""
        egress_rule = SecurityGroupRule.objects.create(
            security_group=self.sg,
            rule_type='egress',
            protocol='-1',
            from_port=-1,
            to_port=-1,
            source_type='cidr',
            source_value='0.0.0.0/0'
        )
        self.assertEqual(egress_rule.rule_type, 'egress')
        self.assertEqual(egress_rule.protocol, '-1')

    def test_rule_cascade_delete(self):
        """Test deleting security group cascades to rules."""
        rule_id = self.rule.id
        self.sg.delete()
        self.assertFalse(SecurityGroupRule.objects.filter(id=rule_id).exists())


class ENIModelTest(TestCase):
    """Tests for ENI model."""

    def setUp(self):
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

    def test_eni_creation(self):
        """Test ENI is created successfully."""
        self.assertEqual(self.eni.eni_id, 'eni-12345678')
        self.assertEqual(self.eni.subnet, self.subnet)
        self.assertEqual(self.eni.private_ip_address, '10.0.1.10')
        self.assertEqual(self.eni.public_ip_address, '54.1.2.3')
        self.assertEqual(self.eni.status, 'in-use')

    def test_eni_str(self):
        """Test string representation."""
        expected = 'eni-12345678 (10.0.1.10)'
        self.assertEqual(str(self.eni), expected)

    def test_eni_without_public_ip(self):
        """Test ENI without public IP."""
        eni = ENI.objects.create(
            eni_id='eni-87654321',
            subnet=self.subnet,
            private_ip_address='10.0.1.20',
            status='available',
            interface_type='interface',
            mac_address='02:00:00:00:00:02',
            owner_account='123456789012'
        )
        self.assertIsNone(eni.public_ip_address)

    def test_eni_subnet_relationship(self):
        """Test ENI belongs to subnet."""
        self.assertEqual(self.eni.subnet.subnet_id, 'subnet-12345678')
        self.assertEqual(self.eni.subnet.vpc.vpc_id, 'vpc-12345678')


class ENISecondaryIPModelTest(TestCase):
    """Tests for ENISecondaryIP model."""

    def setUp(self):
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
            owner_account='123456789012'
        )
        self.secondary_ip = ENISecondaryIP.objects.create(
            eni=self.eni,
            ip_address='10.0.1.11'
        )

    def test_secondary_ip_creation(self):
        """Test secondary IP is created successfully."""
        self.assertEqual(self.secondary_ip.eni, self.eni)
        self.assertEqual(self.secondary_ip.ip_address, '10.0.1.11')

    def test_secondary_ip_str(self):
        """Test string representation."""
        expected = 'eni-12345678 - 10.0.1.11'
        self.assertEqual(str(self.secondary_ip), expected)

    def test_multiple_secondary_ips(self):
        """Test ENI can have multiple secondary IPs."""
        secondary_ip2 = ENISecondaryIP.objects.create(
            eni=self.eni,
            ip_address='10.0.1.12'
        )
        self.assertEqual(self.eni.secondary_ips.count(), 2)
        ips = list(self.eni.secondary_ips.values_list('ip_address', flat=True))
        self.assertIn('10.0.1.11', ips)
        self.assertIn('10.0.1.12', ips)

    def test_secondary_ip_cascade_delete(self):
        """Test deleting ENI cascades to secondary IPs."""
        secondary_ip_id = self.secondary_ip.id
        self.eni.delete()
        self.assertFalse(ENISecondaryIP.objects.filter(id=secondary_ip_id).exists())


class ENISecurityGroupModelTest(TestCase):
    """Tests for ENISecurityGroup (join table) model."""

    def setUp(self):
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
            owner_account='123456789012'
        )
        self.sg = SecurityGroup.objects.create(
            sg_id='sg-12345678',
            name='test-sg',
            vpc=self.vpc
        )
        self.eni_sg = ENISecurityGroup.objects.create(
            eni=self.eni,
            security_group=self.sg
        )

    def test_eni_security_group_creation(self):
        """Test ENI-SecurityGroup association is created."""
        self.assertEqual(self.eni_sg.eni, self.eni)
        self.assertEqual(self.eni_sg.security_group, self.sg)

    def test_eni_security_group_str(self):
        """Test string representation."""
        expected = 'eni-12345678 - test-sg'
        self.assertEqual(str(self.eni_sg), expected)

    def test_multiple_security_groups_per_eni(self):
        """Test ENI can have multiple security groups."""
        sg2 = SecurityGroup.objects.create(
            sg_id='sg-87654321',
            name='test-sg-2',
            vpc=self.vpc
        )
        ENISecurityGroup.objects.create(
            eni=self.eni,
            security_group=sg2
        )
        self.assertEqual(self.eni.eni_security_groups.count(), 2)


class EC2InstanceModelTest(TestCase):
    """Tests for EC2Instance model."""

    def setUp(self):
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
            platform='linux',
            region='us-east-1',
            availability_zone='us-east-1a',
            vpc=self.vpc,
            subnet=self.subnet,
            private_ip_address='10.0.1.50',
            public_ip_address='54.1.2.3',
            owner_account='123456789012',
            tags={'Name': 'Test Instance', 'Environment': 'Test'},
            launch_time=timezone.now()
        )

    def test_instance_creation(self):
        """Test EC2 instance is created successfully."""
        self.assertEqual(self.instance.instance_id, 'i-12345678')
        self.assertEqual(self.instance.name, 'Test Instance')
        self.assertEqual(self.instance.instance_type, 't3.micro')
        self.assertEqual(self.instance.state, 'running')
        self.assertEqual(self.instance.platform, 'linux')

    def test_instance_str(self):
        """Test string representation."""
        expected = 'Test Instance (t3.micro)'
        self.assertEqual(str(self.instance), expected)

    def test_instance_str_without_name(self):
        """Test string representation without name."""
        instance = EC2Instance.objects.create(
            instance_id='i-87654321',
            instance_type='t3.small',
            state='stopped',
            region='us-west-2',
            availability_zone='us-west-2a',
            vpc=self.vpc,
            subnet=self.subnet,
            owner_account='123456789012'
        )
        self.assertEqual(str(instance), 'i-87654321 (t3.small)')

    def test_instance_vpc_subnet_relationships(self):
        """Test instance belongs to VPC and subnet."""
        self.assertEqual(self.instance.vpc.vpc_id, 'vpc-12345678')
        self.assertEqual(self.instance.subnet.subnet_id, 'subnet-12345678')

    def test_instance_tags(self):
        """Test tags are stored correctly."""
        self.assertEqual(self.instance.tags['Name'], 'Test Instance')
        self.assertEqual(self.instance.tags['Environment'], 'Test')

    def test_instance_without_ips(self):
        """Test instance can exist without IPs (stopped instance)."""
        instance = EC2Instance.objects.create(
            instance_id='i-99999999',
            instance_type='t3.nano',
            state='stopped',
            region='us-east-1',
            availability_zone='us-east-1b',
            vpc=self.vpc,
            subnet=self.subnet,
            owner_account='123456789012'
        )
        self.assertIsNone(instance.private_ip_address)
        self.assertIsNone(instance.public_ip_address)
