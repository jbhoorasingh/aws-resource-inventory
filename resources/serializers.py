"""
Serializers for AWS resources API
"""
from rest_framework import serializers
from .models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule, EC2Instance, ENI,
    ENISecondaryIP, ENISecurityGroup
)


class AWSAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = AWSAccount
        fields = ['id', 'account_id', 'account_name', 'is_active', 'last_polled', 'created_at', 'updated_at']


class VPCSerializer(serializers.ModelSerializer):
    class Meta:
        model = VPC
        fields = [
            'id', 'vpc_id', 'region', 'cidr_block', 'owner_account',
            'is_default', 'state', 'tags', 'created_at', 'updated_at'
        ]


class SubnetSerializer(serializers.ModelSerializer):
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    vpc_cidr = serializers.CharField(source='vpc.cidr_block', read_only=True)
    vpc_owner_account = serializers.CharField(source='vpc.owner_account', read_only=True)

    class Meta:
        model = Subnet
        fields = [
            'id', 'subnet_id', 'vpc', 'vpc_id', 'vpc_cidr', 'vpc_owner_account', 'name', 'cidr_block',
            'availability_zone', 'owner_account', 'state', 'tags', 'created_at', 'updated_at'
        ]


class SecurityGroupRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityGroupRule
        fields = [
            'id', 'rule_type', 'protocol', 'from_port', 'to_port',
            'source_type', 'source_value', 'description'
        ]


class SecurityGroupSerializer(serializers.ModelSerializer):
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    vpc_owner_account = serializers.CharField(source='vpc.owner_account', read_only=True)
    ingress_rules = serializers.SerializerMethodField()
    egress_rules = serializers.SerializerMethodField()

    class Meta:
        model = SecurityGroup
        fields = [
            'id', 'sg_id', 'vpc', 'vpc_id', 'vpc_owner_account', 'name', 'description', 'tags',
            'created_at', 'updated_at', 'ingress_rules', 'egress_rules'
        ]

    def get_ingress_rules(self, obj):
        rules = obj.rules.filter(rule_type='ingress')
        return SecurityGroupRuleSerializer(rules, many=True).data

    def get_egress_rules(self, obj):
        rules = obj.rules.filter(rule_type='egress')
        return SecurityGroupRuleSerializer(rules, many=True).data


class EC2InstanceSerializer(serializers.ModelSerializer):
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    subnet_id = serializers.CharField(source='subnet.subnet_id', read_only=True)

    class Meta:
        model = EC2Instance
        fields = [
            'id', 'instance_id', 'vpc_id', 'subnet_id', 'name', 'instance_type',
            'state', 'region', 'availability_zone', 'private_ip_address',
            'public_ip_address', 'platform', 'launch_time', 'owner_account', 'tags',
            'created_at', 'updated_at'
        ]


class ENISecondaryIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = ENISecondaryIP
        fields = ['id', 'ip_address', 'created_at']


class ENISecurityGroupSerializer(serializers.ModelSerializer):
    security_group_name = serializers.CharField(source='security_group.name', read_only=True)
    security_group_id = serializers.CharField(source='security_group.sg_id', read_only=True)
    
    class Meta:
        model = ENISecurityGroup
        fields = [
            'id', 'security_group', 'security_group_name', 'security_group_id', 'created_at'
        ]


class ENISerializer(serializers.ModelSerializer):
    subnet_id = serializers.CharField(source='subnet.subnet_id', read_only=True)
    subnet_cidr = serializers.CharField(source='subnet.cidr_block', read_only=True)
    vpc_id = serializers.CharField(source='subnet.vpc.vpc_id', read_only=True)
    vpc_cidr = serializers.CharField(source='subnet.vpc.cidr_block', read_only=True)
    vpc_owner_account = serializers.CharField(source='subnet.vpc.owner_account', read_only=True)
    subnet_owner_account = serializers.CharField(source='subnet.owner_account', read_only=True)
    availability_zone = serializers.CharField(source='subnet.availability_zone', read_only=True)
    region = serializers.CharField(source='subnet.vpc.region', read_only=True)

    secondary_ips = ENISecondaryIPSerializer(many=True, read_only=True)
    security_groups = ENISecurityGroupSerializer(source='eni_security_groups', many=True, read_only=True)
    ec2_instance_details = EC2InstanceSerializer(source='ec2_instance', read_only=True)

    class Meta:
        model = ENI
        fields = [
            'id', 'eni_id', 'subnet', 'subnet_id', 'subnet_cidr', 'vpc_id', 'vpc_cidr',
            'vpc_owner_account', 'subnet_owner_account', 'name', 'description', 'interface_type',
            'status', 'mac_address', 'private_ip_address', 'public_ip_address', 'attached_resource_id',
            'attached_resource_type', 'ec2_instance_details', 'availability_zone', 'region', 'secondary_ips', 'security_groups', 'tags',
            'created_at', 'updated_at'
        ]


class ENIDetailSerializer(ENISerializer):
    """Detailed ENI serializer with all related information"""
    pass


class ResourceSummarySerializer(serializers.Serializer):
    """Serializer for resource summary statistics"""
    total_accounts = serializers.IntegerField()
    total_vpcs = serializers.IntegerField()
    total_subnets = serializers.IntegerField()
    total_security_groups = serializers.IntegerField()
    total_enis = serializers.IntegerField()
    total_private_ips = serializers.IntegerField()
    total_public_ips = serializers.IntegerField()
    regions = serializers.ListField(child=serializers.CharField())
    accounts = serializers.ListField(child=serializers.CharField())


# Hierarchical VPC/Subnet serializers for tree view
class SubnetENISerializer(serializers.ModelSerializer):
    """Compact ENI serializer for subnet tree view"""
    ec2_instance_id = serializers.CharField(source='ec2_instance.instance_id', read_only=True, allow_null=True)
    ec2_instance_name = serializers.CharField(source='ec2_instance.name', read_only=True, allow_null=True)
    ec2_instance_state = serializers.CharField(source='ec2_instance.state', read_only=True, allow_null=True)
    security_group_ids = serializers.SerializerMethodField()
    secondary_ip_addresses = serializers.SerializerMethodField()

    class Meta:
        model = ENI
        fields = [
            'id', 'eni_id', 'name', 'private_ip_address', 'public_ip_address',
            'status', 'interface_type', 'attached_resource_id', 'attached_resource_type',
            'ec2_instance_id', 'ec2_instance_name', 'ec2_instance_state',
            'security_group_ids', 'secondary_ip_addresses', 'tags'
        ]

    def get_security_group_ids(self, obj):
        return [sg.security_group.sg_id for sg in obj.eni_security_groups.all()]

    def get_secondary_ip_addresses(self, obj):
        return [ip.ip_address for ip in obj.secondary_ips.all()]


class SubnetSecurityGroupSerializer(serializers.ModelSerializer):
    """Compact security group serializer for subnet tree view"""
    rule_count = serializers.SerializerMethodField()
    ingress_rule_count = serializers.SerializerMethodField()
    egress_rule_count = serializers.SerializerMethodField()

    class Meta:
        model = SecurityGroup
        fields = ['id', 'sg_id', 'name', 'description', 'tags', 'rule_count', 'ingress_rule_count', 'egress_rule_count']

    def get_rule_count(self, obj):
        return obj.rules.count()

    def get_ingress_rule_count(self, obj):
        return obj.rules.filter(rule_type='ingress').count()

    def get_egress_rule_count(self, obj):
        return obj.rules.filter(rule_type='egress').count()


class SubnetEC2InstanceSerializer(serializers.ModelSerializer):
    """Compact EC2 instance serializer for subnet tree view"""
    eni_count = serializers.SerializerMethodField()

    class Meta:
        model = EC2Instance
        fields = [
            'id', 'instance_id', 'name', 'instance_type', 'state',
            'private_ip_address', 'public_ip_address', 'platform',
            'launch_time', 'tags', 'eni_count'
        ]

    def get_eni_count(self, obj):
        return obj.enis.count()


class SubnetTreeSerializer(serializers.ModelSerializer):
    """Subnet serializer with nested ENIs, EC2 instances, and security groups"""
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    region = serializers.CharField(source='vpc.region', read_only=True)
    enis = SubnetENISerializer(many=True, read_only=True)
    ec2_instances = SubnetEC2InstanceSerializer(source='instances', many=True, read_only=True)
    security_groups = serializers.SerializerMethodField()
    resource_counts = serializers.SerializerMethodField()

    class Meta:
        model = Subnet
        fields = [
            'id', 'subnet_id', 'vpc_id', 'region', 'name', 'cidr_block',
            'availability_zone', 'owner_account', 'state', 'tags',
            'enis', 'ec2_instances', 'security_groups', 'resource_counts'
        ]

    def get_security_groups(self, obj):
        # Get all unique security groups used by ENIs in this subnet
        sg_ids = set()
        for eni in obj.enis.all():
            for eni_sg in eni.eni_security_groups.all():
                sg_ids.add(eni_sg.security_group.id)

        security_groups = SecurityGroup.objects.filter(id__in=sg_ids).prefetch_related('rules')
        return SubnetSecurityGroupSerializer(security_groups, many=True).data

    def get_resource_counts(self, obj):
        return {
            'eni_count': obj.enis.count(),
            'ec2_instance_count': obj.instances.count(),
            'security_group_count': len(self.get_security_groups(obj))
        }


class VPCTreeSerializer(serializers.ModelSerializer):
    """VPC serializer with nested subnets and all their resources"""
    subnets = SubnetTreeSerializer(many=True, read_only=True)
    resource_counts = serializers.SerializerMethodField()

    class Meta:
        model = VPC
        fields = [
            'id', 'vpc_id', 'region', 'cidr_block', 'owner_account',
            'is_default', 'state', 'tags', 'subnets', 'resource_counts'
        ]

    def get_resource_counts(self, obj):
        subnet_count = obj.subnets.count()
        eni_count = ENI.objects.filter(subnet__vpc=obj).count()
        ec2_count = EC2Instance.objects.filter(vpc=obj).count()
        sg_count = obj.security_groups.count()

        return {
            'subnet_count': subnet_count,
            'eni_count': eni_count,
            'ec2_instance_count': ec2_count,
            'security_group_count': sg_count
        }
