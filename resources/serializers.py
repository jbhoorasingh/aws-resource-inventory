"""
Serializers for AWS resources API
"""
from rest_framework import serializers
from .models import (
    AWSAccount, VPC, Subnet, SecurityGroup, EC2Instance, ENI,
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
            'is_default', 'state', 'created_at', 'updated_at'
        ]


class SubnetSerializer(serializers.ModelSerializer):
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    vpc_cidr = serializers.CharField(source='vpc.cidr_block', read_only=True)
    vpc_owner_account = serializers.CharField(source='vpc.owner_account', read_only=True)
    
    class Meta:
        model = Subnet
        fields = [
            'id', 'subnet_id', 'vpc', 'vpc_id', 'vpc_cidr', 'vpc_owner_account', 'name', 'cidr_block', 
            'availability_zone', 'owner_account', 'state', 'created_at', 'updated_at'
        ]


class SecurityGroupSerializer(serializers.ModelSerializer):
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    vpc_owner_account = serializers.CharField(source='vpc.owner_account', read_only=True)
    
    class Meta:
        model = SecurityGroup
        fields = [
            'id', 'sg_id', 'vpc', 'vpc_id', 'vpc_owner_account', 'name', 'description', 
            'created_at', 'updated_at'
        ]


class EC2InstanceSerializer(serializers.ModelSerializer):
    vpc_id = serializers.CharField(source='vpc.vpc_id', read_only=True)
    subnet_id = serializers.CharField(source='subnet.subnet_id', read_only=True)

    class Meta:
        model = EC2Instance
        fields = [
            'id', 'instance_id', 'vpc_id', 'subnet_id', 'name', 'instance_type',
            'state', 'region', 'availability_zone', 'private_ip_address',
            'public_ip_address', 'platform', 'launch_time', 'owner_account',
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
            'attached_resource_type', 'ec2_instance_details', 'availability_zone', 'region', 'secondary_ips', 'security_groups',
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
