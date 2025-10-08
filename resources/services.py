"""
AWS resource discovery services
"""
import boto3
from django.conf import settings
from django.utils import timezone
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class AWSResourceDiscovery:
    """Service for discovering AWS resources with IP addresses/ENIs"""
    
    def __init__(self, access_key_id: str = None, secret_access_key: str = None, 
                 session_token: str = None, region: str = None):
        self.access_key_id = access_key_id or settings.AWS_ACCESS_KEY_ID
        self.secret_access_key = secret_access_key or settings.AWS_SECRET_ACCESS_KEY
        self.session_token = session_token or settings.AWS_SESSION_TOKEN
        self.region = region or settings.AWS_DEFAULT_REGION
        
        # Initialize AWS clients
        self.session = boto3.Session(
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            aws_session_token=self.session_token,
            region_name=self.region
        )
        
        self.ec2_client = self.session.client('ec2')
        self.ec2_resource = self.session.resource('ec2')
    
    def get_account_id(self) -> str:
        """Get the current AWS account ID"""
        try:
            sts_client = self.session.client('sts')
            response = sts_client.get_caller_identity()
            return response['Account']
        except Exception as e:
            logger.error(f"Failed to get account ID: {e}")
            raise
    
    def discover_vpcs(self, region: str) -> List[Dict[str, Any]]:
        """Discover VPCs in a region"""
        try:
            # Create a new client for the specific region
            ec2_client = self.session.client('ec2', region_name=region)
            
            vpcs = []
            paginator = ec2_client.get_paginator('describe_vpcs')
            
            for page in paginator.paginate():
                for vpc in page['Vpcs']:
                    vpc_data = {
                        'vpc_id': vpc['VpcId'],
                        'region': region,
                        'cidr_block': vpc['CidrBlock'],
                        'state': vpc['State'],
                        'is_default': vpc.get('IsDefault', False),
                        'owner_id': vpc.get('OwnerId', ''),
                        'tags': {tag['Key']: tag['Value'] for tag in vpc.get('Tags', [])}
                    }
                    vpcs.append(vpc_data)
            
            return vpcs
        except Exception as e:
            logger.error(f"Failed to discover VPCs in {region}: {e}")
            return []
    
    def discover_subnets(self, region: str, vpc_id: str = None) -> List[Dict[str, Any]]:
        """Discover subnets in a region, optionally filtered by VPC"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            
            subnets = []
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            paginator = ec2_client.get_paginator('describe_subnets')
            
            for page in paginator.paginate(Filters=filters):
                for subnet in page['Subnets']:
                    subnet_data = {
                        'subnet_id': subnet['SubnetId'],
                        'vpc_id': subnet['VpcId'],
                        'region': region,
                        'cidr_block': subnet['CidrBlock'],
                        'availability_zone': subnet['AvailabilityZone'],
                        'state': subnet['State'],
                        'owner_id': subnet.get('OwnerId', ''),
                        'tags': {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                    }
                    subnets.append(subnet_data)
            
            return subnets
        except Exception as e:
            logger.error(f"Failed to discover subnets in {region}: {e}")
            return []
    
    def discover_security_groups(self, region: str, vpc_id: str = None) -> List[Dict[str, Any]]:
        """Discover security groups in a region, optionally filtered by VPC"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            
            security_groups = []
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            paginator = ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate(Filters=filters):
                for sg in page['SecurityGroups']:
                    # Process ingress rules
                    ingress_rules = []
                    for rule in sg.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            ingress_rules.append({
                                'rule_type': 'ingress',
                                'protocol': rule.get('IpProtocol', '-1'),
                                'from_port': rule.get('FromPort'),
                                'to_port': rule.get('ToPort'),
                                'source_type': 'cidr',
                                'source_value': ip_range.get('CidrIp', '0.0.0.0/0'),
                                'description': ip_range.get('Description', '')
                            })
                        
                        for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                            ingress_rules.append({
                                'rule_type': 'ingress',
                                'protocol': rule.get('IpProtocol', '-1'),
                                'from_port': rule.get('FromPort'),
                                'to_port': rule.get('ToPort'),
                                'source_type': 'security_group',
                                'source_value': user_id_group_pair.get('GroupId', ''),
                                'description': user_id_group_pair.get('Description', '')
                            })
                    
                    # Process egress rules
                    egress_rules = []
                    for rule in sg.get('IpPermissionsEgress', []):
                        for ip_range in rule.get('IpRanges', []):
                            egress_rules.append({
                                'rule_type': 'egress',
                                'protocol': rule.get('IpProtocol', '-1'),
                                'from_port': rule.get('FromPort'),
                                'to_port': rule.get('ToPort'),
                                'source_type': 'cidr',
                                'source_value': ip_range.get('CidrIp', '0.0.0.0/0'),
                                'description': ip_range.get('Description', '')
                            })
                        
                        for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                            egress_rules.append({
                                'rule_type': 'egress',
                                'protocol': rule.get('IpProtocol', '-1'),
                                'from_port': rule.get('FromPort'),
                                'to_port': rule.get('ToPort'),
                                'source_type': 'security_group',
                                'source_value': user_id_group_pair.get('GroupId', ''),
                                'description': user_id_group_pair.get('Description', '')
                            })
                    
                    sg_data = {
                        'sg_id': sg['GroupId'],
                        'vpc_id': sg['VpcId'],
                        'name': sg['GroupName'],
                        'description': sg['Description'],
                        'region': region,
                        'rules': ingress_rules + egress_rules,
                        'tags': {tag['Key']: tag['Value'] for tag in sg.get('Tags', [])}
                    }
                    security_groups.append(sg_data)
            
            return security_groups
        except Exception as e:
            logger.error(f"Failed to discover security groups in {region}: {e}")
            return []
    
    def discover_enis(self, region: str, subnet_id: str = None) -> List[Dict[str, Any]]:
        """Discover ENIs in a region, optionally filtered by subnet"""
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            
            enis = []
            filters = []
            if subnet_id:
                filters.append({'Name': 'subnet-id', 'Values': [subnet_id]})
            
            paginator = ec2_client.get_paginator('describe_network_interfaces')
            
            for page in paginator.paginate(Filters=filters):
                for eni in page['NetworkInterfaces']:
                    # Get primary private IP
                    private_ip = None
                    if eni.get('PrivateIpAddress'):
                        private_ip = eni['PrivateIpAddress']
                    
                    # Get secondary IPs
                    secondary_ips = []
                    for ip in eni.get('PrivateIpAddresses', []):
                        if ip.get('PrivateIpAddress') != private_ip:
                            secondary_ips.append(ip['PrivateIpAddress'])
                    
                    # Get attached resource info
                    attachment = eni.get('Attachment', {})
                    attached_resource_id = attachment.get('InstanceId', '')
                    attached_resource_type = 'instance' if attached_resource_id else ''
                    
                    # Check for other attachment types
                    if not attached_resource_id:
                        if attachment.get('LoadBalancerName'):
                            attached_resource_id = attachment['LoadBalancerName']
                            attached_resource_type = 'load_balancer'
                        elif attachment.get('NetworkLoadBalancerArn'):
                            attached_resource_id = attachment['NetworkLoadBalancerArn']
                            attached_resource_type = 'network_load_balancer'
                    
                    # Get owner ID - try multiple fields
                    owner_id = eni.get('OwnerId', '')
                    requester_id = eni.get('RequesterId', '')
                    
                    # Debug logging
                    logger.info(f"ENI {eni['NetworkInterfaceId']} - OwnerId: {owner_id}")
                    logger.info(f"ENI {eni['NetworkInterfaceId']} - RequesterId: {requester_id}")
                    
                    # Use OwnerId if available, otherwise use RequesterId
                    final_owner_id = owner_id or requester_id
                    
                    eni_data = {
                        'eni_id': eni['NetworkInterfaceId'],
                        'subnet_id': eni['SubnetId'],
                        'region': region,
                        'name': self._get_tag_value(eni.get('TagSet', []), 'Name', ''),
                        'description': eni.get('Description', ''),
                        'interface_type': eni.get('InterfaceType', 'interface'),
                        'status': eni['Status'],
                        'mac_address': eni.get('MacAddress', ''),
                        'private_ip_address': private_ip,
                        'public_ip_address': eni.get('Association', {}).get('PublicIp'),
                        'attached_resource_id': attached_resource_id,
                        'attached_resource_type': attached_resource_type,
                        'secondary_ips': secondary_ips,
                        'security_group_ids': [sg['GroupId'] for sg in eni.get('Groups', [])],
                        'owner_id': final_owner_id,  # Use the determined owner ID
                        'tags': {tag['Key']: tag['Value'] for tag in eni.get('TagSet', [])}
                    }
                    enis.append(eni_data)
            
            return enis
        except Exception as e:
            logger.error(f"Failed to discover ENIs in {region}: {e}")
            return []
    
    def _get_tag_value(self, tags: List[Dict], key: str, default: str = '') -> str:
        """Helper to get tag value from AWS tag list"""
        for tag in tags:
            if tag.get('Key') == key:
                return tag.get('Value', default)
        return default
    
    def discover_all_resources(self, regions: List[str]) -> Dict[str, Any]:
        """Discover all resources across multiple regions"""
        results = {
            'account_id': self.get_account_id(),
            'regions': {},
            'summary': {
                'total_vpcs': 0,
                'total_subnets': 0,
                'total_security_groups': 0,
                'total_enis': 0
            }
        }
        
        for region in regions:
            logger.info(f"Discovering resources in {region}")
            region_results = {
                'vpcs': self.discover_vpcs(region),
                'subnets': [],
                'security_groups': [],
                'enis': []
            }
            
            # Discover subnets for each VPC
            for vpc in region_results['vpcs']:
                subnets = self.discover_subnets(region, vpc['vpc_id'])
                region_results['subnets'].extend(subnets)
            
            # Discover security groups for each VPC
            for vpc in region_results['vpcs']:
                sgs = self.discover_security_groups(region, vpc['vpc_id'])
                region_results['security_groups'].extend(sgs)
            
            # Discover ENIs for each subnet
            for subnet in region_results['subnets']:
                enis = self.discover_enis(region, subnet['subnet_id'])
                region_results['enis'].extend(enis)
            
            results['regions'][region] = region_results
            
            # Update summary
            results['summary']['total_vpcs'] += len(region_results['vpcs'])
            results['summary']['total_subnets'] += len(region_results['subnets'])
            results['summary']['total_security_groups'] += len(region_results['security_groups'])
            results['summary']['total_enis'] += len(region_results['enis'])
        
        return results
