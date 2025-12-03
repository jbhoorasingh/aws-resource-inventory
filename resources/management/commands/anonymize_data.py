"""
Django management command to anonymize sensitive data in the database
"""
from django.core.management.base import BaseCommand
from django.db import transaction, IntegrityError
from resources.models import (
    VPC, Subnet, EC2Instance, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, AWSAccount
)
import hashlib
import random
import ipaddress
import re
import logging

logger = logging.getLogger(__name__)


class DataAnonymizer:
    """Utility class to anonymize data while preserving relationships"""
    
    def __init__(self):
        # Seed random for consistent anonymization
        random.seed(42)
        # Cache for deterministic anonymization
        self._id_cache = {}
        self._ip_cache = {}
        self._name_cache = {}
        self._account_cache = {}
        self._mac_cache = {}
    
    def anonymize_aws_id(self, original_id, prefix, length=8):
        """
        Anonymize AWS resource IDs (e.g., eni-xxx, vpc-xxx, sg-xxx)
        Uses deterministic hashing to preserve relationships
        """
        if not original_id:
            return original_id
        
        if original_id in self._id_cache:
            return self._id_cache[original_id]
        
        # Extract the suffix if it exists
        if '-' in original_id:
            parts = original_id.split('-', 1)
            prefix_part = parts[0]
            suffix = parts[1] if len(parts) > 1 else ''
        else:
            prefix_part = prefix
            suffix = original_id
        
        # Generate deterministic hash-based suffix
        hash_obj = hashlib.md5(original_id.encode())
        hash_hex = hash_obj.hexdigest()[:length]
        
        # Format as AWS ID (e.g., eni-0a1b2c3d, vpc-0a1b2c3d)
        anonymized = f"{prefix_part}-{hash_hex}"
        self._id_cache[original_id] = anonymized
        return anonymized
    
    def anonymize_ip(self, original_ip):
        """
        Anonymize IP addresses while preserving network structure
        Uses deterministic mapping to preserve relationships
        """
        if not original_ip:
            return original_ip
        
        if original_ip in self._ip_cache:
            return self._ip_cache[original_ip]
        
        try:
            ip = ipaddress.ip_address(original_ip)
            
            # Use hash to generate deterministic anonymized IP
            hash_obj = hashlib.md5(original_ip.encode())
            hash_int = int(hash_obj.hexdigest()[:8], 16)
            
            if isinstance(ip, ipaddress.IPv4Address):
                # Map to 10.x.x.x private range
                anonymized = f"10.{hash_int % 256}.{(hash_int >> 8) % 256}.{(hash_int >> 16) % 256}"
            else:
                # IPv6 - map to fd00::/8 (ULA range)
                hash_bytes = hash_obj.digest()[:8]
                anonymized = f"fd00::{hash_bytes.hex()[:4]}:{hash_bytes.hex()[4:8]}:{hash_bytes.hex()[8:12]}:{hash_bytes.hex()[12:16]}"
            
            self._ip_cache[original_ip] = anonymized
            return anonymized
        except ValueError:
            # Invalid IP, return as-is or generate random
            anonymized = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            self._ip_cache[original_ip] = anonymized
            return anonymized
    
    def anonymize_cidr(self, original_cidr):
        """
        Anonymize CIDR blocks while preserving network size
        """
        if not original_cidr:
            return original_cidr
        
        try:
            network = ipaddress.ip_network(original_cidr, strict=False)
            prefix_len = network.prefixlen
            
            # Anonymize the base IP
            base_ip = str(network.network_address)
            anonymized_base = self.anonymize_ip(base_ip)
            
            # Reconstruct CIDR
            if ':' in anonymized_base:
                # IPv6
                return f"{anonymized_base}/{prefix_len}"
            else:
                # IPv4
                return f"{anonymized_base}/{prefix_len}"
        except ValueError:
            # Invalid CIDR, return anonymized version
            return "10.0.0.0/24"
    
    def anonymize_account_id(self, original_account):
        """
        Anonymize AWS account IDs (12-digit numbers)
        """
        if not original_account:
            return original_account
        
        if original_account in self._account_cache:
            return self._account_cache[original_account]
        
        # Generate deterministic 12-digit account ID
        hash_obj = hashlib.md5(original_account.encode())
        hash_int = int(hash_obj.hexdigest()[:10], 16)
        anonymized = f"{hash_int:012d}"[:12]
        
        self._account_cache[original_account] = anonymized
        return anonymized
    
    def anonymize_name(self, original_name):
        """
        Anonymize resource names
        """
        if not original_name:
            return original_name
        
        if original_name in self._name_cache:
            return self._name_cache[original_name]
        
        # Generate deterministic anonymized name
        hash_obj = hashlib.md5(original_name.encode())
        hash_hex = hash_obj.hexdigest()[:8]
        anonymized = f"resource-{hash_hex}"
        
        self._name_cache[original_name] = anonymized
        return anonymized
    
    def anonymize_description(self, original_desc):
        """
        Anonymize descriptions
        """
        if not original_desc:
            return original_desc
        
        # Replace with generic description
        return "Anonymized description"
    
    def anonymize_mac_address(self, original_mac):
        """
        Anonymize MAC addresses
        """
        if not original_mac:
            return original_mac
        
        if original_mac in self._mac_cache:
            return self._mac_cache[original_mac]
        
        # Generate deterministic MAC address
        hash_obj = hashlib.md5(original_mac.encode())
        hash_hex = hash_obj.hexdigest()[:12]
        # Format as MAC address (e.g., 00:1a:2b:3c:4d:5e)
        anonymized = ':'.join([hash_hex[i:i+2] for i in range(0, 12, 2)])
        anonymized = f"00:{anonymized[3:]}"  # Start with 00 to indicate locally administered
        
        self._mac_cache[original_mac] = anonymized
        return anonymized
    
    def anonymize_tags(self, tags_dict):
        """
        Anonymize tag values while preserving tag keys
        """
        if not tags_dict or not isinstance(tags_dict, dict):
            return tags_dict
        
        anonymized_tags = {}
        for key, value in tags_dict.items():
            # Keep tag keys but anonymize values
            if isinstance(value, str):
                anonymized_tags[key] = self.anonymize_name(value)
            else:
                anonymized_tags[key] = value
        
        return anonymized_tags
    
    def anonymize_sg_rule_source(self, source_value):
        """
        Anonymize security group rule source values
        Can contain CIDR blocks, security group IDs, prefix lists, etc.
        """
        if not source_value:
            return source_value
        
        # Check if it's a CIDR block
        if '/' in source_value:
            return self.anonymize_cidr(source_value)
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(source_value)
            return self.anonymize_ip(source_value)
        except ValueError:
            pass
        
        # Check if it's a security group ID (sg-xxx)
        if source_value.startswith('sg-'):
            return self.anonymize_aws_id(source_value, 'sg')
        
        # Check if it's a prefix list ID (pl-xxx)
        if source_value.startswith('pl-'):
            return self.anonymize_aws_id(source_value, 'pl')
        
        # Otherwise, anonymize as name
        return self.anonymize_name(source_value)


class Command(BaseCommand):
    help = 'Anonymize sensitive data in the database (ENI, VPC, Subnet, EC2, Security Groups, Tags, SG Rules)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be anonymized without making changes',
        )
        parser.add_argument(
            '--confirm',
            action='store_true',
            help='Confirm anonymization (required for actual changes)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        confirm = options['confirm']
        
        if not dry_run and not confirm:
            self.stdout.write(
                self.style.ERROR(
                    'This will permanently anonymize data in your database!\n'
                    'Use --dry-run to see what would be changed, or --confirm to proceed.'
                )
            )
            return
        
        anonymizer = DataAnonymizer()
        
        with transaction.atomic():
            # Anonymize VPCs
            self.stdout.write('Anonymizing VPCs...')
            vpcs = list(VPC.objects.all())
            # Pre-compute anonymized IDs to check for collisions
            anonymized_vpc_ids = {}
            for vpc in vpcs:
                anonymized_id = anonymizer.anonymize_aws_id(vpc.vpc_id, 'vpc')
                # Handle collisions by appending counter
                original_anonymized = anonymized_id
                counter = 0
                while anonymized_id in anonymized_vpc_ids.values():
                    counter += 1
                    anonymized_id = f"{original_anonymized}-{counter}"
                anonymized_vpc_ids[vpc.id] = anonymized_id
            
            vpc_count = 0
            for vpc in vpcs:
                vpc.vpc_id = anonymized_vpc_ids[vpc.id]
                vpc.cidr_block = anonymizer.anonymize_cidr(vpc.cidr_block)
                vpc.owner_account = anonymizer.anonymize_account_id(vpc.owner_account)
                vpc.tags = anonymizer.anonymize_tags(vpc.tags)
                if not dry_run:
                    try:
                        vpc.save(update_fields=['vpc_id', 'cidr_block', 'owner_account', 'tags'])
                    except IntegrityError as e:
                        self.stdout.write(self.style.ERROR(f'  Error updating VPC {vpc.id}: {e}'))
                        raise
                vpc_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {vpc_count} VPCs'))
            
            # Anonymize Subnets
            self.stdout.write('Anonymizing Subnets...')
            subnets = list(Subnet.objects.all())
            # Pre-compute anonymized IDs to check for collisions
            anonymized_subnet_ids = {}
            for subnet in subnets:
                anonymized_id = anonymizer.anonymize_aws_id(subnet.subnet_id, 'subnet')
                original_anonymized = anonymized_id
                counter = 0
                while anonymized_id in anonymized_subnet_ids.values():
                    counter += 1
                    anonymized_id = f"{original_anonymized}-{counter}"
                anonymized_subnet_ids[subnet.id] = anonymized_id
            
            subnet_count = 0
            for subnet in subnets:
                subnet.subnet_id = anonymized_subnet_ids[subnet.id]
                subnet.name = anonymizer.anonymize_name(subnet.name) if subnet.name else subnet.name
                subnet.cidr_block = anonymizer.anonymize_cidr(subnet.cidr_block)
                subnet.owner_account = anonymizer.anonymize_account_id(subnet.owner_account)
                subnet.tags = anonymizer.anonymize_tags(subnet.tags)
                if not dry_run:
                    try:
                        subnet.save(update_fields=['subnet_id', 'name', 'cidr_block', 'owner_account', 'tags'])
                    except IntegrityError as e:
                        self.stdout.write(self.style.ERROR(f'  Error updating Subnet {subnet.id}: {e}'))
                        raise
                subnet_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {subnet_count} Subnets'))
            
            # Anonymize Security Groups
            self.stdout.write('Anonymizing Security Groups...')
            sgs = list(SecurityGroup.objects.all())
            # Pre-compute anonymized IDs to check for collisions
            anonymized_sg_ids = {}  # Maps model id -> anonymized sg_id
            original_to_anonymized_sg = {}  # Maps original sg_id -> anonymized sg_id (for rule source_value)
            for sg in sgs:
                anonymized_id = anonymizer.anonymize_aws_id(sg.sg_id, 'sg')
                original_anonymized = anonymized_id
                counter = 0
                while anonymized_id in anonymized_sg_ids.values():
                    counter += 1
                    anonymized_id = f"{original_anonymized}-{counter}"
                anonymized_sg_ids[sg.id] = anonymized_id
                original_to_anonymized_sg[sg.sg_id] = anonymized_id
            
            sg_count = 0
            for sg in sgs:
                sg.sg_id = anonymized_sg_ids[sg.id]
                sg.name = anonymizer.anonymize_name(sg.name)
                sg.description = anonymizer.anonymize_description(sg.description) if sg.description else sg.description
                sg.tags = anonymizer.anonymize_tags(sg.tags)
                if not dry_run:
                    try:
                        sg.save(update_fields=['sg_id', 'name', 'description', 'tags'])
                    except IntegrityError as e:
                        self.stdout.write(self.style.ERROR(f'  Error updating Security Group {sg.id}: {e}'))
                        raise
                sg_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {sg_count} Security Groups'))
            
            # Anonymize Security Group Rules
            self.stdout.write('Anonymizing Security Group Rules...')
            sg_rules = SecurityGroupRule.objects.all()
            rule_count = 0
            for rule in sg_rules:
                # Check if source_value is a security group ID that we've already anonymized
                if rule.source_value.startswith('sg-') and rule.source_value in original_to_anonymized_sg:
                    rule.source_value = original_to_anonymized_sg[rule.source_value]
                else:
                    rule.source_value = anonymizer.anonymize_sg_rule_source(rule.source_value)
                rule.description = anonymizer.anonymize_description(rule.description) if rule.description else rule.description
                if not dry_run:
                    rule.save(update_fields=['source_value', 'description'])
                rule_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {rule_count} Security Group Rules'))
            
            # Anonymize EC2 Instances
            self.stdout.write('Anonymizing EC2 Instances...')
            instances = list(EC2Instance.objects.all())
            # Pre-compute anonymized IDs to check for collisions
            anonymized_instance_ids = {}  # Maps model id -> anonymized instance_id
            original_to_anonymized_instance = {}  # Maps original instance_id -> anonymized instance_id (for ENI attached_resource_id)
            for instance in instances:
                anonymized_id = anonymizer.anonymize_aws_id(instance.instance_id, 'i')
                original_anonymized = anonymized_id
                counter = 0
                while anonymized_id in anonymized_instance_ids.values():
                    counter += 1
                    anonymized_id = f"{original_anonymized}-{counter}"
                anonymized_instance_ids[instance.id] = anonymized_id
                original_to_anonymized_instance[instance.instance_id] = anonymized_id
            
            instance_count = 0
            for instance in instances:
                instance.instance_id = anonymized_instance_ids[instance.id]
                instance.name = anonymizer.anonymize_name(instance.name) if instance.name else instance.name
                if instance.private_ip_address:
                    instance.private_ip_address = anonymizer.anonymize_ip(str(instance.private_ip_address))
                if instance.public_ip_address:
                    instance.public_ip_address = anonymizer.anonymize_ip(str(instance.public_ip_address))
                instance.owner_account = anonymizer.anonymize_account_id(instance.owner_account)
                instance.tags = anonymizer.anonymize_tags(instance.tags)
                if not dry_run:
                    try:
                        instance.save(update_fields=['instance_id', 'name', 'private_ip_address', 'public_ip_address', 'owner_account', 'tags'])
                    except IntegrityError as e:
                        self.stdout.write(self.style.ERROR(f'  Error updating EC2 Instance {instance.id}: {e}'))
                        raise
                instance_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {instance_count} EC2 Instances'))
            
            # Anonymize ENIs
            self.stdout.write('Anonymizing ENIs...')
            enis = list(ENI.objects.all())
            # Pre-compute anonymized IDs to check for collisions
            anonymized_eni_ids = {}  # Maps model id -> anonymized eni_id
            original_to_anonymized_eni = {}  # Maps original eni_id -> anonymized eni_id (for ENI attached_resource_id)
            for eni in enis:
                anonymized_id = anonymizer.anonymize_aws_id(eni.eni_id, 'eni')
                original_anonymized = anonymized_id
                counter = 0
                while anonymized_id in anonymized_eni_ids.values():
                    counter += 1
                    anonymized_id = f"{original_anonymized}-{counter}"
                anonymized_eni_ids[eni.id] = anonymized_id
                original_to_anonymized_eni[eni.eni_id] = anonymized_id
            
            eni_count = 0
            for eni in enis:
                eni.eni_id = anonymized_eni_ids[eni.id]
                eni.name = anonymizer.anonymize_name(eni.name) if eni.name else eni.name
                eni.description = anonymizer.anonymize_description(eni.description) if eni.description else eni.description
                eni.private_ip_address = anonymizer.anonymize_ip(str(eni.private_ip_address))
                if eni.public_ip_address:
                    eni.public_ip_address = anonymizer.anonymize_ip(str(eni.public_ip_address))
                if eni.mac_address:
                    eni.mac_address = anonymizer.anonymize_mac_address(eni.mac_address)
                if eni.attached_resource_id:
                    # Use the mapping if this resource was already anonymized
                    if eni.attached_resource_id.startswith('i-') and eni.attached_resource_id in original_to_anonymized_instance:
                        eni.attached_resource_id = original_to_anonymized_instance[eni.attached_resource_id]
                    elif eni.attached_resource_id.startswith('eni-') and eni.attached_resource_id in original_to_anonymized_eni:
                        eni.attached_resource_id = original_to_anonymized_eni[eni.attached_resource_id]
                    elif eni.attached_resource_id.startswith('i-'):
                        eni.attached_resource_id = anonymizer.anonymize_aws_id(eni.attached_resource_id, 'i')
                    elif eni.attached_resource_id.startswith('eni-'):
                        eni.attached_resource_id = anonymizer.anonymize_aws_id(eni.attached_resource_id, 'eni')
                    else:
                        eni.attached_resource_id = anonymizer.anonymize_name(eni.attached_resource_id)
                eni.owner_account = anonymizer.anonymize_account_id(eni.owner_account) if eni.owner_account else eni.owner_account
                eni.tags = anonymizer.anonymize_tags(eni.tags)
                if not dry_run:
                    try:
                        eni.save(update_fields=['eni_id', 'name', 'description', 'private_ip_address', 'public_ip_address', 'mac_address', 'attached_resource_id', 'owner_account', 'tags'])
                    except IntegrityError as e:
                        self.stdout.write(self.style.ERROR(f'  Error updating ENI {eni.id}: {e}'))
                        raise
                eni_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {eni_count} ENIs'))
            
            # Anonymize ENI Secondary IPs
            self.stdout.write('Anonymizing ENI Secondary IPs...')
            secondary_ips = ENISecondaryIP.objects.all()
            secondary_ip_count = 0
            for sec_ip in secondary_ips:
                sec_ip.ip_address = anonymizer.anonymize_ip(str(sec_ip.ip_address))
                if not dry_run:
                    sec_ip.save(update_fields=['ip_address'])
                secondary_ip_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {secondary_ip_count} ENI Secondary IPs'))
            
            # Anonymize AWS Accounts (optional - account IDs and names)
            self.stdout.write('Anonymizing AWS Accounts...')
            accounts = list(AWSAccount.objects.all())
            # Pre-compute anonymized IDs to check for collisions
            anonymized_account_ids = {}
            for account in accounts:
                anonymized_id = anonymizer.anonymize_account_id(account.account_id)
                original_anonymized = anonymized_id
                counter = 0
                while anonymized_id in anonymized_account_ids.values():
                    counter += 1
                    anonymized_id = f"{original_anonymized[:10]}{counter:02d}"
                anonymized_account_ids[account.id] = anonymized_id
            
            account_count = 0
            for account in accounts:
                account.account_id = anonymized_account_ids[account.id]
                account.account_name = anonymizer.anonymize_name(account.account_name) if account.account_name else account.account_name
                if not dry_run:
                    try:
                        account.save(update_fields=['account_id', 'account_name'])
                    except IntegrityError as e:
                        self.stdout.write(self.style.ERROR(f'  Error updating AWS Account {account.id}: {e}'))
                        raise
                account_count += 1
            self.stdout.write(self.style.SUCCESS(f'  Processed {account_count} AWS Accounts'))
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    '\nDRY RUN - No changes were made. Use --confirm to apply changes.'
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    '\n✓ Data anonymization completed successfully!'
                )
            )

