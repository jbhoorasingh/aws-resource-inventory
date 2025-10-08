"""
Django management command to discover AWS resources
"""
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from resources.services import AWSResourceDiscovery
from resources.models import (
    AWSAccount, VPC, Subnet, SecurityGroup, ENI, 
    ENISecondaryIP, ENISecurityGroup
)
from django.db import transaction
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Discover AWS resources with IP addresses/ENIs across specified regions. Usage: discover_aws_resources <account_number> <access_key_id> <secret_access_key> <session_token> <regions...>'

    def add_arguments(self, parser):
        parser.add_argument(
            'account_number',
            type=str,
            help='AWS Account Number (required)'
        )
        parser.add_argument(
            'access_key_id',
            type=str,
            help='AWS Access Key ID (required)'
        )
        parser.add_argument(
            'secret_access_key',
            type=str,
            help='AWS Secret Access Key (required)'
        )
        parser.add_argument(
            'session_token',
            type=str,
            help='AWS Session Token (required)'
        )
        parser.add_argument(
            'regions',
            nargs='+',
            help='AWS regions to scan (required)'
        )
        parser.add_argument(
            '--account-name',
            type=str,
            help='Account name/alias for this discovery (optional)'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be discovered without saving to database'
        )

    def handle(self, *args, **options):
        account_number = options['account_number']
        regions = options['regions']
        access_key_id = options['access_key_id']
        secret_access_key = options['secret_access_key']
        session_token = options['session_token']
        account_name = options.get('account_name')
        dry_run = options['dry_run']

        self.stdout.write(
            self.style.SUCCESS(f'Starting AWS resource discovery for account {account_number} in regions: {", ".join(regions)}')
        )

        try:
            # Initialize AWS discovery service
            discovery = AWSResourceDiscovery(
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                session_token=session_token
            )

            # Verify account ID matches
            discovered_account_id = discovery.get_account_id()
            if discovered_account_id != account_number:
                raise CommandError(
                    f'Account ID mismatch: provided {account_number}, but credentials belong to {discovered_account_id}'
                )
            
            self.stdout.write(f'Verified account ID: {account_number}')

            if dry_run:
                self.stdout.write(self.style.WARNING('DRY RUN MODE - No data will be saved'))
                results = discovery.discover_all_resources(regions)
                self._print_summary(results)
                return

            # Discover all resources
            results = discovery.discover_all_resources(regions)
            
            # Save to database
            with transaction.atomic():
                account = self._get_or_create_account(account_number, account_name)
                self._save_resources(account, results)

            self.stdout.write(
                self.style.SUCCESS('AWS resource discovery completed successfully!')
            )
            self._print_summary(results)

        except Exception as e:
            logger.error(f"AWS resource discovery failed: {e}")
            raise CommandError(f'Discovery failed: {e}')

    def _get_or_create_account(self, account_id: str, account_name: str = None):
        """Get or create AWS account"""
        from django.utils import timezone
        
        account, created = AWSAccount.objects.get_or_create(
            account_id=account_id,
            defaults={'account_name': account_name or '', 'is_active': True}
        )
        
        # Update last_polled timestamp
        account.last_polled = timezone.now()
        account.save()
        
        if created:
            self.stdout.write(f'Created new account: {account}')
        else:
            self.stdout.write(f'Using existing account: {account} (last polled: {account.last_polled})')
        return account

    def _save_resources(self, account: AWSAccount, results: dict):
        """Save discovered resources to database"""
        total_saved = 0

        for region, region_data in results['regions'].items():
            self.stdout.write(f'Processing region: {region}')
            
            # Save VPCs
            for vpc_data in region_data['vpcs']:
                vpc, created = VPC.objects.update_or_create(
                    vpc_id=vpc_data['vpc_id'],
                    defaults={
                        'region': region,
                        'cidr_block': vpc_data['cidr_block'],
                        'owner_account': vpc_data['owner_id'],
                        'is_default': vpc_data['is_default'],
                        'state': vpc_data['state']
                    }
                )
                if created:
                    total_saved += 1

            # Save Subnets
            for subnet_data in region_data['subnets']:
                try:
                    vpc = VPC.objects.get(vpc_id=subnet_data['vpc_id'])
                    subnet, created = Subnet.objects.update_or_create(
                        subnet_id=subnet_data['subnet_id'],
                        defaults={
                            'vpc': vpc,
                            'name': subnet_data['tags'].get('Name', ''),
                            'cidr_block': subnet_data['cidr_block'],
                            'availability_zone': subnet_data['availability_zone'],
                            'owner_account': subnet_data['owner_id'],
                            'state': subnet_data['state']
                        }
                    )
                    if created:
                        total_saved += 1
                except VPC.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'VPC {subnet_data["vpc_id"]} not found for subnet {subnet_data["subnet_id"]}')
                    )

            # Save Security Groups
            for sg_data in region_data['security_groups']:
                try:
                    vpc = VPC.objects.get(vpc_id=sg_data['vpc_id'])
                    sg, created = SecurityGroup.objects.update_or_create(
                        sg_id=sg_data['sg_id'],
                        defaults={
                            'vpc': vpc,
                            'name': sg_data['name'],
                            'description': sg_data['description']
                        }
                    )
                    if created:
                        total_saved += 1

                    # Save security group rules
                    from resources.models import SecurityGroupRule
                    # Clear existing rules
                    SecurityGroupRule.objects.filter(security_group=sg).delete()
                    
                    # Save new rules
                    for rule_data in sg_data.get('rules', []):
                        SecurityGroupRule.objects.create(
                            security_group=sg,
                            rule_type=rule_data['rule_type'],
                            protocol=rule_data['protocol'],
                            from_port=rule_data['from_port'],
                            to_port=rule_data['to_port'],
                            source_type=rule_data['source_type'],
                            source_value=rule_data['source_value'],
                            description=rule_data['description']
                        )

                except VPC.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'VPC {sg_data["vpc_id"]} not found for security group {sg_data["sg_id"]}')
                    )

            # Save ENIs
            for eni_data in region_data['enis']:
                try:
                    subnet = Subnet.objects.get(subnet_id=eni_data['subnet_id'])
                    eni, created = ENI.objects.update_or_create(
                        eni_id=eni_data['eni_id'],
                        defaults={
                            'subnet': subnet,
                            'name': eni_data['name'],
                            'description': eni_data['description'],
                            'interface_type': eni_data['interface_type'],
                            'status': eni_data['status'],
                            'mac_address': eni_data['mac_address'],
                            'private_ip_address': eni_data['private_ip_address'],
                            'public_ip_address': eni_data['public_ip_address'],
                            'attached_resource_id': eni_data['attached_resource_id'],
                            'attached_resource_type': eni_data['attached_resource_type'],
                            'owner_account': eni_data['owner_id']  # Use ENI's owner_id (already processed in service)
                        }
                    )
                    if created:
                        total_saved += 1

                    # Clear existing secondary IPs and save new ones
                    ENISecondaryIP.objects.filter(eni=eni).delete()
                    for secondary_ip in eni_data['secondary_ips']:
                        ENISecondaryIP.objects.create(
                            eni=eni,
                            ip_address=secondary_ip
                        )

                    # Clear existing ENI-Security Group relationships and save new ones
                    ENISecurityGroup.objects.filter(eni=eni).delete()
                    for sg_id in eni_data['security_group_ids']:
                        try:
                            sg = SecurityGroup.objects.get(sg_id=sg_id)
                            ENISecurityGroup.objects.create(
                                eni=eni,
                                security_group=sg
                            )
                        except SecurityGroup.DoesNotExist:
                            self.stdout.write(
                                self.style.WARNING(f'Security Group {sg_id} not found for ENI {eni_data["eni_id"]}')
                            )

                except Subnet.DoesNotExist:
                    self.stdout.write(
                        self.style.WARNING(f'Subnet {eni_data["subnet_id"]} not found for ENI {eni_data["eni_id"]}')
                    )

        self.stdout.write(f'Total new resources saved: {total_saved}')

    def _print_summary(self, results: dict):
        """Print discovery summary"""
        self.stdout.write('\n' + '='*50)
        self.stdout.write('DISCOVERY SUMMARY')
        self.stdout.write('='*50)
        self.stdout.write(f'Account ID: {results["account_id"]}')
        self.stdout.write(f'Regions scanned: {len(results["regions"])}')
        
        summary = results['summary']
        self.stdout.write(f'Total VPCs: {summary["total_vpcs"]}')
        self.stdout.write(f'Total Subnets: {summary["total_subnets"]}')
        self.stdout.write(f'Total Security Groups: {summary["total_security_groups"]}')
        self.stdout.write(f'Total ENIs: {summary["total_enis"]}')
        
        for region, region_data in results['regions'].items():
            self.stdout.write(f'\n{region}:')
            self.stdout.write(f'  VPCs: {len(region_data["vpcs"])}')
            self.stdout.write(f'  Subnets: {len(region_data["subnets"])}')
            self.stdout.write(f'  Security Groups: {len(region_data["security_groups"])}')
            self.stdout.write(f'  ENIs: {len(region_data["enis"])}')
