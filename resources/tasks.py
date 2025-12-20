"""
Celery tasks for AWS resource discovery
"""
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from django.conf import settings
from django.utils import timezone
from django.db import transaction
import logging

from .models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance, DiscoveryTask
)
from .services import AWSResourceDiscovery

logger = logging.getLogger(__name__)


def _delete_account_enis_and_ec2(account_id: str) -> dict:
    """
    Delete ENIs and EC2 instances for an account before re-discovery.

    This is a safe deletion that only removes account-specific resources.
    VPCs, Subnets, and Security Groups are NOT deleted here since they may be
    shared across accounts (via VPC sharing/RAM).

    Args:
        account_id: The AWS account ID (12-digit string)

    Returns:
        Dictionary with counts of deleted resources
    """
    counts = {
        'enis': 0,
        'eni_secondary_ips': 0,
        'eni_security_groups': 0,
        'ec2_instances': 0,
    }

    # Get ENIs owned by this account
    enis = ENI.objects.filter(owner_account=account_id)
    eni_ids = list(enis.values_list('id', flat=True))

    if eni_ids:
        # Delete ENI secondary IPs
        counts['eni_secondary_ips'] = ENISecondaryIP.objects.filter(
            eni_id__in=eni_ids
        ).delete()[0]

        # Delete ENI-SecurityGroup relationships
        counts['eni_security_groups'] = ENISecurityGroup.objects.filter(
            eni_id__in=eni_ids
        ).delete()[0]

        # Delete ENIs
        counts['enis'] = enis.delete()[0]

    # Delete EC2 instances owned by this account
    counts['ec2_instances'] = EC2Instance.objects.filter(
        owner_account=account_id
    ).delete()[0]

    if any(counts.values()):
        logger.info(
            f"Deleted account resources for {account_id}: "
            f"{counts['enis']} ENIs, {counts['ec2_instances']} EC2 Instances, "
            f"{counts['eni_secondary_ips']} Secondary IPs, {counts['eni_security_groups']} ENI-SG links"
        )
    else:
        logger.info(f"No ENIs or EC2 instances found for account {account_id}")

    return counts


def _cleanup_orphaned_vpcs(account_id: str, discovered_vpc_ids: set) -> dict:
    """
    Clean up orphaned VPCs that no longer exist in AWS.

    Only deletes VPCs that:
    1. Are owned by this account
    2. Have no remaining ENIs or EC2 instances
    3. Were NOT found in the current discovery (no longer exist in AWS)

    Args:
        account_id: The AWS account ID
        discovered_vpc_ids: Set of VPC IDs found in the current AWS discovery

    Returns:
        Dictionary with counts of deleted resources
    """
    counts = {
        'vpcs': 0,
        'subnets': 0,
        'security_groups': 0,
        'security_group_rules': 0,
    }

    # Find VPCs owned by this account that weren't in the discovery results
    orphaned_vpcs = VPC.objects.filter(
        owner_account=account_id
    ).exclude(
        vpc_id__in=discovered_vpc_ids
    )

    for vpc in orphaned_vpcs:
        # Check if VPC has any remaining ENIs or EC2 instances
        has_enis = ENI.objects.filter(subnet__vpc=vpc).exists()
        has_ec2 = EC2Instance.objects.filter(vpc=vpc).exists()

        if not has_enis and not has_ec2:
            # Safe to delete - VPC is orphaned and has no child resources
            vpc_id = vpc.vpc_id

            # Count related resources before deletion
            subnet_count = Subnet.objects.filter(vpc=vpc).count()
            sg_count = SecurityGroup.objects.filter(vpc=vpc).count()
            rule_count = SecurityGroupRule.objects.filter(security_group__vpc=vpc).count()

            # Delete VPC (cascades to subnets, security groups, rules)
            vpc.delete()

            counts['vpcs'] += 1
            counts['subnets'] += subnet_count
            counts['security_groups'] += sg_count
            counts['security_group_rules'] += rule_count

            logger.info(
                f"Deleted orphaned VPC {vpc_id} (not in AWS, no remaining ENIs/EC2): "
                f"{subnet_count} subnets, {sg_count} security groups"
            )

    if counts['vpcs']:
        logger.info(
            f"Cleaned up {counts['vpcs']} orphaned VPCs for account {account_id}"
        )

    return counts


@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def discover_account_resources(
    self,
    task_record_id: int,
    account_number: str,
    account_name: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str,
    regions: list,
    role_arn: str = None,
    external_id: str = None,
):
    """
    Celery task to discover AWS resources for a single account.

    This task wraps the existing AWSResourceDiscovery service and handles:
    - Task status updates
    - Error handling and retries
    - Result logging
    """
    task_record = DiscoveryTask.objects.get(id=task_record_id)

    try:
        # Update task status to running
        task_record.status = 'running'
        task_record.started_at = timezone.now()
        task_record.task_id = self.request.id
        task_record.save(update_fields=['status', 'started_at', 'task_id'])

        logger.info(f"Starting discovery for account {account_number}")

        # Initialize AWS discovery service (reusing existing service)
        discovery = AWSResourceDiscovery(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token or None,
            role_arn=role_arn or None,
            external_id=external_id or None
        )

        # Verify account ID matches
        discovered_account_id = discovery.get_account_id()
        if role_arn:
            if discovered_account_id != account_number:
                raise ValueError(
                    f'Role assumption failed: assumed role account is '
                    f'{discovered_account_id}, but expected {account_number}'
                )
        else:
            if discovered_account_id != account_number:
                raise ValueError(
                    f'Account ID mismatch: provided {account_number}, '
                    f'but credentials belong to {discovered_account_id}'
                )

        # Discover all resources
        results = discovery.discover_all_resources(regions)

        # Extract discovered VPC IDs for orphan cleanup
        discovered_vpc_ids = set()
        for region_data in results.get('regions', {}).values():
            for vpc in region_data.get('vpcs', []):
                discovered_vpc_ids.add(vpc['vpc_id'])

        # Save to database
        with transaction.atomic():
            account = _get_or_create_account(
                account_number, account_name, role_arn, external_id
            )
            # Delete existing ENIs and EC2 instances before saving new ones
            # (VPCs, Subnets, SGs are kept as they may be shared)
            _delete_account_enis_and_ec2(account_number)
            _save_resources(account, results)
            # Clean up orphaned VPCs that no longer exist in AWS
            _cleanup_orphaned_vpcs(account_number, discovered_vpc_ids)

        # Update task record with success
        task_record.status = 'success'
        task_record.completed_at = timezone.now()
        task_record.result_summary = results.get('summary', {})
        task_record.save(update_fields=[
            'status', 'completed_at', 'result_summary'
        ])

        # Update parent task progress if this is a child task
        if task_record.parent_task:
            _update_parent_task_progress(task_record.parent_task.id)

        logger.info(f"Successfully completed discovery for account {account_number}")

        return {
            'status': 'success',
            'account_number': account_number,
            'summary': results.get('summary', {})
        }

    except SoftTimeLimitExceeded:
        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = 'Task exceeded time limit'
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        if task_record.parent_task:
            _update_parent_task_progress(task_record.parent_task.id)

        raise

    except Exception as e:
        logger.error(f"Discovery failed for account {account_number}: {str(e)}")

        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = str(e)
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        if task_record.parent_task:
            _update_parent_task_progress(task_record.parent_task.id)

        # Optionally retry
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)

        return {
            'status': 'failed',
            'account_number': account_number,
            'error': str(e)
        }


@shared_task(bind=True)
def bulk_discover_resources(
    self,
    task_record_id: int,
    access_key_id: str,
    secret_access_key: str,
    session_token: str,
    regions: list,
    accounts_config: list,
    user_id: int
):
    """
    Celery task to orchestrate bulk discovery across multiple accounts.

    Creates child tasks for each account and tracks overall progress.
    """
    task_record = DiscoveryTask.objects.get(id=task_record_id)

    try:
        task_record.status = 'running'
        task_record.started_at = timezone.now()
        task_record.task_id = self.request.id
        task_record.total_accounts = len(accounts_config)
        task_record.save(update_fields=[
            'status', 'started_at', 'task_id', 'total_accounts'
        ])

        child_task_ids = []

        for account_config in accounts_config:
            # Get or create account in database immediately
            account, _ = AWSAccount.objects.get_or_create(
                account_id=account_config['account_number'],
                defaults={
                    'account_name': account_config.get('account_name', ''),
                    'role_arn': account_config.get('role_arn', ''),
                    'external_id': account_config.get('external_id', ''),
                    'is_active': True
                }
            )

            # Create child task record
            child_task = DiscoveryTask.objects.create(
                task_type='single',
                status='pending',
                account=account,
                regions=regions,
                initiated_by_id=user_id,
                parent_task=task_record,
                total_accounts=1
            )

            # Queue the discovery task
            discover_account_resources.delay(
                task_record_id=child_task.id,
                account_number=account_config['account_number'],
                account_name=account_config.get('account_name', ''),
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                session_token=session_token,
                regions=regions,
                role_arn=account_config.get('role_arn'),
                external_id=account_config.get('external_id'),
            )

            child_task_ids.append(child_task.id)

        logger.info(f"Bulk discovery queued {len(accounts_config)} account tasks")

        return {
            'status': 'started',
            'total_accounts': len(accounts_config),
            'child_task_ids': child_task_ids
        }

    except Exception as e:
        logger.error(f"Bulk discovery setup failed: {str(e)}")
        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = str(e)
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])
        raise


def _update_parent_task_progress(parent_task_id: int):
    """
    Update the status of a bulk discovery task based on child task results.
    """
    parent_task = DiscoveryTask.objects.get(id=parent_task_id)
    child_tasks = parent_task.child_tasks.all()

    completed = child_tasks.filter(status='success').count()
    failed = child_tasks.filter(status='failed').count()
    total = child_tasks.count()

    parent_task.completed_accounts = completed
    parent_task.failed_accounts = failed

    # Update parent status if all children are done
    if completed + failed >= total:
        if failed == 0:
            parent_task.status = 'success'
        elif completed == 0:
            parent_task.status = 'failed'
        else:
            parent_task.status = 'success'  # Partial success
        parent_task.completed_at = timezone.now()

    parent_task.save()


def _get_or_create_account(account_id: str, account_name: str = None,
                           role_arn: str = None, external_id: str = None):
    """Get or create AWS account"""
    defaults = {
        'account_name': account_name or '',
        'is_active': True
    }

    if role_arn:
        defaults['role_arn'] = role_arn
    if external_id:
        defaults['external_id'] = external_id

    account, created = AWSAccount.objects.get_or_create(
        account_id=account_id,
        defaults=defaults
    )

    if not created:
        if account_name:
            account.account_name = account_name
        if role_arn is not None:
            account.role_arn = role_arn
        if external_id is not None:
            account.external_id = external_id

    account.last_polled = timezone.now()
    account.save()
    return account


@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def repoll_account_with_instance_role(
    self,
    task_record_id: int,
    account_id: int,
):
    """
    Celery task to re-poll an account using EC2 instance role authentication.

    This is used for accounts configured with instance_role auth method.
    The instance role is used to assume the target account's discovery role.
    """
    task_record = DiscoveryTask.objects.get(id=task_record_id)

    try:
        # Get the account
        account = AWSAccount.objects.get(id=account_id)

        # Update task status to running
        task_record.status = 'running'
        task_record.started_at = timezone.now()
        task_record.task_id = self.request.id
        task_record.save(update_fields=['status', 'started_at', 'task_id'])

        logger.info(f"Starting instance role discovery for account {account.account_id}")

        # Get the role ARN (from explicit or constructed from default_role_name)
        role_arn = account.get_role_arn()
        if not role_arn:
            raise ValueError(
                f'No role ARN configured for account {account.account_id}. '
                f'Set role_arn or default_role_name.'
            )

        # Get regions to poll
        regions = account.default_regions
        if not regions:
            raise ValueError(
                f'No regions configured for account {account.account_id}. '
                f'Set default_regions for re-polling.'
            )

        # Initialize AWS discovery service with instance role
        discovery = AWSResourceDiscovery(
            use_instance_role=True,
            role_arn=role_arn,
            external_id=account.external_id or None
        )

        # Verify account ID matches
        discovered_account_id = discovery.get_account_id()
        if discovered_account_id != account.account_id:
            raise ValueError(
                f'Role assumption failed: assumed role account is '
                f'{discovered_account_id}, but expected {account.account_id}'
            )

        # Discover all resources
        results = discovery.discover_all_resources(regions)

        # Extract discovered VPC IDs for orphan cleanup
        discovered_vpc_ids = set()
        for region_data in results.get('regions', {}).values():
            for vpc in region_data.get('vpcs', []):
                discovered_vpc_ids.add(vpc['vpc_id'])

        # Save to database
        with transaction.atomic():
            # Delete existing ENIs and EC2 instances before saving new ones
            # (VPCs, Subnets, SGs are kept as they may be shared)
            _delete_account_enis_and_ec2(account.account_id)
            _save_resources(account, results)
            # Clean up orphaned VPCs that no longer exist in AWS
            _cleanup_orphaned_vpcs(account.account_id, discovered_vpc_ids)
            account.last_polled = timezone.now()
            account.save(update_fields=['last_polled'])

        # Update task record with success
        task_record.status = 'success'
        task_record.completed_at = timezone.now()
        task_record.result_summary = results.get('summary', {})
        task_record.save(update_fields=[
            'status', 'completed_at', 'result_summary'
        ])

        logger.info(f"Successfully completed instance role discovery for account {account.account_id}")

        return {
            'status': 'success',
            'account_number': account.account_id,
            'summary': results.get('summary', {})
        }

    except SoftTimeLimitExceeded:
        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = 'Task exceeded time limit'
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])
        raise

    except Exception as e:
        logger.error(f"Instance role discovery failed: {str(e)}")

        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = str(e)
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        # Optionally retry
        if self.request.retries < self.max_retries:
            raise self.retry(exc=e)

        return {
            'status': 'failed',
            'error': str(e)
        }


@shared_task(bind=True)
def bulk_repoll_accounts_with_instance_role(
    self,
    task_record_id: int,
    account_ids: list,
    user_id: int
):
    """
    Celery task to re-poll multiple accounts using EC2 instance role authentication.

    Creates child tasks for each account.
    """
    task_record = DiscoveryTask.objects.get(id=task_record_id)

    try:
        task_record.status = 'running'
        task_record.started_at = timezone.now()
        task_record.task_id = self.request.id
        task_record.total_accounts = len(account_ids)
        task_record.save(update_fields=[
            'status', 'started_at', 'task_id', 'total_accounts'
        ])

        child_task_ids = []

        for account_id in account_ids:
            account = AWSAccount.objects.get(id=account_id)

            # Skip accounts that can't be re-polled
            if not account.can_repoll:
                logger.warning(
                    f"Account {account.account_id} cannot be re-polled with instance role"
                )
                continue

            # Create child task record
            child_task = DiscoveryTask.objects.create(
                task_type='single',
                status='pending',
                account=account,
                regions=account.default_regions,
                initiated_by_id=user_id,
                parent_task=task_record,
                total_accounts=1
            )

            # Queue the discovery task
            repoll_account_with_instance_role.delay(
                task_record_id=child_task.id,
                account_id=account.id
            )

            child_task_ids.append(child_task.id)

        # Update total accounts to actual number queued
        task_record.total_accounts = len(child_task_ids)
        task_record.save(update_fields=['total_accounts'])

        logger.info(f"Bulk instance role repoll queued {len(child_task_ids)} account tasks")

        return {
            'status': 'started',
            'total_accounts': len(child_task_ids),
            'child_task_ids': child_task_ids
        }

    except Exception as e:
        logger.error(f"Bulk instance role repoll setup failed: {str(e)}")
        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = str(e)
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])
        raise


def _save_resources(account: AWSAccount, results: dict):
    """Save discovered resources to database"""
    for region, region_data in results['regions'].items():
        logger.info(f"Processing region {region}: "
                   f"{len(region_data['vpcs'])} VPCs, "
                   f"{len(region_data['subnets'])} Subnets, "
                   f"{len(region_data['security_groups'])} Security Groups, "
                   f"{len(region_data.get('ec2_instances', []))} EC2 Instances, "
                   f"{len(region_data['enis'])} ENIs")

        # Save VPCs
        for vpc_data in region_data['vpcs']:
            VPC.objects.update_or_create(
                vpc_id=vpc_data['vpc_id'],
                defaults={
                    'region': region,
                    'cidr_block': vpc_data['cidr_block'],
                    'owner_account': vpc_data['owner_id'],
                    'is_default': vpc_data['is_default'],
                    'state': vpc_data['state'],
                    'tags': vpc_data.get('tags', {})
                }
            )

        # Save Subnets
        for subnet_data in region_data['subnets']:
            try:
                vpc = VPC.objects.get(vpc_id=subnet_data['vpc_id'])
                Subnet.objects.update_or_create(
                    subnet_id=subnet_data['subnet_id'],
                    defaults={
                        'vpc': vpc,
                        'name': subnet_data['tags'].get('Name', ''),
                        'cidr_block': subnet_data['cidr_block'],
                        'availability_zone': subnet_data['availability_zone'],
                        'owner_account': subnet_data['owner_id'],
                        'state': subnet_data['state'],
                        'tags': subnet_data.get('tags', {})
                    }
                )
            except VPC.DoesNotExist:
                logger.warning(f'VPC {subnet_data["vpc_id"]} not found for subnet {subnet_data["subnet_id"]}')

        # Save Security Groups
        for sg_data in region_data['security_groups']:
            try:
                vpc = VPC.objects.get(vpc_id=sg_data['vpc_id'])
                sg, _ = SecurityGroup.objects.update_or_create(
                    sg_id=sg_data['sg_id'],
                    defaults={
                        'vpc': vpc,
                        'name': sg_data['name'],
                        'description': sg_data['description'],
                        'tags': sg_data.get('tags', {})
                    }
                )

                # Clear existing rules and save new ones
                SecurityGroupRule.objects.filter(security_group=sg).delete()
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
                logger.warning(f'VPC {sg_data["vpc_id"]} not found for security group {sg_data["sg_id"]}')

        # Save EC2 Instances
        for instance_data in region_data.get('ec2_instances', []):
            try:
                vpc = VPC.objects.get(vpc_id=instance_data['vpc_id'])
                subnet = Subnet.objects.get(subnet_id=instance_data['subnet_id'])
                EC2Instance.objects.update_or_create(
                    instance_id=instance_data['instance_id'],
                    region=region,
                    defaults={
                        'vpc': vpc,
                        'subnet': subnet,
                        'name': instance_data['name'],
                        'instance_type': instance_data['instance_type'],
                        'state': instance_data['state'],
                        'availability_zone': instance_data['availability_zone'],
                        'private_ip_address': instance_data['private_ip_address'],
                        'public_ip_address': instance_data['public_ip_address'],
                        'platform': instance_data['platform'],
                        'launch_time': instance_data['launch_time'],
                        'owner_account': instance_data['owner_id'],
                        'tags': instance_data.get('tags', {})
                    }
                )
            except (VPC.DoesNotExist, Subnet.DoesNotExist) as e:
                logger.warning(f'VPC or Subnet not found for instance {instance_data["instance_id"]}: {e}')

        # Save ENIs
        for eni_data in region_data['enis']:
            try:
                subnet = Subnet.objects.get(subnet_id=eni_data['subnet_id'])

                # Link to EC2 instance if attached
                ec2_instance = None
                if eni_data['attached_resource_type'] == 'instance' and eni_data['attached_resource_id']:
                    try:
                        ec2_instance = EC2Instance.objects.get(instance_id=eni_data['attached_resource_id'])
                    except EC2Instance.DoesNotExist:
                        logger.warning(f'EC2 instance {eni_data["attached_resource_id"]} not found for ENI {eni_data["eni_id"]}')

                eni, _ = ENI.objects.update_or_create(
                    eni_id=eni_data['eni_id'],
                    defaults={
                        'subnet': subnet,
                        'ec2_instance': ec2_instance,
                        'name': eni_data['name'],
                        'description': eni_data['description'],
                        'interface_type': eni_data['interface_type'],
                        'status': eni_data['status'],
                        'mac_address': eni_data['mac_address'],
                        'private_ip_address': eni_data['private_ip_address'],
                        'public_ip_address': eni_data['public_ip_address'],
                        'attached_resource_id': eni_data['attached_resource_id'],
                        'attached_resource_type': eni_data['attached_resource_type'],
                        'owner_account': eni_data['owner_id'],
                        'tags': eni_data.get('tags', {})
                    }
                )

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
                        logger.warning(f'Security Group {sg_id} not found for ENI {eni_data["eni_id"]}')

            except Subnet.DoesNotExist:
                logger.warning(f'Subnet {eni_data["subnet_id"]} not found for ENI {eni_data["eni_id"]}')


@shared_task(bind=True)
def scheduled_poll_instance_role_accounts(self):
    """
    Scheduled task to poll all accounts with instance_role auth method.

    This task runs hourly via Celery Beat and:
    - Gets all active accounts configured for instance role authentication
    - Creates a parent DiscoveryTask to track overall progress
    - Queues child tasks for each account with staggered countdowns for rate limiting

    Rate limiting is controlled by settings:
    - SCHEDULED_POLLING_ENABLED: Toggle scheduled polling on/off
    - SCHEDULED_POLLING_MAX_CONCURRENT: Maximum concurrent polls
    - SCHEDULED_POLLING_STAGGER_SECONDS: Seconds between poll starts
    """
    # Check if scheduled polling is enabled
    if not getattr(settings, 'SCHEDULED_POLLING_ENABLED', True):
        logger.info("Scheduled polling is disabled")
        return {'status': 'disabled', 'message': 'Scheduled polling is disabled'}

    # Get all accounts that can be re-polled with instance role
    accounts = AWSAccount.objects.filter(
        auth_method='instance_role',
        is_active=True,
    ).exclude(
        default_regions=[]
    ).exclude(
        default_role_name=''
    )

    if not accounts.exists():
        logger.info("No accounts configured for scheduled instance role polling")
        return {'status': 'skipped', 'message': 'No eligible accounts'}

    # Get rate limiting configuration
    max_concurrent = getattr(settings, 'SCHEDULED_POLLING_MAX_CONCURRENT', 2)
    stagger_seconds = getattr(settings, 'SCHEDULED_POLLING_STAGGER_SECONDS', 30)

    account_list = list(accounts)
    total_accounts = len(account_list)

    logger.info(
        f"Starting scheduled poll for {total_accounts} accounts "
        f"(max_concurrent={max_concurrent}, stagger={stagger_seconds}s)"
    )

    # Create parent task record for tracking
    parent_task = DiscoveryTask.objects.create(
        task_type='bulk',
        status='running',
        regions=[],  # Will vary per account
        total_accounts=total_accounts,
        # Note: No initiated_by since this is automated
    )
    parent_task.task_id = self.request.id
    parent_task.started_at = timezone.now()
    parent_task.save(update_fields=['task_id', 'started_at'])

    # Queue child tasks with staggered countdowns for rate limiting
    queued_count = 0
    child_task_ids = []

    for i, account in enumerate(account_list):
        # Create child task record
        child_task = DiscoveryTask.objects.create(
            task_type='single',
            status='pending',
            account=account,
            regions=account.default_regions,
            parent_task=parent_task,
            total_accounts=1
        )

        # Calculate countdown for staggering
        # batch_number * batch_size * stagger + position_in_batch * stagger
        batch_number = i // max_concurrent
        position_in_batch = i % max_concurrent
        countdown = (batch_number * max_concurrent + position_in_batch) * stagger_seconds

        # Queue the task with countdown for rate limiting
        repoll_account_with_instance_role.apply_async(
            kwargs={
                'task_record_id': child_task.id,
                'account_id': account.id
            },
            countdown=countdown
        )

        queued_count += 1
        child_task_ids.append(child_task.id)
        logger.info(
            f"Queued scheduled poll for account {account.account_id} "
            f"(countdown={countdown}s)"
        )

    logger.info(f"Scheduled poll queued {queued_count} account tasks")

    return {
        'status': 'started',
        'total_accounts': total_accounts,
        'queued': queued_count,
        'parent_task_id': parent_task.id,
        'child_task_ids': child_task_ids
    }
