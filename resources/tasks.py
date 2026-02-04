"""
Celery tasks for AWS resource discovery
"""
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.db import transaction
from django.db.models import F
import logging

from .models import (
    AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule,
    ENI, ENISecondaryIP, ENISecurityGroup, EC2Instance, DiscoveryTask
)
from .services import AWSResourceDiscovery

logger = logging.getLogger(__name__)

# Configuration constants
MISSED_POLLS_THRESHOLD = 3  # Number of missed polls before soft delete
TASK_TIMEOUT_HOURS = 3  # Hours before marking a task as timed out
TASK_RETENTION_DAYS = 30  # Days to keep task records
SOFT_DELETE_RETENTION_DAYS = 7  # Days to keep soft-deleted resources


def _mark_resources_for_cleanup(account_id: str, discovered_ids: dict) -> dict:
    """
    Mark resources not found in discovery for eventual soft delete.

    Uses a 3-missed-polls strategy:
    - Resources seen: reset missed_polls=0, update last_seen_at
    - Resources not seen: increment missed_polls
    - Resources with missed_polls >= 3: set deleted_at (soft delete)

    This approach handles shared VPCs gracefully since ENIs/EC2 from different
    accounts are tracked independently.

    Args:
        account_id: The AWS account ID (12-digit string)
        discovered_ids: Dict with keys 'eni_ids', 'ec2_ids', 'vpc_ids', 'subnet_ids', 'sg_ids'

    Returns:
        Dictionary with counts of affected resources
    """
    now = timezone.now()
    counts = {
        'enis_seen': 0,
        'enis_missed': 0,
        'enis_soft_deleted': 0,
        'ec2_seen': 0,
        'ec2_missed': 0,
        'ec2_soft_deleted': 0,
        'vpcs_seen': 0,
        'vpcs_missed': 0,
        'vpcs_soft_deleted': 0,
        'subnets_seen': 0,
        'subnets_missed': 0,
        'subnets_soft_deleted': 0,
        'sgs_seen': 0,
        'sgs_missed': 0,
        'sgs_soft_deleted': 0,
    }

    # --- ENIs owned by this account ---
    # Mark seen ENIs (reset missed_polls, update last_seen_at, resurrect if soft-deleted)
    counts['enis_seen'] = ENI.all_objects.filter(
        owner_account=account_id,
        eni_id__in=discovered_ids.get('eni_ids', [])
    ).update(last_seen_at=now, missed_polls=0, deleted_at=None)

    # Increment missed_polls for not-seen ENIs (only non-deleted ones)
    counts['enis_missed'] = ENI.objects.filter(
        owner_account=account_id,
        deleted_at__isnull=True
    ).exclude(
        eni_id__in=discovered_ids.get('eni_ids', [])
    ).update(missed_polls=F('missed_polls') + 1)

    # Soft delete ENIs with >= 3 missed polls
    counts['enis_soft_deleted'] = ENI.objects.filter(
        owner_account=account_id,
        missed_polls__gte=MISSED_POLLS_THRESHOLD,
        deleted_at__isnull=True
    ).update(deleted_at=now)

    # --- EC2 Instances owned by this account ---
    counts['ec2_seen'] = EC2Instance.all_objects.filter(
        owner_account=account_id,
        instance_id__in=discovered_ids.get('ec2_ids', [])
    ).update(last_seen_at=now, missed_polls=0, deleted_at=None)

    counts['ec2_missed'] = EC2Instance.objects.filter(
        owner_account=account_id,
        deleted_at__isnull=True
    ).exclude(
        instance_id__in=discovered_ids.get('ec2_ids', [])
    ).update(missed_polls=F('missed_polls') + 1)

    counts['ec2_soft_deleted'] = EC2Instance.objects.filter(
        owner_account=account_id,
        missed_polls__gte=MISSED_POLLS_THRESHOLD,
        deleted_at__isnull=True
    ).update(deleted_at=now)

    # --- VPCs owned by this account ---
    counts['vpcs_seen'] = VPC.all_objects.filter(
        owner_account=account_id,
        vpc_id__in=discovered_ids.get('vpc_ids', [])
    ).update(last_seen_at=now, missed_polls=0, deleted_at=None)

    counts['vpcs_missed'] = VPC.objects.filter(
        owner_account=account_id,
        deleted_at__isnull=True
    ).exclude(
        vpc_id__in=discovered_ids.get('vpc_ids', [])
    ).update(missed_polls=F('missed_polls') + 1)

    counts['vpcs_soft_deleted'] = VPC.objects.filter(
        owner_account=account_id,
        missed_polls__gte=MISSED_POLLS_THRESHOLD,
        deleted_at__isnull=True
    ).update(deleted_at=now)

    # --- Subnets owned by this account ---
    counts['subnets_seen'] = Subnet.all_objects.filter(
        owner_account=account_id,
        subnet_id__in=discovered_ids.get('subnet_ids', [])
    ).update(last_seen_at=now, missed_polls=0, deleted_at=None)

    counts['subnets_missed'] = Subnet.objects.filter(
        owner_account=account_id,
        deleted_at__isnull=True
    ).exclude(
        subnet_id__in=discovered_ids.get('subnet_ids', [])
    ).update(missed_polls=F('missed_polls') + 1)

    counts['subnets_soft_deleted'] = Subnet.objects.filter(
        owner_account=account_id,
        missed_polls__gte=MISSED_POLLS_THRESHOLD,
        deleted_at__isnull=True
    ).update(deleted_at=now)

    # --- Security Groups in VPCs owned by this account ---
    # SGs don't have owner_account, so we track by VPC ownership
    owned_vpc_ids = list(VPC.objects.filter(owner_account=account_id).values_list('vpc_id', flat=True))

    counts['sgs_seen'] = SecurityGroup.all_objects.filter(
        vpc__vpc_id__in=owned_vpc_ids,
        sg_id__in=discovered_ids.get('sg_ids', [])
    ).update(last_seen_at=now, missed_polls=0, deleted_at=None)

    counts['sgs_missed'] = SecurityGroup.objects.filter(
        vpc__vpc_id__in=owned_vpc_ids,
        deleted_at__isnull=True
    ).exclude(
        sg_id__in=discovered_ids.get('sg_ids', [])
    ).update(missed_polls=F('missed_polls') + 1)

    counts['sgs_soft_deleted'] = SecurityGroup.objects.filter(
        vpc__vpc_id__in=owned_vpc_ids,
        missed_polls__gte=MISSED_POLLS_THRESHOLD,
        deleted_at__isnull=True
    ).update(deleted_at=now)

    # Log summary
    soft_deleted = (
        counts['enis_soft_deleted'] + counts['ec2_soft_deleted'] +
        counts['vpcs_soft_deleted'] + counts['subnets_soft_deleted'] +
        counts['sgs_soft_deleted']
    )
    if soft_deleted > 0:
        logger.info(
            f"Soft deleted resources for {account_id}: "
            f"{counts['enis_soft_deleted']} ENIs, {counts['ec2_soft_deleted']} EC2, "
            f"{counts['vpcs_soft_deleted']} VPCs, {counts['subnets_soft_deleted']} Subnets, "
            f"{counts['sgs_soft_deleted']} SGs"
        )

    return counts


def _extract_discovered_ids(results: dict) -> dict:
    """
    Extract all resource IDs discovered in the results.

    Args:
        results: Discovery results from AWSResourceDiscovery

    Returns:
        Dictionary with sets of discovered IDs by resource type
    """
    discovered_ids = {
        'vpc_ids': set(),
        'subnet_ids': set(),
        'sg_ids': set(),
        'eni_ids': set(),
        'ec2_ids': set(),
    }

    for region_data in results.get('regions', {}).values():
        for vpc in region_data.get('vpcs', []):
            discovered_ids['vpc_ids'].add(vpc['vpc_id'])

        for subnet in region_data.get('subnets', []):
            discovered_ids['subnet_ids'].add(subnet['subnet_id'])

        for sg in region_data.get('security_groups', []):
            discovered_ids['sg_ids'].add(sg['sg_id'])

        for eni in region_data.get('enis', []):
            discovered_ids['eni_ids'].add(eni['eni_id'])

        for ec2 in region_data.get('ec2_instances', []):
            discovered_ids['ec2_ids'].add(ec2['instance_id'])

    return discovered_ids


def _get_polling_order(accounts: list) -> list:
    """
    Order accounts for polling: VPC owners first, then shared VPC users.

    This ensures that when an account has resources (ENIs, EC2) in a VPC
    owned by another account, the VPC-owning account is polled first.
    This way, the shared VPC/subnet infrastructure exists before we
    create ENIs/EC2 that reference them.

    Args:
        accounts: List of AWSAccount objects

    Returns:
        Ordered list of AWSAccount objects
    """
    if not accounts:
        return []

    # Get all account IDs
    account_ids = {a.account_id for a in accounts}

    # Find VPCs and their owners
    vpc_owners = {}  # vpc_id -> owner_account_id
    for vpc in VPC.objects.filter(owner_account__in=account_ids).values('vpc_id', 'owner_account'):
        vpc_owners[vpc['vpc_id']] = vpc['owner_account']

    # Find which accounts have ENIs in VPCs they don't own
    accounts_with_shared_vpc_resources = set()
    for eni in ENI.objects.filter(
        owner_account__in=account_ids,
        subnet__isnull=False
    ).select_related('subnet__vpc').values('owner_account', 'subnet__vpc__vpc_id', 'subnet__vpc__owner_account'):
        eni_owner = eni['owner_account']
        vpc_owner = eni['subnet__vpc__owner_account']
        if eni_owner != vpc_owner and vpc_owner in account_ids:
            accounts_with_shared_vpc_resources.add(eni_owner)

    # Split accounts into two groups
    vpc_owner_accounts = []
    shared_vpc_user_accounts = []

    for account in accounts:
        if account.account_id in accounts_with_shared_vpc_resources:
            shared_vpc_user_accounts.append(account)
        else:
            vpc_owner_accounts.append(account)

    # Return VPC owners first, then shared VPC users
    ordered = vpc_owner_accounts + shared_vpc_user_accounts

    logger.info(
        f"Polling order: {len(vpc_owner_accounts)} VPC owners first, "
        f"then {len(shared_vpc_user_accounts)} shared VPC users"
    )

    return ordered


@shared_task(bind=True, max_retries=0, default_retry_delay=60)
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
    - Error handling (no retries - failures recorded for auto-disable)
    - Soft delete tracking for missing resources
    - Account success/failure tracking
    """
    task_record = DiscoveryTask.objects.get(id=task_record_id)
    account = None

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

        # Extract discovered resource IDs for soft delete tracking
        discovered_ids = _extract_discovered_ids(results)

        # Save to database and track soft deletes
        with transaction.atomic():
            account = _get_or_create_account(
                account_number, account_name, role_arn, external_id, regions
            )

            # Save newly discovered resources (sets last_seen_at)
            _save_resources(account, results)

            # Mark resources not found for eventual soft delete
            cleanup_counts = _mark_resources_for_cleanup(account_number, discovered_ids)

            # Record successful poll
            account.record_poll_success()

        # Update task record with success
        task_record.status = 'success'
        task_record.completed_at = timezone.now()
        result_summary = results.get('summary', {})
        result_summary['cleanup'] = cleanup_counts
        task_record.result_summary = result_summary
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
            'summary': result_summary
        }

    except SoftTimeLimitExceeded:
        error_msg = 'Task exceeded time limit'
        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = error_msg
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        # Record failure for auto-disable tracking
        if account is None:
            try:
                account = AWSAccount.objects.get(account_id=account_number)
            except AWSAccount.DoesNotExist:
                pass
        if account:
            account.record_poll_failure(error_msg)

        if task_record.parent_task:
            _update_parent_task_progress(task_record.parent_task.id)

        raise

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Discovery failed for account {account_number}: {error_msg}")

        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = error_msg
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        # Record failure for auto-disable tracking
        if account is None:
            try:
                account = AWSAccount.objects.get(account_id=account_number)
            except AWSAccount.DoesNotExist:
                pass
        if account:
            account.record_poll_failure(error_msg)

        if task_record.parent_task:
            _update_parent_task_progress(task_record.parent_task.id)

        # No retries - failures are tracked for auto-disable
        return {
            'status': 'failed',
            'account_number': account_number,
            'error': error_msg
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
            role_arn = account_config.get('role_arn', '')
            defaults = {
                'account_name': account_config.get('account_name', ''),
                'role_arn': role_arn,
                'external_id': account_config.get('external_id', ''),
                'is_active': True,
                'default_regions': regions,
            }
            if role_arn:
                defaults['auth_method'] = 'instance_role'

            account, created = AWSAccount.objects.get_or_create(
                account_id=account_config['account_number'],
                defaults=defaults
            )

            # Update existing account if role_arn is provided
            if not created and role_arn and account.auth_method != 'instance_role':
                account.auth_method = 'instance_role'
                account.role_arn = role_arn
                if account_config.get('external_id'):
                    account.external_id = account_config['external_id']
                account.default_regions = regions
                account.save()

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
                           role_arn: str = None, external_id: str = None,
                           regions: list = None):
    """Get or create AWS account"""
    defaults = {
        'account_name': account_name or '',
        'is_active': True
    }

    if role_arn:
        defaults['role_arn'] = role_arn
        defaults['auth_method'] = 'instance_role'
    if external_id:
        defaults['external_id'] = external_id
    if regions:
        defaults['default_regions'] = regions

    account, created = AWSAccount.objects.get_or_create(
        account_id=account_id,
        defaults=defaults
    )

    if not created:
        if account_name:
            account.account_name = account_name
        if role_arn is not None:
            account.role_arn = role_arn
            if role_arn:
                account.auth_method = 'instance_role'
        if external_id is not None:
            account.external_id = external_id
        if regions:
            account.default_regions = regions

    account.last_polled = timezone.now()
    account.save()
    return account


@shared_task(bind=True, max_retries=0, default_retry_delay=60)
def repoll_account_with_instance_role(
    self,
    task_record_id: int,
    account_id: int,
):
    """
    Celery task to re-poll an account using EC2 instance role authentication.

    This is used for accounts configured with instance_role auth method.
    The instance role is used to assume the target account's discovery role.
    Uses soft delete tracking and account failure tracking.
    """
    task_record = DiscoveryTask.objects.get(id=task_record_id)
    parent_task_id = task_record.parent_task_id
    account = None

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

        # Extract discovered resource IDs for soft delete tracking
        discovered_ids = _extract_discovered_ids(results)

        # Save to database and track soft deletes
        with transaction.atomic():
            # Save newly discovered resources (sets last_seen_at)
            _save_resources(account, results)

            # Mark resources not found for eventual soft delete
            cleanup_counts = _mark_resources_for_cleanup(account.account_id, discovered_ids)

            # Record successful poll
            account.last_polled = timezone.now()
            account.record_poll_success()

        # Update task record with success
        task_record.status = 'success'
        task_record.completed_at = timezone.now()
        result_summary = results.get('summary', {})
        result_summary['cleanup'] = cleanup_counts
        task_record.result_summary = result_summary
        task_record.save(update_fields=[
            'status', 'completed_at', 'result_summary'
        ])

        if parent_task_id:
            _update_parent_task_progress(parent_task_id)

        logger.info(f"Successfully completed instance role discovery for account {account.account_id}")

        return {
            'status': 'success',
            'account_number': account.account_id,
            'summary': result_summary
        }

    except SoftTimeLimitExceeded:
        error_msg = 'Task exceeded time limit'
        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = error_msg
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        # Record failure for auto-disable tracking
        if account:
            account.record_poll_failure(error_msg)

        if parent_task_id:
            _update_parent_task_progress(parent_task_id)

        raise

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Instance role discovery failed: {error_msg}")

        task_record.status = 'failed'
        task_record.completed_at = timezone.now()
        task_record.error_message = error_msg
        task_record.save(update_fields=['status', 'completed_at', 'error_message'])

        # Record failure for auto-disable tracking
        if account:
            account.record_poll_failure(error_msg)

        if parent_task_id:
            _update_parent_task_progress(parent_task_id)

        # No retries - failures are tracked for auto-disable
        return {
            'status': 'failed',
            'error': error_msg
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
    """Save discovered resources to database with last_seen_at tracking"""
    now = timezone.now()

    for region, region_data in results['regions'].items():
        logger.info(f"Processing region {region}: "
                   f"{len(region_data['vpcs'])} VPCs, "
                   f"{len(region_data['subnets'])} Subnets, "
                   f"{len(region_data['security_groups'])} Security Groups, "
                   f"{len(region_data.get('ec2_instances', []))} EC2 Instances, "
                   f"{len(region_data['enis'])} ENIs")

        # Save VPCs
        for vpc_data in region_data['vpcs']:
            VPC.all_objects.update_or_create(
                vpc_id=vpc_data['vpc_id'],
                defaults={
                    'region': region,
                    'cidr_block': vpc_data['cidr_block'],
                    'owner_account': vpc_data['owner_id'],
                    'is_default': vpc_data['is_default'],
                    'state': vpc_data['state'],
                    'tags': vpc_data.get('tags', {}),
                    'last_seen_at': now,
                    'missed_polls': 0,
                    'deleted_at': None,  # Resurrect if previously soft-deleted
                }
            )

        # Save Subnets
        for subnet_data in region_data['subnets']:
            try:
                vpc = VPC.all_objects.get(vpc_id=subnet_data['vpc_id'])
                Subnet.all_objects.update_or_create(
                    subnet_id=subnet_data['subnet_id'],
                    defaults={
                        'vpc': vpc,
                        'name': subnet_data['tags'].get('Name', ''),
                        'cidr_block': subnet_data['cidr_block'],
                        'availability_zone': subnet_data['availability_zone'],
                        'owner_account': subnet_data['owner_id'],
                        'state': subnet_data['state'],
                        'tags': subnet_data.get('tags', {}),
                        'last_seen_at': now,
                        'missed_polls': 0,
                        'deleted_at': None,
                    }
                )
            except VPC.DoesNotExist:
                logger.warning(f'VPC {subnet_data["vpc_id"]} not found for subnet {subnet_data["subnet_id"]}')

        # Save Security Groups
        for sg_data in region_data['security_groups']:
            try:
                vpc = VPC.all_objects.get(vpc_id=sg_data['vpc_id'])
                sg, _ = SecurityGroup.all_objects.update_or_create(
                    sg_id=sg_data['sg_id'],
                    defaults={
                        'vpc': vpc,
                        'name': sg_data['name'],
                        'description': sg_data['description'],
                        'tags': sg_data.get('tags', {}),
                        'last_seen_at': now,
                        'missed_polls': 0,
                        'deleted_at': None,
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
                vpc = VPC.all_objects.get(vpc_id=instance_data['vpc_id'])
                subnet = Subnet.all_objects.get(subnet_id=instance_data['subnet_id'])
                EC2Instance.all_objects.update_or_create(
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
                        'tags': instance_data.get('tags', {}),
                        'last_seen_at': now,
                        'missed_polls': 0,
                        'deleted_at': None,
                    }
                )
            except (VPC.DoesNotExist, Subnet.DoesNotExist) as e:
                logger.warning(f'VPC or Subnet not found for instance {instance_data["instance_id"]}: {e}')

        # Save ENIs
        for eni_data in region_data['enis']:
            try:
                subnet = Subnet.all_objects.get(subnet_id=eni_data['subnet_id'])

                # Link to EC2 instance if attached
                ec2_instance = None
                if eni_data['attached_resource_type'] == 'instance' and eni_data['attached_resource_id']:
                    try:
                        ec2_instance = EC2Instance.all_objects.get(instance_id=eni_data['attached_resource_id'])
                    except EC2Instance.DoesNotExist:
                        logger.warning(f'EC2 instance {eni_data["attached_resource_id"]} not found for ENI {eni_data["eni_id"]}')

                eni, _ = ENI.all_objects.update_or_create(
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
                        'tags': eni_data.get('tags', {}),
                        'last_seen_at': now,
                        'missed_polls': 0,
                        'deleted_at': None,
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
                        sg = SecurityGroup.all_objects.get(sg_id=sg_id)
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
    - Excludes accounts that are auto_poll_disabled (3+ consecutive failures)
    - Orders accounts: VPC owners first, then shared VPC users
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
    # Excludes auto_poll_disabled accounts
    accounts = AWSAccount.objects.filter(
        auth_method='instance_role',
        is_active=True,
        auto_poll_disabled=False,  # Exclude accounts disabled due to repeated failures
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

    # Order accounts: VPC owners first, then shared VPC users
    account_list = _get_polling_order(list(accounts))
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


# =============================================================================
# Periodic Maintenance Tasks
# =============================================================================

@shared_task
def check_stuck_tasks():
    """
    Mark tasks running longer than TASK_TIMEOUT_HOURS as failed.

    Runs every 15 minutes via Celery Beat.
    This handles tasks that may have crashed without proper cleanup.
    """
    timeout_threshold = timezone.now() - timedelta(hours=TASK_TIMEOUT_HOURS)

    # Find stuck tasks (pending or running for too long)
    stuck_tasks = DiscoveryTask.objects.filter(
        status__in=['pending', 'running'],
        created_at__lt=timeout_threshold
    )

    count = stuck_tasks.count()
    if count > 0:
        # Update stuck tasks to failed
        stuck_tasks.update(
            status='failed',
            completed_at=timezone.now(),
            error_message=f'Task timed out after {TASK_TIMEOUT_HOURS} hours'
        )

        # Update parent task progress for any affected child tasks
        parent_ids = set(
            stuck_tasks.exclude(parent_task__isnull=True)
            .values_list('parent_task_id', flat=True)
        )
        for parent_id in parent_ids:
            _update_parent_task_progress(parent_id)

        logger.info(f"Marked {count} stuck tasks as failed")

    return {
        'status': 'completed',
        'stuck_tasks_found': count
    }


@shared_task
def cleanup_old_tasks():
    """
    Delete task records older than TASK_RETENTION_DAYS.

    Runs daily at 2 AM via Celery Beat.
    Keeps the database clean while maintaining sufficient audit trail.
    """
    cutoff = timezone.now() - timedelta(days=TASK_RETENTION_DAYS)

    # Delete old tasks (cascades to child tasks due to ForeignKey on_delete)
    # Only delete parent tasks (non-child) to trigger cascade
    deleted_count, _ = DiscoveryTask.objects.filter(
        created_at__lt=cutoff,
        parent_task__isnull=True  # Only top-level tasks
    ).delete()

    # Also clean up any orphaned child tasks
    orphaned_count, _ = DiscoveryTask.objects.filter(
        created_at__lt=cutoff
    ).delete()

    total_deleted = deleted_count + orphaned_count

    if total_deleted > 0:
        logger.info(f"Deleted {total_deleted} old task records (older than {TASK_RETENTION_DAYS} days)")

    return {
        'status': 'completed',
        'tasks_deleted': total_deleted,
        'cutoff_date': cutoff.isoformat()
    }


@shared_task
def hard_delete_old_soft_deleted_resources():
    """
    Permanently delete soft-deleted resources older than SOFT_DELETE_RETENTION_DAYS.

    Runs weekly (Sunday 3 AM) via Celery Beat.
    This is the final cleanup after resources have been soft-deleted and
    given time for any audit/investigation.
    """
    cutoff = timezone.now() - timedelta(days=SOFT_DELETE_RETENTION_DAYS)
    counts = {
        'enis': 0,
        'ec2_instances': 0,
        'security_groups': 0,
        'subnets': 0,
        'vpcs': 0,
    }

    # Delete in order: ENIs -> EC2 -> SecurityGroups -> Subnets -> VPCs
    # (reverse dependency order to avoid FK constraint issues)

    # Delete soft-deleted ENI secondary IPs and security group links first
    eni_ids = list(ENI.all_objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff
    ).values_list('id', flat=True))

    if eni_ids:
        ENISecondaryIP.objects.filter(eni_id__in=eni_ids).delete()
        ENISecurityGroup.objects.filter(eni_id__in=eni_ids).delete()

    # Delete ENIs
    counts['enis'] = ENI.all_objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff
    ).delete()[0]

    # Delete EC2 Instances
    counts['ec2_instances'] = EC2Instance.all_objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff
    ).delete()[0]

    # Delete Security Groups (and their rules via cascade)
    counts['security_groups'] = SecurityGroup.all_objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff
    ).delete()[0]

    # Delete Subnets
    counts['subnets'] = Subnet.all_objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff
    ).delete()[0]

    # Delete VPCs (must be last as others may reference them)
    counts['vpcs'] = VPC.all_objects.filter(
        deleted_at__isnull=False,
        deleted_at__lt=cutoff
    ).delete()[0]

    total_deleted = sum(counts.values())

    if total_deleted > 0:
        logger.info(
            f"Hard deleted {total_deleted} soft-deleted resources "
            f"(older than {SOFT_DELETE_RETENTION_DAYS} days): "
            f"{counts['enis']} ENIs, {counts['ec2_instances']} EC2, "
            f"{counts['security_groups']} SGs, {counts['subnets']} Subnets, "
            f"{counts['vpcs']} VPCs"
        )

    return {
        'status': 'completed',
        'total_deleted': total_deleted,
        'counts': counts,
        'cutoff_date': cutoff.isoformat()
    }
