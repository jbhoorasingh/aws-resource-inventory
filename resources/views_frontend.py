"""
Frontend views for AWS Resource Inventory
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q
from django.db import transaction
from django.utils import timezone
import json
import logging
from .models import AWSAccount, ENI, VPC, Subnet, ENISecondaryIP, SecurityGroup, SecurityGroupRule, EC2Instance, DiscoveryTask

logger = logging.getLogger(__name__)


@login_required
def accounts_view(request):
    """Display accounts page with polling functionality"""
    # Since we removed the account->vpc relationship, we need to count ENIs differently
    # We'll count ENIs by matching the account_id with the owner_account field
    accounts = AWSAccount.objects.all().order_by('-last_polled', 'account_id')
    
    # Get ENI counts for all accounts in a single query
    from django.db.models import Count
    eni_counts = ENI.objects.values('owner_account').annotate(
        count=Count('id')
    ).values_list('owner_account', 'count')
    
    # Create a dictionary for quick lookup
    eni_count_dict = dict(eni_counts)
    
    # Add ENI count for each account
    for account in accounts:
        account.eni_count = eni_count_dict.get(account.account_id, 0)
    
    context = {
        'accounts': accounts,
    }
    return render(request, 'resources/accounts.html', context)


@login_required
def vpcs_view(request):
    """Display VPCs page with hierarchical tree view of subnets and resources"""
    # Get filter parameters
    region_filter = request.GET.get('region', '')
    account_filter = request.GET.get('account', '')
    state_filter = request.GET.get('state', '')

    # Base queryset with prefetching
    vpcs = VPC.objects.prefetch_related(
        'subnets',
        'subnets__enis__secondary_ips',
        'subnets__enis__eni_security_groups__security_group',
        'subnets__enis__ec2_instance',
        'subnets__instances',
        'security_groups'
    ).all()

    # Apply filters
    if region_filter:
        vpcs = vpcs.filter(region=region_filter)
    if account_filter:
        vpcs = vpcs.filter(owner_account=account_filter)
    if state_filter:
        vpcs = vpcs.filter(state=state_filter)

    vpcs = vpcs.order_by('region', 'vpc_id')

    # Get summary statistics
    total_vpcs = VPC.objects.count()
    total_subnets = Subnet.objects.count()
    total_enis = ENI.objects.count()
    total_ec2 = EC2Instance.objects.count()
    total_sgs = SecurityGroup.objects.count()

    # Get unique values for filters
    regions = VPC.objects.values_list('region', flat=True).distinct().order_by('region')
    accounts = VPC.objects.values_list('owner_account', flat=True).distinct().order_by('owner_account')
    states = VPC.objects.values_list('state', flat=True).distinct().order_by('state')

    # Add resource counts to each VPC and subnet
    for vpc in vpcs:
        vpc.subnet_list = vpc.subnets.all()
        for subnet in vpc.subnet_list:
            subnet.eni_list = subnet.enis.all()
            subnet.ec2_list = subnet.instances.all()
            # Get unique security groups for this subnet
            sg_ids = set()
            for eni in subnet.eni_list:
                for eni_sg in eni.eni_security_groups.all():
                    sg_ids.add(eni_sg.security_group)
            subnet.sg_list = list(sg_ids)

    context = {
        'vpcs': vpcs,
        'total_vpcs': total_vpcs,
        'total_subnets': total_subnets,
        'total_enis': total_enis,
        'total_ec2': total_ec2,
        'total_sgs': total_sgs,
        'regions': regions,
        'accounts': accounts,
        'states': states,
        'selected_region': region_filter,
        'selected_account': account_filter,
        'selected_state': state_filter,
    }
    return render(request, 'resources/vpcs.html', context)


@login_required
def enis_view(request):
    """Display ENIs page with detailed information"""
    # Get filter parameters
    region_filter = request.GET.get('region', '')
    account_filter = request.GET.get('account', '')
    status_filter = request.GET.get('status', '')
    vpc_filter = request.GET.get('vpc', '')
    subnet_filter = request.GET.get('subnet', '')
    interface_type_filter = request.GET.get('interface_type', '')
    has_public_ip_filter = request.GET.get('has_public_ip', '')
    attached_filter = request.GET.get('attached', '')

    # Base queryset
    enis = ENI.objects.select_related(
        'subnet__vpc', 'ec2_instance'
    ).prefetch_related(
        'secondary_ips', 'eni_security_groups__security_group'
    ).all()

    # Apply filters
    if region_filter:
        enis = enis.filter(subnet__vpc__region=region_filter)
    if account_filter:
        enis = enis.filter(owner_account=account_filter)
    if status_filter:
        enis = enis.filter(status=status_filter)
    if vpc_filter:
        enis = enis.filter(subnet__vpc__vpc_id=vpc_filter)
    if subnet_filter:
        enis = enis.filter(subnet__subnet_id=subnet_filter)
    if interface_type_filter:
        enis = enis.filter(interface_type=interface_type_filter)
    if has_public_ip_filter == 'yes':
        enis = enis.exclude(public_ip_address__isnull=True).exclude(public_ip_address='')
    elif has_public_ip_filter == 'no':
        enis = enis.filter(Q(public_ip_address__isnull=True) | Q(public_ip_address=''))
    if attached_filter == 'yes':
        enis = enis.exclude(attached_resource_id='')
    elif attached_filter == 'no':
        enis = enis.filter(attached_resource_id='')

    enis = enis.order_by('-created_at')

    # Get summary statistics (use base ENI queryset without filters)
    total_enis = ENI.objects.count()

    # Count private IPs (primary + secondary)
    primary_private_ips = ENI.objects.filter(private_ip_address__isnull=False).count()
    secondary_ips_count = ENISecondaryIP.objects.count()
    total_private_ips = primary_private_ips + secondary_ips_count

    # Count public IPs
    total_public_ips = ENI.objects.exclude(public_ip_address__isnull=True).exclude(public_ip_address='').count()

    # Count unique regions
    total_regions = VPC.objects.values('region').distinct().count()

    # Get unique values for filter dropdowns
    regions = VPC.objects.values_list('region', flat=True).distinct().order_by('region')
    accounts = ENI.objects.values_list('owner_account', flat=True).distinct().order_by('owner_account')
    statuses = ENI.objects.values_list('status', flat=True).distinct().order_by('status')
    vpcs = VPC.objects.values_list('vpc_id', flat=True).distinct().order_by('vpc_id')
    subnets = Subnet.objects.select_related('vpc').values('subnet_id', 'vpc__vpc_id').distinct().order_by('subnet_id')
    interface_types = ENI.objects.values_list('interface_type', flat=True).distinct().order_by('interface_type')

    context = {
        'enis': enis,
        'total_enis': total_enis,
        'total_private_ips': total_private_ips,
        'total_public_ips': total_public_ips,
        'total_regions': total_regions,
        'filtered_count': enis.count(),
        'regions': regions,
        'accounts': accounts,
        'statuses': statuses,
        'vpcs': vpcs,
        'subnets': subnets,
        'interface_types': interface_types,
        'selected_region': region_filter,
        'selected_account': account_filter,
        'selected_status': status_filter,
        'selected_vpc': vpc_filter,
        'selected_subnet': subnet_filter,
        'selected_interface_type': interface_type_filter,
        'selected_has_public_ip': has_public_ip_filter,
        'selected_attached': attached_filter,
    }
    return render(request, 'resources/enis.html', context)


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
@csrf_exempt
@require_http_methods(["POST"])
def poll_account_view(request):
    """Handle account polling requests - now async with Celery"""
    from .tasks import discover_account_resources

    try:
        # Get form data
        account_number = request.POST.get('account_number')
        account_name = request.POST.get('account_name', '')
        access_key_id = request.POST.get('access_key_id')
        secret_access_key = request.POST.get('secret_access_key')
        session_token = request.POST.get('session_token')
        regions = request.POST.get('regions', 'us-east-1,us-west-2')
        role_arn = request.POST.get('role_arn', '')
        external_id = request.POST.get('external_id', '')

        # Log poll attempt
        logger.info(f"Web UI poll request received for account {account_number} ({account_name or 'No name'})")
        logger.info(f"Regions: {regions}")
        logger.info(f"Auth method: {'Role Assumption' if role_arn else 'Direct Credentials'}")
        if role_arn:
            logger.info(f"Role ARN: {role_arn}")

        # Validate required fields
        if not all([account_number, access_key_id, secret_access_key, session_token]):
            messages.error(request, 'All required fields must be provided.')
            return redirect('accounts')

        # Parse regions
        region_list = [r.strip() for r in regions.split(',') if r.strip()]
        if not region_list:
            messages.error(request, 'At least one region must be specified.')
            return redirect('accounts')

        # Get or create account and queue task in atomic block
        with transaction.atomic():
            account, _ = AWSAccount.objects.get_or_create(
                account_id=account_number,
                defaults={
                    'account_name': account_name,
                    'role_arn': role_arn,
                    'external_id': external_id,
                }
            )

            # Create task record
            task_record = DiscoveryTask.objects.create(
                task_type='single',
                status='pending',
                account=account,
                regions=region_list,
                initiated_by=request.user,
                total_accounts=1
            )

            # Capture values for the lambda closure
            task_id = task_record.id

            # Queue the Celery task after database commit (prevents race condition)
            transaction.on_commit(
                lambda: discover_account_resources.delay(
                    task_record_id=task_id,
                    account_number=account_number,
                    account_name=account_name,
                    access_key_id=access_key_id,
                    secret_access_key=secret_access_key,
                    session_token=session_token,
                    regions=region_list,
                    role_arn=role_arn or None,
                    external_id=external_id or None
                )
            )

        messages.success(
            request,
            f'Discovery task queued for account {account_number}. '
            f'View progress on the Task Status page.'
        )
        return redirect('task_status')

    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')

    return redirect('accounts')


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
@csrf_exempt
@require_http_methods(["POST"])
def bulk_poll_accounts_view(request):
    """Handle bulk account polling requests - now async with Celery"""
    from .tasks import bulk_discover_resources

    try:
        # Get shared credentials
        access_key_id = request.POST.get('access_key_id')
        secret_access_key = request.POST.get('secret_access_key')
        session_token = request.POST.get('session_token', '')
        regions = request.POST.get('regions', 'us-east-1,us-west-2')
        accounts_config = request.POST.get('accounts_config', '')

        logger.info("="*80)
        logger.info("BULK POLL REQUEST RECEIVED (Async)")
        logger.info(f"Timestamp: {timezone.now().isoformat()}")
        logger.info(f"Regions: {regions}")

        # Validate required fields
        if not all([access_key_id, secret_access_key, accounts_config]):
            messages.error(request, 'Access key, secret key, and accounts configuration are required.')
            return redirect('accounts')

        # Parse regions
        region_list = [r.strip() for r in regions.split(',') if r.strip()]
        if not region_list:
            messages.error(request, 'At least one region must be specified.')
            return redirect('accounts')

        # Parse accounts configuration
        # Format: account_number|account_name|role_arn|external_id (one per line)
        accounts = []
        for line_num, line in enumerate(accounts_config.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue

            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 3:
                messages.error(
                    request,
                    f'Line {line_num}: Invalid format. Expected: account_number|account_name|role_arn|external_id'
                )
                return redirect('accounts')

            account_config = {
                'account_number': parts[0],
                'account_name': parts[1] if len(parts) > 1 else '',
                'role_arn': parts[2] if len(parts) > 2 else '',
                'external_id': parts[3] if len(parts) > 3 else ''
            }
            accounts.append(account_config)

        if not accounts:
            messages.error(request, 'No valid accounts found in configuration.')
            return redirect('accounts')

        logger.info(f"Total accounts to poll: {len(accounts)}")
        for idx, acc in enumerate(accounts, 1):
            logger.info(f"  {idx}. Account {acc['account_number']} ({acc['account_name']}) - Role: {acc['role_arn']}")
        logger.info("="*80)

        # Create parent task record and queue Celery task in atomic block
        with transaction.atomic():
            task_record = DiscoveryTask.objects.create(
                task_type='bulk',
                status='pending',
                regions=region_list,
                initiated_by=request.user,
                total_accounts=len(accounts)
            )

            # Capture values for the lambda closure
            task_id = task_record.id
            user_id = request.user.id

            # Queue the bulk discovery task after database commit (prevents race condition)
            transaction.on_commit(
                lambda: bulk_discover_resources.delay(
                    task_record_id=task_id,
                    access_key_id=access_key_id,
                    secret_access_key=secret_access_key,
                    session_token=session_token,
                    regions=region_list,
                    accounts_config=accounts,
                    user_id=user_id
                )
            )

        messages.success(
            request,
            f'Bulk discovery queued for {len(accounts)} accounts. '
            f'View progress on the Task Status page.'
        )
        return redirect('task_status')

    except Exception as e:
        messages.error(request, f'Bulk polling error: {str(e)}')

    return redirect('accounts')


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
@csrf_exempt
@require_http_methods(["POST"])
def repoll_account_view(request, account_id):
    """Handle re-polling an account using instance role authentication"""
    from .tasks import repoll_account_with_instance_role

    try:
        account = get_object_or_404(AWSAccount, id=account_id)

        # Verify account is configured for instance role auth
        if account.auth_method != 'instance_role':
            messages.error(request, f'Account {account.account_id} is not configured for instance role authentication.')
            return redirect('accounts')

        if not account.can_repoll:
            messages.error(
                request,
                f'Account {account.account_id} cannot be re-polled. '
                f'Ensure default_regions and role configuration are set.'
            )
            return redirect('accounts')

        # Create task record and queue in atomic block
        with transaction.atomic():
            task_record = DiscoveryTask.objects.create(
                task_type='single',
                status='pending',
                account=account,
                regions=account.default_regions,
                initiated_by=request.user,
                total_accounts=1
            )

            # Capture values for the lambda closure
            task_id = task_record.id
            acct_id = account.id

            # Queue the Celery task after database commit
            transaction.on_commit(
                lambda: repoll_account_with_instance_role.delay(
                    task_record_id=task_id,
                    account_id=acct_id
                )
            )

        messages.success(
            request,
            f'Re-poll queued for account {account.account_id} using instance role. '
            f'View progress on the Task Status page.'
        )
        return redirect('task_status')

    except Exception as e:
        messages.error(request, f'Re-poll error: {str(e)}')

    return redirect('accounts')


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
@csrf_exempt
@require_http_methods(["POST"])
def bulk_repoll_accounts_view(request):
    """Handle bulk re-polling of accounts using instance role authentication"""
    from .tasks import bulk_repoll_accounts_with_instance_role

    try:
        # Get selected account IDs from form
        account_ids = request.POST.getlist('account_ids')

        if not account_ids:
            messages.error(request, 'No accounts selected for re-poll.')
            return redirect('accounts')

        # Filter to only accounts that can be re-polled
        accounts = AWSAccount.objects.filter(
            id__in=account_ids,
            auth_method='instance_role'
        )

        repollable_accounts = [a for a in accounts if a.can_repoll]

        if not repollable_accounts:
            messages.error(
                request,
                'None of the selected accounts are configured for instance role re-polling.'
            )
            return redirect('accounts')

        # Create parent task record and queue in atomic block
        with transaction.atomic():
            task_record = DiscoveryTask.objects.create(
                task_type='bulk',
                status='pending',
                regions=[],  # Will be set per-account
                initiated_by=request.user,
                total_accounts=len(repollable_accounts)
            )

            # Capture values for the lambda closure
            task_id = task_record.id
            account_id_list = [a.id for a in repollable_accounts]
            user_id = request.user.id

            # Queue the bulk discovery task after database commit
            transaction.on_commit(
                lambda: bulk_repoll_accounts_with_instance_role.delay(
                    task_record_id=task_id,
                    account_ids=account_id_list,
                    user_id=user_id
                )
            )

        messages.success(
            request,
            f'Bulk re-poll queued for {len(repollable_accounts)} accounts using instance role. '
            f'View progress on the Task Status page.'
        )
        return redirect('task_status')

    except Exception as e:
        messages.error(request, f'Bulk re-poll error: {str(e)}')

    return redirect('accounts')


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
def add_account_view(request):
    """Add one or more accounts with instance role authentication"""
    if request.method == 'POST':
        accounts_config = request.POST.get('accounts_config', '').strip()
        auth_method = request.POST.get('auth_method', 'instance_role')
        default_role_name = request.POST.get('default_role_name', 'PaloInventoryInspectionRole').strip()
        external_id = request.POST.get('external_id', '').strip()
        default_regions = request.POST.get('default_regions', '').strip()

        if not accounts_config:
            messages.error(request, 'At least one account is required.')
            return redirect('add_account')

        # Parse regions
        region_list = [r.strip() for r in default_regions.split(',') if r.strip()]

        # Parse accounts (format: account_id|account_name per line)
        added_count = 0
        skipped_count = 0
        errors = []

        for line_num, line in enumerate(accounts_config.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue

            parts = [p.strip() for p in line.split('|')]
            account_id = parts[0] if parts else ''
            account_name = parts[1] if len(parts) > 1 else ''

            # Validate account ID format (12 digits)
            if not account_id.isdigit() or len(account_id) != 12:
                errors.append(f'Line {line_num}: Invalid account ID "{account_id}" (must be 12 digits)')
                continue

            try:
                account, created = AWSAccount.objects.get_or_create(
                    account_id=account_id,
                    defaults={
                        'account_name': account_name,
                        'auth_method': auth_method,
                        'default_role_name': default_role_name,
                        'external_id': external_id,
                        'default_regions': region_list,
                        'is_active': True
                    }
                )

                if created:
                    added_count += 1
                else:
                    # Update existing account with new settings if not created
                    skipped_count += 1

            except Exception as e:
                errors.append(f'Line {line_num}: Error adding {account_id}: {str(e)}')

        # Show results
        if added_count > 0:
            messages.success(request, f'Successfully added {added_count} account(s).')
        if skipped_count > 0:
            messages.warning(request, f'{skipped_count} account(s) already existed (skipped).')
        if errors:
            messages.error(request, 'Errors: ' + '; '.join(errors[:5]))
            if len(errors) > 5:
                messages.error(request, f'... and {len(errors) - 5} more errors.')

        if added_count > 0 or skipped_count > 0:
            return redirect('accounts')
        return redirect('add_account')

    # GET request - show form
    return render(request, 'resources/add_account.html', {
        'default_role_name': 'PaloInventoryInspectionRole',
        'default_regions': 'us-east-1,us-west-2',
    })


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
def edit_account_view(request, account_id):
    """Edit an existing account's configuration"""
    account = get_object_or_404(AWSAccount, id=account_id)

    if request.method == 'POST':
        account.account_name = request.POST.get('account_name', '').strip()
        account.auth_method = request.POST.get('auth_method', 'credentials')
        account.default_role_name = request.POST.get('default_role_name', '').strip()
        account.role_arn = request.POST.get('role_arn', '').strip()
        account.external_id = request.POST.get('external_id', '').strip()
        account.is_active = request.POST.get('is_active') == 'on'

        # Parse regions
        default_regions = request.POST.get('default_regions', '').strip()
        account.default_regions = [r.strip() for r in default_regions.split(',') if r.strip()]

        try:
            account.save()
            messages.success(request, f'Account {account.account_id} updated successfully.')
            return redirect('accounts')
        except Exception as e:
            messages.error(request, f'Error updating account: {str(e)}')

    # GET request - show form with current values
    return render(request, 'resources/edit_account.html', {
        'account': account,
        'default_regions_str': ','.join(account.default_regions) if account.default_regions else '',
    })


@login_required
def api_enis_json(request):
    """API endpoint for ENIs data (for AJAX requests)"""
    enis = ENI.objects.select_related(
        'subnet__vpc'
    ).prefetch_related(
        'secondary_ips', 'eni_security_groups__security_group'
    ).all().order_by('-created_at')
    
    data = []
    for eni in enis:
        eni_data = {
            'eni_id': eni.eni_id,
            'name': eni.name or '',
            'private_ip_address': eni.private_ip_address,
            'public_ip_address': eni.public_ip_address or '',
            'secondary_ips': [ip.ip_address for ip in eni.secondary_ips.all()],
            'vpc_id': eni.subnet.vpc.vpc_id,
            'vpc_cidr': eni.subnet.vpc.cidr_block,
            'subnet_id': eni.subnet.subnet_id,
            'subnet_cidr': eni.subnet.cidr_block,
            'availability_zone': eni.subnet.availability_zone,
            'security_groups': [sg.security_group.name for sg in eni.eni_security_groups.all()],
            'owner_account': eni.subnet.owner_account,
            'status': eni.status,
            'attached_resource_id': eni.attached_resource_id or '',
            'attached_resource_type': eni.attached_resource_type or '',
            'created_at': eni.created_at.isoformat(),
        }
        data.append(eni_data)
    
    return JsonResponse({'enis': data})


@login_required
def api_accounts_json(request):
    """API endpoint for accounts data (for AJAX requests)"""
    accounts = AWSAccount.objects.all().order_by('-last_polled', 'account_id')
    
    # Get ENI counts for all accounts in a single query
    from django.db.models import Count
    eni_counts = ENI.objects.values('owner_account').annotate(
        count=Count('id')
    ).values_list('owner_account', 'count')
    
    # Create a dictionary for quick lookup
    eni_count_dict = dict(eni_counts)
    
    data = []
    for account in accounts:
        account_data = {
            'account_id': account.account_id,
            'account_name': account.account_name or '',
            'is_active': account.is_active,
            'eni_count': eni_count_dict.get(account.account_id, 0),
            'last_polled': account.last_polled.isoformat() if account.last_polled else None,
            'created_at': account.created_at.isoformat(),
        }
        data.append(account_data)
    
    return JsonResponse({'accounts': data})


@login_required
def security_groups_view(request):
    """Display security groups page with rules information"""
    # Get filter parameters
    region_filter = request.GET.get('region', '')
    account_filter = request.GET.get('account', '')
    vpc_filter = request.GET.get('vpc', '')
    has_ingress_filter = request.GET.get('has_ingress', '')
    has_egress_filter = request.GET.get('has_egress', '')

    # Base queryset
    security_groups = SecurityGroup.objects.select_related('vpc').prefetch_related('rules').all()

    # Apply filters
    if region_filter:
        security_groups = security_groups.filter(vpc__region=region_filter)
    if account_filter:
        security_groups = security_groups.filter(vpc__owner_account=account_filter)
    if vpc_filter:
        security_groups = security_groups.filter(vpc__vpc_id=vpc_filter)
    if has_ingress_filter == 'yes':
        security_groups = security_groups.filter(rules__rule_type='ingress').distinct()
    elif has_ingress_filter == 'no':
        security_groups = security_groups.exclude(rules__rule_type='ingress').distinct()
    if has_egress_filter == 'yes':
        security_groups = security_groups.filter(rules__rule_type='egress').distinct()
    elif has_egress_filter == 'no':
        security_groups = security_groups.exclude(rules__rule_type='egress').distinct()

    security_groups = security_groups.order_by('name')

    # Add rule counts for each security group
    for sg in security_groups:
        sg.ingress_count = sg.rules.filter(rule_type='ingress').count()
        sg.egress_count = sg.rules.filter(rule_type='egress').count()

    # Get summary statistics (use base queryset without filters)
    total_security_groups = SecurityGroup.objects.count()
    total_ingress_rules = SecurityGroupRule.objects.filter(rule_type='ingress').count()
    total_egress_rules = SecurityGroupRule.objects.filter(rule_type='egress').count()
    total_regions = VPC.objects.values('region').distinct().count()

    # Get unique values for filter dropdowns
    regions = VPC.objects.values_list('region', flat=True).distinct().order_by('region')
    accounts = VPC.objects.values_list('owner_account', flat=True).distinct().order_by('owner_account')
    vpcs = VPC.objects.values_list('vpc_id', flat=True).distinct().order_by('vpc_id')

    context = {
        'security_groups': security_groups,
        'total_security_groups': total_security_groups,
        'total_ingress_rules': total_ingress_rules,
        'total_egress_rules': total_egress_rules,
        'total_regions': total_regions,
        'filtered_count': security_groups.count(),
        'regions': regions,
        'accounts': accounts,
        'vpcs': vpcs,
        'selected_region': region_filter,
        'selected_account': account_filter,
        'selected_vpc': vpc_filter,
        'selected_has_ingress': has_ingress_filter,
        'selected_has_egress': has_egress_filter,
    }
    return render(request, 'resources/security_groups.html', context)


@login_required
def security_group_detail_view(request, sg_id):
    """Display detailed security group rules"""
    try:
        security_group = SecurityGroup.objects.select_related('vpc').prefetch_related('rules').get(id=sg_id)
        
        # Get rules ordered by type and protocol
        rules = security_group.rules.all().order_by('rule_type', 'protocol', 'from_port')
        
        # Get associated ENIs
        associated_enis = ENI.objects.filter(
            eni_security_groups__security_group=security_group
        ).select_related('subnet').all()
        
        context = {
            'security_group': security_group,
            'rules': rules,
            'associated_enis': associated_enis,
        }
        return render(request, 'resources/security_group_detail.html', context)
        
    except SecurityGroup.DoesNotExist:
        messages.error(request, 'Security group not found.')
        return redirect('security_groups')


@login_required
def ec2_instances_view(request):
    """Display EC2 instances page with detailed information"""
    # Get filter parameters
    region_filter = request.GET.get('region', '')
    account_filter = request.GET.get('account', '')
    state_filter = request.GET.get('state', '')
    instance_type_filter = request.GET.get('instance_type', '')
    vpc_filter = request.GET.get('vpc', '')
    subnet_filter = request.GET.get('subnet', '')
    has_public_ip_filter = request.GET.get('has_public_ip', '')
    platform_filter = request.GET.get('platform', '')

    # Base queryset
    instances = EC2Instance.objects.select_related(
        'vpc', 'subnet'
    ).prefetch_related(
        'enis__secondary_ips', 'enis__eni_security_groups__security_group'
    ).all()

    # Apply filters
    if region_filter:
        instances = instances.filter(region=region_filter)
    if account_filter:
        instances = instances.filter(owner_account=account_filter)
    if state_filter:
        instances = instances.filter(state=state_filter)
    if instance_type_filter:
        instances = instances.filter(instance_type=instance_type_filter)
    if vpc_filter:
        instances = instances.filter(vpc__vpc_id=vpc_filter)
    if subnet_filter:
        instances = instances.filter(subnet__subnet_id=subnet_filter)
    if has_public_ip_filter == 'yes':
        instances = instances.exclude(public_ip_address__isnull=True).exclude(public_ip_address='')
    elif has_public_ip_filter == 'no':
        instances = instances.filter(Q(public_ip_address__isnull=True) | Q(public_ip_address=''))
    if platform_filter:
        instances = instances.filter(platform=platform_filter)

    instances = instances.order_by('-launch_time')

    # Get summary statistics (use base queryset without filters)
    total_instances = EC2Instance.objects.count()
    running_instances = EC2Instance.objects.filter(state='running').count()
    stopped_instances = EC2Instance.objects.filter(state='stopped').count()
    total_regions = EC2Instance.objects.values('region').distinct().count()

    # Get unique values for filter dropdowns
    regions = EC2Instance.objects.values_list('region', flat=True).distinct().order_by('region')
    accounts = EC2Instance.objects.values_list('owner_account', flat=True).distinct().order_by('owner_account')
    states = EC2Instance.objects.values_list('state', flat=True).distinct().order_by('state')
    instance_types = EC2Instance.objects.values_list('instance_type', flat=True).distinct().order_by('instance_type')
    vpcs = VPC.objects.values_list('vpc_id', flat=True).distinct().order_by('vpc_id')
    subnets = Subnet.objects.select_related('vpc').values('subnet_id', 'vpc__vpc_id').distinct().order_by('subnet_id')
    platforms = EC2Instance.objects.exclude(platform='').values_list('platform', flat=True).distinct().order_by('platform')

    context = {
        'instances': instances,
        'total_instances': total_instances,
        'running_instances': running_instances,
        'stopped_instances': stopped_instances,
        'total_regions': total_regions,
        'filtered_count': instances.count(),
        'regions': regions,
        'accounts': accounts,
        'states': states,
        'instance_types': instance_types,
        'vpcs': vpcs,
        'subnets': subnets,
        'platforms': platforms,
        'selected_region': region_filter,
        'selected_account': account_filter,
        'selected_state': state_filter,
        'selected_instance_type': instance_type_filter,
        'selected_vpc': vpc_filter,
        'selected_subnet': subnet_filter,
        'selected_has_public_ip': has_public_ip_filter,
        'selected_platform': platform_filter,
    }
    return render(request, 'resources/ec2_instances.html', context)


@login_required
def ec2_instance_detail_view(request, instance_id):
    """Display detailed EC2 instance information"""
    try:
        instance = EC2Instance.objects.select_related(
            'vpc', 'subnet'
        ).prefetch_related(
            'enis__secondary_ips',
            'enis__eni_security_groups__security_group__rules'
        ).get(id=instance_id)

        # Get all ENIs for this instance with their security groups and rules
        enis = instance.enis.all()

        # Organize security groups with rules for each ENI
        enis_with_sgs = []
        for eni in enis:
            security_groups = []
            for eni_sg in eni.eni_security_groups.all():
                sg = eni_sg.security_group
                ingress_rules = sg.rules.filter(rule_type='ingress').order_by('protocol', 'from_port')
                egress_rules = sg.rules.filter(rule_type='egress').order_by('protocol', 'from_port')
                security_groups.append({
                    'security_group': sg,
                    'ingress_rules': ingress_rules,
                    'egress_rules': egress_rules,
                })
            enis_with_sgs.append({
                'eni': eni,
                'security_groups': security_groups,
            })

        context = {
            'instance': instance,
            'enis_with_sgs': enis_with_sgs,
        }
        return render(request, 'resources/ec2_instance_detail.html', context)

    except EC2Instance.DoesNotExist:
        messages.error(request, 'EC2 instance not found.')
        return redirect('ec2_instances')


@login_required
def eni_detail_view(request, eni_id):
    """Display detailed ENI information"""
    try:
        eni = ENI.objects.select_related(
            'subnet__vpc', 'ec2_instance__vpc', 'ec2_instance__subnet'
        ).prefetch_related(
            'secondary_ips',
            'eni_security_groups__security_group__rules'
        ).get(id=eni_id)

        # Get all security groups with their rules
        security_groups = []
        for eni_sg in eni.eni_security_groups.all():
            sg = eni_sg.security_group
            ingress_rules = sg.rules.filter(rule_type='ingress').order_by('protocol', 'from_port')
            egress_rules = sg.rules.filter(rule_type='egress').order_by('protocol', 'from_port')
            security_groups.append({
                'security_group': sg,
                'ingress_rules': ingress_rules,
                'egress_rules': egress_rules,
            })

        context = {
            'eni': eni,
            'security_groups': security_groups,
        }
        return render(request, 'resources/eni_detail.html', context)

    except ENI.DoesNotExist:
        messages.error(request, 'ENI not found.')
        return redirect('enis')

# Authentication Views

def login_view(request):
    """User login view"""
    if request.user.is_authenticated:
        return redirect('accounts')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        next_url = request.POST.get('next') or request.GET.get('next') or 'accounts'
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password.')
    
    context = {
        'next': request.GET.get('next', 'accounts')
    }
    return render(request, 'resources/login.html', context)


def logout_view(request):
    """User logout view"""
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')


@login_required
def profile_view(request):
    """User profile view with API token management"""
    user = request.user

    # Get DRF auth token
    from rest_framework.authtoken.models import Token
    drf_token, created = Token.objects.get_or_create(user=user)

    context = {
        'user': user,
        'api_token': user.profile.api_token,
        'drf_token': drf_token.key,
    }
    return render(request, 'resources/profile.html', context)


@login_required
@require_http_methods(["POST"])
def regenerate_token_view(request):
    """Regenerate user's API token"""
    new_token = request.user.profile.regenerate_token()
    messages.success(request, 'Your API token has been regenerated!')
    return redirect('profile')


# Task Status Views

@login_required
def task_status_view(request):
    """Display task status page with history"""
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    task_type_filter = request.GET.get('task_type', '')

    # Base queryset
    if request.user.is_superuser:
        tasks = DiscoveryTask.objects.all()
    else:
        tasks = DiscoveryTask.objects.filter(initiated_by=request.user)

    tasks = tasks.select_related('account', 'initiated_by', 'parent_task')

    # Apply filters
    if status_filter:
        tasks = tasks.filter(status=status_filter)
    if task_type_filter:
        tasks = tasks.filter(task_type=task_type_filter)

    # Only show parent tasks (not children)
    tasks = tasks.filter(parent_task__isnull=True).order_by('-created_at')[:50]

    # Get summary stats
    all_tasks = DiscoveryTask.objects.filter(parent_task__isnull=True)
    if not request.user.is_superuser:
        all_tasks = all_tasks.filter(initiated_by=request.user)

    context = {
        'tasks': tasks,
        'total_tasks': all_tasks.count(),
        'pending_count': all_tasks.filter(status='pending').count(),
        'running_count': all_tasks.filter(status='running').count(),
        'success_count': all_tasks.filter(status='success').count(),
        'failed_count': all_tasks.filter(status='failed').count(),
        'selected_status': status_filter,
        'selected_task_type': task_type_filter,
    }
    return render(request, 'resources/task_status.html', context)


@login_required
def task_detail_view(request, task_id):
    """Display detailed task information including child tasks"""
    task = get_object_or_404(
        DiscoveryTask.objects.select_related('account', 'initiated_by')
        .prefetch_related('child_tasks__account'),
        id=task_id
    )

    # Permission check
    if not request.user.is_superuser and task.initiated_by != request.user:
        messages.error(request, 'Access denied.')
        return redirect('task_status')

    context = {
        'task': task,
        'child_tasks': task.child_tasks.all().order_by('-created_at'),
    }
    return render(request, 'resources/task_detail.html', context)
