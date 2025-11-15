"""
Frontend views for AWS Resource Inventory
"""
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q
from django.utils import timezone
import subprocess
import json
import logging
from .models import AWSAccount, ENI, VPC, Subnet, ENISecondaryIP, SecurityGroup, SecurityGroupRule, EC2Instance

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
def enis_view(request):
    """Display ENIs page with detailed information"""
    enis = ENI.objects.select_related(
        'subnet__vpc', 'ec2_instance'
    ).prefetch_related(
        'secondary_ips', 'eni_security_groups__security_group'
    ).all().order_by('-created_at')
    
    # Get summary statistics
    total_enis = ENI.objects.count()
    
    # Count private IPs (primary + secondary)
    # Primary private IPs from ENI records - use a simpler approach
    primary_private_ips = ENI.objects.filter(private_ip_address__isnull=False).count()
    # Secondary IPs from ENISecondaryIP records
    secondary_ips_count = ENISecondaryIP.objects.count()
    total_private_ips = primary_private_ips + secondary_ips_count
    
    # Count public IPs
    total_public_ips = ENI.objects.exclude(public_ip_address__isnull=True).exclude(public_ip_address='').count()
    
    # Count unique regions
    total_regions = VPC.objects.values('region').distinct().count()
    
    
    context = {
        'enis': enis,
        'total_enis': total_enis,
        'total_private_ips': total_private_ips,
        'total_public_ips': total_public_ips,
        'total_regions': total_regions,
    }
    return render(request, 'resources/enis.html', context)


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
@csrf_exempt
@require_http_methods(["POST"])
def poll_account_view(request):
    """Handle account polling requests"""
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

        # Run the discovery command
        cmd = [
            'python', 'manage.py', 'discover_aws_resources',
            account_number,
            access_key_id,
            secret_access_key,
            session_token
        ] + region_list

        if account_name:
            cmd.extend(['--account-name', account_name])

        if role_arn:
            cmd.extend(['--role-arn', role_arn])

        if external_id:
            cmd.extend(['--external-id', external_id])
        
        # Execute the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd='.'
        )
        
        if result.returncode == 0:
            auth_method = f'using role assumption ({role_arn})' if role_arn else 'with direct credentials'
            logger.info(f"Successfully polled account {account_number} {auth_method}")
            logger.info(f"Regions: {', '.join(region_list)}")
            messages.success(
                request,
                f'Successfully polled account {account_number} {auth_method}. '
                f'Discovered resources in regions: {", ".join(region_list)}'
            )
        else:
            logger.error(f"Failed to poll account {account_number}")
            logger.error(f"Error output: {result.stderr[:500]}")
            messages.error(
                request,
                f'Failed to poll account {account_number}. '
                f'Error: {result.stderr}'
            )
    
    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')

    return redirect('accounts')


@login_required
@permission_required('resources.can_poll_accounts', raise_exception=True)
@csrf_exempt
@require_http_methods(["POST"])
def bulk_poll_accounts_view(request):
    """Handle bulk account polling requests with role assumption"""
    try:
        # Get shared credentials
        access_key_id = request.POST.get('access_key_id')
        secret_access_key = request.POST.get('secret_access_key')
        session_token = request.POST.get('session_token', '')
        regions = request.POST.get('regions', 'us-east-1,us-west-2')
        accounts_config = request.POST.get('accounts_config', '')

        logger.info("="*80)
        logger.info("BULK POLL REQUEST RECEIVED")
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

        # Poll each account
        total_accounts = len(accounts)
        successful = 0
        failed = 0
        results = []

        for idx, account_config in enumerate(accounts, 1):
            account_number = account_config['account_number']
            account_name = account_config['account_name']
            role_arn = account_config['role_arn']
            external_id = account_config['external_id']

            logger.info(f"Processing account {idx}/{total_accounts}: {account_number} ({account_name})")

            try:
                # Build command
                cmd = [
                    'python', 'manage.py', 'discover_aws_resources',
                    account_number,
                    access_key_id,
                    secret_access_key,
                    session_token
                ] + region_list

                if account_name:
                    cmd.extend(['--account-name', account_name])

                if role_arn:
                    cmd.extend(['--role-arn', role_arn])

                if external_id:
                    cmd.extend(['--external-id', external_id])

                # Execute the command
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd='.',
                    timeout=300  # 5 minute timeout per account
                )

                if result.returncode == 0:
                    successful += 1
                    logger.info(f"✓ SUCCESS: Account {account_number} ({account_name})")
                    results.append(f'✓ Account {account_number} ({account_name}): Success')
                else:
                    failed += 1
                    error_msg = result.stderr[:200] if result.stderr else 'Unknown error'
                    logger.error(f"✗ FAILED: Account {account_number} ({account_name}) - {error_msg}")
                    results.append(f'✗ Account {account_number} ({account_name}): Failed - {error_msg}')

            except subprocess.TimeoutExpired:
                failed += 1
                logger.error(f"✗ TIMEOUT: Account {account_number} ({account_name}) after 5 minutes")
                results.append(f'✗ Account {account_number} ({account_name}): Timeout after 5 minutes')
            except Exception as e:
                failed += 1
                logger.error(f"✗ ERROR: Account {account_number} ({account_name}) - {str(e)}")
                results.append(f'✗ Account {account_number} ({account_name}): Error - {str(e)}')

        # Log final summary
        logger.info("="*80)
        logger.info(f"BULK POLL COMPLETED")
        logger.info(f"Total accounts: {total_accounts}")
        logger.info(f"Successful: {successful}")
        logger.info(f"Failed: {failed}")
        logger.info(f"Success rate: {(successful/total_accounts*100):.1f}%")
        logger.info("="*80)

        # Show summary message
        if successful == total_accounts:
            messages.success(
                request,
                f'Successfully polled all {total_accounts} accounts! '
                f'Discovered resources in regions: {", ".join(region_list)}'
            )
        elif successful > 0:
            messages.warning(
                request,
                f'Bulk polling completed: {successful} succeeded, {failed} failed out of {total_accounts} accounts.'
            )
        else:
            messages.error(
                request,
                f'All {total_accounts} accounts failed to poll. Check your credentials and role configuration.'
            )

        # Show detailed results
        for result_msg in results:
            if result_msg.startswith('✓'):
                messages.success(request, result_msg)
            else:
                messages.error(request, result_msg)

    except Exception as e:
        messages.error(request, f'Bulk polling error: {str(e)}')

    return redirect('accounts')


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
    security_groups = SecurityGroup.objects.select_related('vpc').prefetch_related('rules').all().order_by('name')
    
    # Add rule counts for each security group
    for sg in security_groups:
        sg.ingress_count = sg.rules.filter(rule_type='ingress').count()
        sg.egress_count = sg.rules.filter(rule_type='egress').count()
    
    # Get summary statistics
    total_security_groups = SecurityGroup.objects.count()
    total_ingress_rules = SecurityGroupRule.objects.filter(rule_type='ingress').count()
    total_egress_rules = SecurityGroupRule.objects.filter(rule_type='egress').count()
    total_regions = VPC.objects.values('region').distinct().count()
    
    context = {
        'security_groups': security_groups,
        'total_security_groups': total_security_groups,
        'total_ingress_rules': total_ingress_rules,
        'total_egress_rules': total_egress_rules,
        'total_regions': total_regions,
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
    instances = EC2Instance.objects.select_related(
        'vpc', 'subnet'
    ).prefetch_related(
        'enis__secondary_ips', 'enis__eni_security_groups__security_group'
    ).all().order_by('-launch_time')

    # Get summary statistics
    total_instances = EC2Instance.objects.count()
    running_instances = EC2Instance.objects.filter(state='running').count()
    stopped_instances = EC2Instance.objects.filter(state='stopped').count()
    total_regions = EC2Instance.objects.values('region').distinct().count()

    context = {
        'instances': instances,
        'total_instances': total_instances,
        'running_instances': running_instances,
        'stopped_instances': stopped_instances,
        'total_regions': total_regions,
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
