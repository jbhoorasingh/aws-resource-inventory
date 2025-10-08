"""
Frontend views for AWS Resource Inventory
"""
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Count, Q
from django.utils import timezone
import subprocess
import json
from .models import AWSAccount, ENI, VPC, Subnet, ENISecondaryIP, SecurityGroup, SecurityGroupRule


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


def enis_view(request):
    """Display ENIs page with detailed information"""
    enis = ENI.objects.select_related(
        'subnet__vpc'
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
        
        # Execute the command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd='.'
        )
        
        if result.returncode == 0:
            messages.success(
                request, 
                f'Successfully polled account {account_number}. '
                f'Discovered resources in regions: {", ".join(region_list)}'
            )
        else:
            messages.error(
                request, 
                f'Failed to poll account {account_number}. '
                f'Error: {result.stderr}'
            )
    
    except Exception as e:
        messages.error(request, f'An error occurred: {str(e)}')
    
    return redirect('accounts')


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
