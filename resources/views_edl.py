"""
External Dynamic List (EDL) views for Palo Alto integration
"""
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import cache_page
from django.views.decorators.http import require_http_methods
from django.db.models import Q
from .models import AWSAccount, ENI, ENISecondaryIP, SecurityGroup


@cache_page(300)  # Cache for 5 minutes
def edl_account_ips(request, account_id):
    """EDL endpoint for account IP addresses"""
    try:
        # Get all ENIs owned by this account
        enis = ENI.objects.filter(
            owner_account=account_id
        ).select_related('subnet').prefetch_related('secondary_ips')
        
        ip_lines = []
        
        for eni in enis:
            # Add primary IP
            if eni.private_ip_address:
                ip_lines.append(f"{eni.private_ip_address} # {eni.eni_id}, primary")
            
            # Add secondary IPs
            for secondary_ip in eni.secondary_ips.all():
                ip_lines.append(f"{secondary_ip.ip_address} # {eni.eni_id}, secondary")
        
        # Create response
        response = HttpResponse('\n'.join(ip_lines), content_type='text/plain; charset=utf-8')
        response['X-Content-Type-Options'] = 'nosniff'
        return response
        
    except Exception as e:
        return HttpResponse(f"Error generating EDL: {str(e)}", status=500)


@cache_page(300)  # Cache for 5 minutes
def edl_security_group_ips(request, sg_id):
    """EDL endpoint for security group IP addresses"""
    try:
        # Get security group
        security_group = get_object_or_404(SecurityGroup, sg_id=sg_id)
        
        # Get all ENIs associated with this security group
        enis = ENI.objects.filter(
            eni_security_groups__security_group=security_group
        ).select_related('subnet').prefetch_related('secondary_ips')
        
        ip_lines = []
        
        for eni in enis:
            # Add primary IP
            if eni.private_ip_address:
                ip_lines.append(f"{eni.private_ip_address} # {eni.eni_id}, primary")
            
            # Add secondary IPs
            for secondary_ip in eni.secondary_ips.all():
                ip_lines.append(f"{secondary_ip.ip_address} # {eni.eni_id}, secondary")
        
        # Create response
        response = HttpResponse('\n'.join(ip_lines), content_type='text/plain; charset=utf-8')
        response['X-Content-Type-Options'] = 'nosniff'
        return response
        
    except Exception as e:
        return HttpResponse(f"Error generating EDL: {str(e)}", status=500)


def edl_summary(request):
    """EDL summary page with links to all available EDLs"""
    # Get all unique owner accounts from ENIs (regardless of AWSAccount table)
    owner_accounts = list(set(ENI.objects.values_list('owner_account', flat=True)))
    
    # Create account objects for display (even if not in AWSAccount table)
    accounts_with_enis = []
    for account_id in owner_accounts:
        try:
            # Try to get from AWSAccount table first
            account = AWSAccount.objects.get(account_id=account_id)
        except AWSAccount.DoesNotExist:
            # Create a mock account object for display
            class MockAccount:
                def __init__(self, account_id):
                    self.account_id = account_id
                    self.account_name = f"Account {account_id}"
                    self.eni_count = 0
            account = MockAccount(account_id)
        
        # Add ENI count
        account.eni_count = ENI.objects.filter(
            owner_account=account_id
        ).count()
        
        accounts_with_enis.append(account)
    
    # Sort by account_id
    accounts_with_enis.sort(key=lambda x: x.account_id)
    
    # Get all security groups with associated ENIs
    security_groups_with_enis = SecurityGroup.objects.filter(
        sg_enis__isnull=False
    ).distinct().order_by('name')
    
    # Add ENI counts for each security group
    for sg in security_groups_with_enis:
        sg.eni_count = ENI.objects.filter(
            eni_security_groups__security_group=sg
        ).count()
    
    context = {
        'accounts': accounts_with_enis,
        'security_groups': security_groups_with_enis,
    }
    return render(request, 'resources/edl_summary.html', context)


def edl_account_json(request, account_id):
    """JSON endpoint for account EDL metadata"""
    try:
        account = get_object_or_404(AWSAccount, account_id=account_id)
        
        # Get ENI count
        eni_count = ENI.objects.filter(
            owner_account=account_id
        ).count()
        
        # Get IP count (primary + secondary)
        primary_ips = ENI.objects.filter(
            owner_account=account_id,
            private_ip_address__isnull=False
        ).exclude(private_ip_address='').count()
        
        secondary_ips = ENISecondaryIP.objects.filter(
            eni__owner_account=account_id
        ).count()
        
        total_ips = primary_ips + secondary_ips
        
        data = {
            'account_id': account_id,
            'account_name': account.account_name or '',
            'edl_url': f"/edl/account/{account_id}",
            'eni_count': eni_count,
            'total_ips': total_ips,
            'primary_ips': primary_ips,
            'secondary_ips': secondary_ips,
            'last_updated': account.last_polled.isoformat() if account.last_polled else None,
        }
        
        return JsonResponse(data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def edl_security_group_json(request, sg_id):
    """JSON endpoint for security group EDL metadata"""
    try:
        security_group = get_object_or_404(SecurityGroup, sg_id=sg_id)

        # Get ENI count
        eni_count = ENI.objects.filter(
            eni_security_groups__security_group=security_group
        ).count()

        # Get IP count (primary + secondary)
        primary_ips = ENI.objects.filter(
            eni_security_groups__security_group=security_group,
            private_ip_address__isnull=False
        ).exclude(private_ip_address='').count()

        secondary_ips = ENISecondaryIP.objects.filter(
            eni__eni_security_groups__security_group=security_group
        ).count()

        total_ips = primary_ips + secondary_ips

        data = {
            'sg_id': sg_id,
            'sg_name': security_group.name,
            'vpc_id': security_group.vpc.vpc_id,
            'edl_url': f"/edl/sg/{sg_id}",
            'eni_count': eni_count,
            'total_ips': total_ips,
            'primary_ips': primary_ips,
            'secondary_ips': secondary_ips,
            'last_updated': security_group.updated_at.isoformat(),
        }

        return JsonResponse(data)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@cache_page(300)  # Cache for 5 minutes
def edl_enis_by_tags(request):
    """
    EDL endpoint for ENI IP addresses filtered by tags
    Example: /edl/enis/?Environment=PROD&Application=WebServer
    """
    try:
        # Start with all ENIs
        enis = ENI.objects.all()

        # Get tag filters from query parameters
        tag_filters = {}
        for key, value in request.GET.items():
            if key:  # Ensure key is not empty
                tag_filters[key] = value

        # Filter ENIs by tags
        # For each tag filter, check if the ENI has that tag with the specified value
        for tag_key, tag_value in tag_filters.items():
            enis = enis.filter(**{f'tags__{tag_key}': tag_value})

        # Prefetch related data
        enis = enis.select_related('subnet').prefetch_related('secondary_ips')

        ip_lines = []

        for eni in enis:
            # Add primary IP
            if eni.private_ip_address:
                # Include tag information in comment
                tag_str = ', '.join([f"{k}={v}" for k, v in eni.tags.items()]) if eni.tags else 'no tags'
                ip_lines.append(f"{eni.private_ip_address} # {eni.eni_id}, primary, tags: {tag_str}")

            # Add secondary IPs
            for secondary_ip in eni.secondary_ips.all():
                tag_str = ', '.join([f"{k}={v}" for k, v in eni.tags.items()]) if eni.tags else 'no tags'
                ip_lines.append(f"{secondary_ip.ip_address} # {eni.eni_id}, secondary, tags: {tag_str}")

        # Create response
        response = HttpResponse('\n'.join(ip_lines), content_type='text/plain; charset=utf-8')
        response['X-Content-Type-Options'] = 'nosniff'
        return response

    except Exception as e:
        return HttpResponse(f"Error generating EDL: {str(e)}", status=500)


def edl_enis_by_tags_json(request):
    """JSON endpoint for tag-filtered ENI EDL metadata"""
    try:
        # Start with all ENIs
        enis = ENI.objects.all()

        # Get tag filters from query parameters
        tag_filters = {}
        for key, value in request.GET.items():
            if key:  # Ensure key is not empty
                tag_filters[key] = value

        # Filter ENIs by tags
        for tag_key, tag_value in tag_filters.items():
            enis = enis.filter(**{f'tags__{tag_key}': tag_value})

        # Count results
        eni_count = enis.count()

        # Get IP count (primary + secondary)
        primary_ips = enis.filter(
            private_ip_address__isnull=False
        ).exclude(private_ip_address='').count()

        secondary_ips = ENISecondaryIP.objects.filter(
            eni__in=enis
        ).count()

        total_ips = primary_ips + secondary_ips

        # Build query string for URL
        query_string = '&'.join([f"{k}={v}" for k, v in tag_filters.items()])

        data = {
            'filters': tag_filters,
            'edl_url': f"/edl/enis/?{query_string}" if query_string else "/edl/enis/",
            'eni_count': eni_count,
            'total_ips': total_ips,
            'primary_ips': primary_ips,
            'secondary_ips': secondary_ips,
        }

        return JsonResponse(data)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
