"""
API views for AWS resources
"""
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Q
from .models import (
    AWSAccount, VPC, Subnet, SecurityGroup, ENI, 
    ENISecondaryIP, ENISecurityGroup
)
from .serializers import (
    AWSAccountSerializer, VPCSerializer, SubnetSerializer, 
    SecurityGroupSerializer, ENISerializer, ENIDetailSerializer,
    ResourceSummarySerializer
)


class AWSAccountViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AWSAccount.objects.all()
    serializer_class = AWSAccountSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_active']
    search_fields = ['account_id', 'account_name']
    ordering_fields = ['account_id', 'account_name', 'created_at']
    ordering = ['account_id']


class VPCViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = VPC.objects.all()
    serializer_class = VPCSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['region', 'is_default', 'state', 'owner_account']
    search_fields = ['vpc_id', 'cidr_block', 'owner_account']
    ordering_fields = ['vpc_id', 'region', 'created_at']
    ordering = ['vpc_id']


class SubnetViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Subnet.objects.select_related('vpc').all()
    serializer_class = SubnetSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['vpc', 'vpc__region', 'availability_zone', 'state', 'owner_account']
    search_fields = ['subnet_id', 'name', 'cidr_block', 'owner_account']
    ordering_fields = ['subnet_id', 'name', 'availability_zone', 'created_at']
    ordering = ['subnet_id']


class SecurityGroupViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SecurityGroup.objects.select_related('vpc').prefetch_related('rules').all()
    serializer_class = SecurityGroupSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['vpc', 'vpc__region']
    search_fields = ['sg_id', 'name', 'description']
    ordering_fields = ['sg_id', 'name', 'created_at']
    ordering = ['sg_id']


class ENIViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = ENI.objects.select_related(
        'subnet__vpc'
    ).prefetch_related(
        'secondary_ips', 'eni_security_groups__security_group'
    ).all()
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = [
        'subnet', 'subnet__vpc', 'subnet__vpc__region', 'owner_account',
        'interface_type', 'status', 'attached_resource_type'
    ]
    search_fields = [
        'eni_id', 'name', 'description', 'private_ip_address', 
        'public_ip_address', 'attached_resource_id'
    ]
    ordering_fields = [
        'eni_id', 'name', 'private_ip_address', 'public_ip_address', 
        'interface_type', 'status', 'created_at'
    ]
    ordering = ['eni_id']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return ENIDetailSerializer
        return ENISerializer

    @action(detail=False, methods=['get'])
    def by_ip(self, request):
        """Find ENIs by IP address (private or public)"""
        ip_address = request.query_params.get('ip')
        if not ip_address:
            return Response(
                {'error': 'ip parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        enis = self.get_queryset().filter(
            Q(private_ip_address=ip_address) | 
            Q(public_ip_address=ip_address) |
            Q(secondary_ips__ip_address=ip_address)
        ).distinct()
        
        serializer = self.get_serializer(enis, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def with_public_ip(self, request):
        """Find ENIs with public IP addresses"""
        enis = self.get_queryset().filter(public_ip_address__isnull=False)
        serializer = self.get_serializer(enis, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def attached_resources(self, request):
        """Find ENIs with attached resources"""
        resource_type = request.query_params.get('type')
        enis = self.get_queryset().exclude(attached_resource_id='')
        
        if resource_type:
            enis = enis.filter(attached_resource_type=resource_type)
        
        serializer = self.get_serializer(enis, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get summary statistics"""
        # Get basic counts
        total_accounts = AWSAccount.objects.count()
        total_vpcs = VPC.objects.count()
        total_subnets = Subnet.objects.count()
        total_security_groups = SecurityGroup.objects.count()
        total_enis = ENI.objects.count()
        
        # Count IP addresses
        total_private_ips = ENI.objects.filter(private_ip_address__isnull=False).count()
        total_public_ips = ENI.objects.filter(public_ip_address__isnull=False).count()
        
        # Get unique regions and accounts
        regions = list(VPC.objects.values_list('region', flat=True).distinct())
        accounts = list(AWSAccount.objects.values_list('account_id', flat=True))
        
        summary_data = {
            'total_accounts': total_accounts,
            'total_vpcs': total_vpcs,
            'total_subnets': total_subnets,
            'total_security_groups': total_security_groups,
            'total_enis': total_enis,
            'total_private_ips': total_private_ips,
            'total_public_ips': total_public_ips,
            'regions': regions,
            'accounts': accounts
        }
        
        serializer = ResourceSummarySerializer(summary_data)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def by_region(self, request):
        """Get ENIs grouped by region"""
        region = request.query_params.get('region')
        if not region:
            return Response(
                {'error': 'region parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        enis = self.get_queryset().filter(subnet__vpc__region=region)
        serializer = self.get_serializer(enis, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def by_owner_account(self, request):
        """Get ENIs grouped by owner account"""
        owner_account = request.query_params.get('owner_account')
        if not owner_account:
            return Response(
                {'error': 'owner_account parameter is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        enis = self.get_queryset().filter(owner_account=owner_account)
        serializer = self.get_serializer(enis, many=True)
        return Response(serializer.data)
