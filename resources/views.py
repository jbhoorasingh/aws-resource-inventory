"""
API views for AWS resources
"""
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from .models import (
    AWSAccount, VPC, Subnet, SecurityGroup, ENI,
    ENISecondaryIP, ENISecurityGroup, DiscoveryTask
)
from .serializers import (
    AWSAccountSerializer, VPCSerializer, SubnetSerializer,
    SecurityGroupSerializer, ENISerializer, ENIDetailSerializer,
    ResourceSummarySerializer, VPCTreeSerializer, SubnetTreeSerializer,
    DiscoveryTaskSerializer, DiscoveryTaskDetailSerializer,
    TriggerDiscoverySerializer, TriggerBulkDiscoverySerializer
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

    @action(detail=False, methods=['get'])
    def tree(self, request):
        """Get VPCs with nested subnets and all resources in tree structure"""
        # Get filtered VPCs
        queryset = self.filter_queryset(self.get_queryset())

        # Prefetch all related resources for efficiency
        queryset = queryset.prefetch_related(
            'subnets',
            'subnets__enis__secondary_ips',
            'subnets__enis__eni_security_groups__security_group__rules',
            'subnets__enis__ec2_instance',
            'subnets__instances',
            'security_groups__rules'
        )

        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = VPCTreeSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = VPCTreeSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def tree_detail(self, request, pk=None):
        """Get single VPC with nested subnets and all resources"""
        vpc = self.get_object()
        serializer = VPCTreeSerializer(vpc)
        return Response(serializer.data)


class SubnetViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Subnet.objects.select_related('vpc').all()
    serializer_class = SubnetSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['vpc', 'vpc__region', 'availability_zone', 'state', 'owner_account']
    search_fields = ['subnet_id', 'name', 'cidr_block', 'owner_account']
    ordering_fields = ['subnet_id', 'name', 'availability_zone', 'created_at']
    ordering = ['subnet_id']

    @action(detail=False, methods=['get'])
    def tree(self, request):
        """Get subnets with nested ENIs, EC2 instances, and security groups"""
        # Get filtered subnets
        queryset = self.filter_queryset(self.get_queryset())

        # Prefetch all related resources for efficiency
        queryset = queryset.prefetch_related(
            'enis__secondary_ips',
            'enis__eni_security_groups__security_group__rules',
            'enis__ec2_instance',
            'instances'
        )

        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = SubnetTreeSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = SubnetTreeSerializer(queryset, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def tree_detail(self, request, pk=None):
        """Get single subnet with nested resources"""
        subnet = self.get_object()
        serializer = SubnetTreeSerializer(subnet)
        return Response(serializer.data)


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


class DiscoveryTaskViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing and managing discovery tasks.

    list: Get all discovery tasks (paginated)
    retrieve: Get details of a specific task including child tasks
    trigger: Start a new single-account discovery
    bulk_trigger: Start a new bulk discovery operation
    cancel: Cancel a pending or running task
    summary: Get task statistics
    """
    queryset = DiscoveryTask.objects.select_related(
        'account', 'initiated_by', 'parent_task'
    ).prefetch_related('child_tasks')
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['status', 'task_type', 'account']
    ordering_fields = ['created_at', 'started_at', 'completed_at']
    ordering = ['-created_at']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return DiscoveryTaskDetailSerializer
        return DiscoveryTaskSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        # Filter to show only tasks initiated by the user or all if superuser
        if not self.request.user.is_superuser:
            qs = qs.filter(initiated_by=self.request.user)
        return qs

    @action(detail=False, methods=['post'])
    def trigger(self, request):
        """Trigger a single account discovery task"""
        from .tasks import discover_account_resources

        # Check permission
        if not (request.user.has_perm('resources.can_poll_accounts') or
                request.user.is_superuser):
            return Response(
                {'error': 'Permission denied. You need the can_poll_accounts permission.'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = TriggerDiscoverySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Get or create account immediately
        account, _ = AWSAccount.objects.get_or_create(
            account_id=data['account_number'],
            defaults={
                'account_name': data.get('account_name', ''),
                'role_arn': data.get('role_arn', ''),
                'external_id': data.get('external_id', ''),
            }
        )

        # Create task record
        task_record = DiscoveryTask.objects.create(
            task_type='single',
            status='pending',
            account=account,
            regions=data['regions'],
            initiated_by=request.user,
            total_accounts=1
        )

        # Queue the Celery task
        discover_account_resources.delay(
            task_record_id=task_record.id,
            account_number=data['account_number'],
            account_name=data.get('account_name', ''),
            access_key_id=data['access_key_id'],
            secret_access_key=data['secret_access_key'],
            session_token=data.get('session_token', ''),
            regions=data['regions'],
            role_arn=data.get('role_arn'),
            external_id=data.get('external_id')
        )

        return Response(
            DiscoveryTaskSerializer(task_record).data,
            status=status.HTTP_202_ACCEPTED
        )

    @action(detail=False, methods=['post'])
    def bulk_trigger(self, request):
        """Trigger bulk discovery across multiple accounts"""
        from .tasks import bulk_discover_resources

        # Check permission
        if not (request.user.has_perm('resources.can_poll_accounts') or
                request.user.is_superuser):
            return Response(
                {'error': 'Permission denied. You need the can_poll_accounts permission.'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = TriggerBulkDiscoverySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Create parent task record
        task_record = DiscoveryTask.objects.create(
            task_type='bulk',
            status='pending',
            regions=data['regions'],
            initiated_by=request.user,
            total_accounts=len(data['accounts'])
        )

        # Queue the bulk discovery task
        bulk_discover_resources.delay(
            task_record_id=task_record.id,
            access_key_id=data['access_key_id'],
            secret_access_key=data['secret_access_key'],
            session_token=data.get('session_token', ''),
            regions=data['regions'],
            accounts_config=[dict(a) for a in data['accounts']],
            user_id=request.user.id
        )

        return Response(
            DiscoveryTaskSerializer(task_record).data,
            status=status.HTTP_202_ACCEPTED
        )

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a pending or running task"""
        task = self.get_object()

        if task.status not in ['pending', 'running']:
            return Response(
                {'error': 'Only pending or running tasks can be cancelled'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Revoke the Celery task if it has a task_id
        if task.task_id:
            from aws_inventory.celery import app
            app.control.revoke(task.task_id, terminate=True)

        task.status = 'cancelled'
        task.completed_at = timezone.now()
        task.save()

        return Response(DiscoveryTaskSerializer(task).data)

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get summary statistics of discovery tasks"""
        qs = self.get_queryset()

        return Response({
            'total_tasks': qs.count(),
            'pending': qs.filter(status='pending').count(),
            'running': qs.filter(status='running').count(),
            'success': qs.filter(status='success').count(),
            'failed': qs.filter(status='failed').count(),
            'cancelled': qs.filter(status='cancelled').count(),
        })
