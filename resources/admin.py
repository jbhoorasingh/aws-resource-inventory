"""
Django admin configuration for AWS resources
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.utils.html import format_html
from .models import (
    UserProfile, AWSAccount, VPC, Subnet, SecurityGroup, SecurityGroupRule, EC2Instance, ENI,
    ENISecondaryIP, ENISecurityGroup, DiscoveryTask
)


# User Profile Admin (inline with User)
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = ['api_token', 'created_at', 'updated_at']
    readonly_fields = ['api_token', 'created_at', 'updated_at']


class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    list_display = ['username', 'email', 'first_name', 'last_name', 'is_staff', 'can_poll']

    def can_poll(self, obj):
        """Check if user has permission to poll accounts"""
        return obj.has_perm('resources.can_poll_accounts')
    can_poll.boolean = True
    can_poll.short_description = 'Can Poll Accounts'


# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(AWSAccount)
class AWSAccountAdmin(admin.ModelAdmin):
    list_display = ['account_id', 'account_name', 'is_active', 'has_role_assumption', 'last_polled', 'created_at']
    list_filter = ['is_active', 'created_at', 'last_polled']
    search_fields = ['account_id', 'account_name', 'role_arn']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-last_polled', 'account_id']

    fieldsets = (
        ('Account Information', {
            'fields': ('account_id', 'account_name', 'is_active', 'last_polled')
        }),
        ('Role Assumption Configuration', {
            'fields': ('role_arn', 'external_id'),
            'description': 'Configure role assumption for cross-account access. Leave blank for direct credential access.'
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def has_role_assumption(self, obj):
        return bool(obj.role_arn)
    has_role_assumption.boolean = True
    has_role_assumption.short_description = 'Uses Role'


@admin.register(VPC)
class VPCAdmin(admin.ModelAdmin):
    list_display = ['vpc_id', 'region', 'cidr_block', 'owner_account', 'is_default', 'state']
    list_filter = ['region', 'is_default', 'state', 'owner_account', 'created_at']
    search_fields = ['vpc_id', 'cidr_block', 'owner_account']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Subnet)
class SubnetAdmin(admin.ModelAdmin):
    list_display = ['subnet_id', 'name', 'vpc', 'cidr_block', 'availability_zone', 'owner_account', 'state']
    list_filter = ['vpc__region', 'availability_zone', 'state', 'owner_account', 'created_at']
    search_fields = ['subnet_id', 'name', 'cidr_block', 'owner_account']
    readonly_fields = ['created_at', 'updated_at']
    raw_id_fields = ['vpc']


class SecurityGroupRuleInline(admin.TabularInline):
    model = SecurityGroupRule
    extra = 0
    readonly_fields = ['created_at']
    fields = ['rule_type', 'protocol', 'from_port', 'to_port', 'source_type', 'source_value', 'description', 'created_at']


@admin.register(SecurityGroup)
class SecurityGroupAdmin(admin.ModelAdmin):
    list_display = ['sg_id', 'name', 'vpc', 'rules_count', 'description_short']
    list_filter = ['vpc__region', 'created_at']
    search_fields = ['sg_id', 'name', 'description']
    readonly_fields = ['created_at', 'updated_at']
    raw_id_fields = ['vpc']
    inlines = [SecurityGroupRuleInline]

    def description_short(self, obj):
        return obj.description[:50] + '...' if len(obj.description) > 50 else obj.description
    description_short.short_description = 'Description'

    def rules_count(self, obj):
        return obj.rules.count()
    rules_count.short_description = 'Rules'


@admin.register(SecurityGroupRule)
class SecurityGroupRuleAdmin(admin.ModelAdmin):
    list_display = ['security_group', 'rule_type', 'protocol_display', 'port_range', 'source_value', 'description_short']
    list_filter = ['rule_type', 'protocol', 'source_type', 'created_at']
    search_fields = ['security_group__name', 'source_value', 'description']
    readonly_fields = ['created_at']
    raw_id_fields = ['security_group']

    def protocol_display(self, obj):
        if obj.protocol == '-1':
            return 'All'
        return obj.protocol.upper()
    protocol_display.short_description = 'Protocol'

    def port_range(self, obj):
        if obj.from_port is None and obj.to_port is None:
            return 'All'
        elif obj.from_port == obj.to_port:
            return str(obj.from_port) if obj.from_port else 'All'
        elif obj.from_port and obj.to_port:
            return f"{obj.from_port}-{obj.to_port}"
        else:
            return 'All'
    port_range.short_description = 'Port Range'

    def description_short(self, obj):
        return obj.description[:30] + '...' if len(obj.description) > 30 else obj.description
    description_short.short_description = 'Description'


@admin.register(EC2Instance)
class EC2InstanceAdmin(admin.ModelAdmin):
    list_display = ['instance_id', 'name', 'instance_type', 'state', 'vpc', 'subnet', 'private_ip_address', 'public_ip_address', 'region', 'availability_zone']
    list_filter = ['state', 'region', 'availability_zone', 'instance_type', 'platform', 'owner_account', 'created_at']
    search_fields = ['instance_id', 'name', 'private_ip_address', 'public_ip_address', 'owner_account']
    readonly_fields = ['created_at', 'updated_at', 'launch_time']
    raw_id_fields = ['vpc', 'subnet']
    ordering = ['-launch_time']

    fieldsets = (
        ('Instance Information', {
            'fields': ('instance_id', 'name', 'instance_type', 'state', 'platform')
        }),
        ('Network Information', {
            'fields': ('vpc', 'subnet', 'private_ip_address', 'public_ip_address', 'region', 'availability_zone')
        }),
        ('Metadata', {
            'fields': ('owner_account', 'launch_time', 'created_at', 'updated_at')
        }),
    )


class ENISecondaryIPInline(admin.TabularInline):
    model = ENISecondaryIP
    extra = 0
    readonly_fields = ['created_at']
    fields = ['ip_address', 'created_at']
    verbose_name = 'Secondary IP Address'
    verbose_name_plural = 'Secondary IP Addresses'


class ENISecurityGroupInline(admin.TabularInline):
    model = ENISecurityGroup
    extra = 0
    readonly_fields = ['created_at']
    fields = ['security_group', 'created_at']
    verbose_name = 'Security Group'
    verbose_name_plural = 'Security Groups'


@admin.register(ENI)
class ENIAdmin(admin.ModelAdmin):
    list_display = [
        'eni_id', 'name', 'subnet', 'private_ip_address', 'public_ip_address',
        'interface_type', 'status', 'ec2_instance_info', 'attached_resource_info', 'secondary_ips_count', 'security_groups_count'
    ]
    list_filter = [
        'subnet__vpc__region', 'interface_type',
        'status', 'attached_resource_type', 'created_at'
    ]
    search_fields = [
        'eni_id', 'name', 'description', 'private_ip_address',
        'public_ip_address', 'attached_resource_id', 'ec2_instance__instance_id', 'ec2_instance__name'
    ]
    readonly_fields = ['created_at', 'updated_at', 'secondary_ips_list', 'security_groups_list']
    raw_id_fields = ['subnet', 'ec2_instance']
    inlines = [ENISecondaryIPInline, ENISecurityGroupInline]

    def ec2_instance_info(self, obj):
        if obj.ec2_instance:
            instance = obj.ec2_instance
            display_name = instance.name or instance.instance_id
            return format_html('<span style="color: green;">{} ({})</span>', display_name, instance.state)
        return "-"
    ec2_instance_info.short_description = 'EC2 Instance'

    def attached_resource_info(self, obj):
        if obj.attached_resource_id and obj.attached_resource_type != 'instance':
            return f"{obj.attached_resource_type}: {obj.attached_resource_id}"
        return "-"
    attached_resource_info.short_description = 'Other Resource'

    def secondary_ips_count(self, obj):
        return obj.secondary_ips.count()
    secondary_ips_count.short_description = 'Secondary IPs'

    def security_groups_count(self, obj):
        return obj.eni_security_groups.count()
    security_groups_count.short_description = 'Security Groups'

    def secondary_ips_list(self, obj):
        ips = obj.secondary_ips.all()
        if ips:
            return ', '.join([ip.ip_address for ip in ips])
        return "None"
    secondary_ips_list.short_description = 'Secondary IP Addresses'

    def security_groups_list(self, obj):
        sgs = obj.eni_security_groups.all()
        if sgs:
            return ', '.join([sg.security_group.name for sg in sgs])
        return "None"
    security_groups_list.short_description = 'Security Groups'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'subnet__vpc'
        ).prefetch_related(
            'secondary_ips', 'eni_security_groups__security_group'
        )


@admin.register(ENISecondaryIP)
class ENISecondaryIPAdmin(admin.ModelAdmin):
    list_display = ['eni', 'ip_address', 'created_at']
    list_filter = ['created_at']
    search_fields = ['eni__eni_id', 'ip_address']
    raw_id_fields = ['eni']


@admin.register(ENISecurityGroup)
class ENISecurityGroupAdmin(admin.ModelAdmin):
    list_display = ['eni', 'security_group', 'created_at']
    list_filter = ['created_at']
    search_fields = ['eni__eni_id', 'security_group__name']
    raw_id_fields = ['eni', 'security_group']


class ChildTaskInline(admin.TabularInline):
    model = DiscoveryTask
    fk_name = 'parent_task'
    extra = 0
    readonly_fields = ['task_id', 'task_type', 'status', 'account', 'started_at', 'completed_at', 'error_message']
    fields = ['task_id', 'task_type', 'status', 'account', 'started_at', 'completed_at', 'error_message']
    can_delete = False
    verbose_name = 'Child Task'
    verbose_name_plural = 'Child Tasks'
    show_change_link = True

    def has_add_permission(self, request, obj=None):
        return False


@admin.register(DiscoveryTask)
class DiscoveryTaskAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'task_type', 'status_badge', 'account_info', 'initiated_by',
        'progress_info', 'duration_display', 'created_at'
    ]
    list_filter = ['status', 'task_type', 'created_at', 'initiated_by']
    search_fields = ['task_id', 'account__account_id', 'account__account_name', 'initiated_by__username']
    readonly_fields = [
        'task_id', 'created_at', 'started_at', 'completed_at',
        'result_summary', 'error_message', 'duration_display', 'progress_info'
    ]
    raw_id_fields = ['account', 'initiated_by', 'parent_task']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    inlines = [ChildTaskInline]

    fieldsets = (
        ('Task Information', {
            'fields': ('task_id', 'task_type', 'status', 'account', 'regions')
        }),
        ('User & Parent', {
            'fields': ('initiated_by', 'parent_task')
        }),
        ('Progress (Bulk Tasks)', {
            'fields': ('total_accounts', 'completed_accounts', 'failed_accounts', 'progress_info'),
            'classes': ('collapse',)
        }),
        ('Results', {
            'fields': ('result_summary', 'error_message')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'started_at', 'completed_at', 'duration_display'),
            'classes': ('collapse',)
        }),
    )

    def status_badge(self, obj):
        colors = {
            'pending': '#FFC107',
            'running': '#17A2B8',
            'success': '#28A745',
            'failed': '#DC3545',
            'cancelled': '#6C757D',
        }
        color = colors.get(obj.status, '#6C757D')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; '
            'border-radius: 3px; font-size: 11px;">{}</span>',
            color, obj.status.upper()
        )
    status_badge.short_description = 'Status'

    def account_info(self, obj):
        if obj.account:
            return f"{obj.account.account_name or obj.account.account_id}"
        elif obj.task_type == 'bulk':
            return f"Bulk ({obj.total_accounts} accounts)"
        return "-"
    account_info.short_description = 'Account'

    def progress_info(self, obj):
        if obj.task_type == 'bulk':
            return f"{obj.completed_accounts}/{obj.total_accounts} ({obj.progress_percentage:.0f}%)"
        return "-"
    progress_info.short_description = 'Progress'

    def duration_display(self, obj):
        duration = obj.duration
        if duration:
            if duration < 60:
                return f"{duration:.1f}s"
            minutes = int(duration // 60)
            seconds = duration % 60
            return f"{minutes}m {seconds:.0f}s"
        return "-"
    duration_display.short_description = 'Duration'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'account', 'initiated_by', 'parent_task'
        ).prefetch_related('child_tasks')

    actions = ['cancel_tasks']

    @admin.action(description='Cancel selected tasks')
    def cancel_tasks(self, request, queryset):
        updated = queryset.filter(status__in=['pending', 'running']).update(status='cancelled')
        self.message_user(request, f'{updated} task(s) cancelled.')


# Customize admin site
admin.site.site_header = "AWS Resource Inventory"
admin.site.site_title = "AWS Resources"
admin.site.index_title = "AWS Resource Management"
