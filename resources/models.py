from django.db import models
from django.core.validators import validate_ipv46_address


class AWSAccount(models.Model):
    """AWS Account information"""
    account_id = models.CharField(max_length=12, unique=True, help_text="AWS Account ID")
    account_name = models.CharField(max_length=255, blank=True, help_text="Account name or alias")
    is_active = models.BooleanField(default=True, help_text="Whether this account is actively monitored")
    last_polled = models.DateTimeField(null=True, blank=True, help_text="Last time resources were polled for this account")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['account_id']

    def __str__(self):
        return f"{self.account_name} ({self.account_id})" if self.account_name else self.account_id


class VPC(models.Model):
    """VPC information"""
    vpc_id = models.CharField(max_length=21, unique=True, help_text="VPC ID")
    region = models.CharField(max_length=50, help_text="AWS Region")
    cidr_block = models.CharField(max_length=18, help_text="CIDR block")
    owner_account = models.CharField(max_length=12, help_text="Owner account ID")
    is_default = models.BooleanField(default=False, help_text="Whether this is the default VPC")
    state = models.CharField(max_length=20, help_text="VPC state")
    tags = models.JSONField(default=dict, blank=True, help_text="AWS tags as key-value pairs")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['vpc_id']
        unique_together = ['vpc_id', 'region']

    def __str__(self):
        return f"{self.vpc_id} ({self.region})"


class Subnet(models.Model):
    """Subnet information"""
    subnet_id = models.CharField(max_length=24, unique=True, help_text="Subnet ID")
    vpc = models.ForeignKey(VPC, on_delete=models.CASCADE, related_name='subnets')
    name = models.CharField(max_length=255, blank=True, help_text="Subnet name tag")
    cidr_block = models.CharField(max_length=18, help_text="CIDR block")
    availability_zone = models.CharField(max_length=50, help_text="Availability Zone")
    owner_account = models.CharField(max_length=12, help_text="Owner account ID")
    state = models.CharField(max_length=20, help_text="Subnet state")
    tags = models.JSONField(default=dict, blank=True, help_text="AWS tags as key-value pairs")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['subnet_id']

    def __str__(self):
        return f"{self.name or self.subnet_id} ({self.availability_zone})"


class SecurityGroup(models.Model):
    """Security Group information"""
    sg_id = models.CharField(max_length=20, unique=True, help_text="Security Group ID")
    vpc = models.ForeignKey(VPC, on_delete=models.CASCADE, related_name='security_groups')
    name = models.CharField(max_length=255, help_text="Security Group name")
    description = models.TextField(blank=True, help_text="Security Group description")
    tags = models.JSONField(default=dict, blank=True, help_text="AWS tags as key-value pairs")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['sg_id']

    def __str__(self):
        return f"{self.name} ({self.sg_id})"


class SecurityGroupRule(models.Model):
    """Security Group Rule information"""
    RULE_TYPE_CHOICES = [
        ('ingress', 'Ingress'),
        ('egress', 'Egress'),
    ]
    
    security_group = models.ForeignKey(SecurityGroup, on_delete=models.CASCADE, related_name='rules')
    rule_type = models.CharField(max_length=10, choices=RULE_TYPE_CHOICES, help_text="Rule type (ingress/egress)")
    protocol = models.CharField(max_length=10, help_text="Protocol (tcp, udp, icmp, etc.)")
    from_port = models.IntegerField(null=True, blank=True, help_text="From port")
    to_port = models.IntegerField(null=True, blank=True, help_text="To port")
    source_type = models.CharField(max_length=20, help_text="Source type (cidr, sg, prefix-list, etc.)")
    source_value = models.TextField(help_text="Source value (CIDR, security group ID, etc.)")
    description = models.TextField(blank=True, help_text="Rule description")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['rule_type', 'protocol', 'from_port']
        unique_together = ['security_group', 'rule_type', 'protocol', 'from_port', 'to_port', 'source_type', 'source_value']

    def __str__(self):
        protocol_display = "All" if self.protocol == '-1' else self.protocol.upper()
        if self.from_port is None and self.to_port is None:
            port_range = "All"
        elif self.from_port == self.to_port:
            port_range = str(self.from_port) if self.from_port else "All"
        elif self.from_port and self.to_port:
            port_range = f"{self.from_port}-{self.to_port}"
        else:
            port_range = "All"
        return f"{self.rule_type.upper()} {protocol_display} {port_range} from {self.source_value}"


class EC2Instance(models.Model):
    """EC2 Instance information"""
    instance_id = models.CharField(max_length=19, unique=True, help_text="EC2 Instance ID")
    vpc = models.ForeignKey(VPC, on_delete=models.CASCADE, related_name='instances')
    subnet = models.ForeignKey(Subnet, on_delete=models.CASCADE, related_name='instances')
    name = models.CharField(max_length=255, blank=True, help_text="Instance name tag")
    instance_type = models.CharField(max_length=50, help_text="Instance type (e.g., t2.micro, m5.large)")
    state = models.CharField(max_length=20, help_text="Instance state (running, stopped, etc.)")
    region = models.CharField(max_length=50, help_text="AWS Region")
    availability_zone = models.CharField(max_length=50, help_text="Availability Zone")
    private_ip_address = models.GenericIPAddressField(null=True, blank=True, help_text="Primary private IP address")
    public_ip_address = models.GenericIPAddressField(null=True, blank=True, help_text="Public IP address if assigned")
    platform = models.CharField(max_length=50, blank=True, help_text="Platform (e.g., windows, linux)")
    launch_time = models.DateTimeField(null=True, blank=True, help_text="Instance launch time")
    owner_account = models.CharField(max_length=12, help_text="Owner account ID")
    tags = models.JSONField(default=dict, blank=True, help_text="AWS tags as key-value pairs")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['instance_id']
        unique_together = ['instance_id', 'region']

    def __str__(self):
        return f"{self.name or self.instance_id} ({self.instance_type})"


class ENI(models.Model):
    """Elastic Network Interface information"""
    eni_id = models.CharField(max_length=21, unique=True, help_text="ENI ID")
    subnet = models.ForeignKey(Subnet, on_delete=models.CASCADE, related_name='enis')
    ec2_instance = models.ForeignKey(EC2Instance, on_delete=models.SET_NULL, null=True, blank=True, related_name='enis', help_text="Attached EC2 instance")
    name = models.CharField(max_length=255, blank=True, help_text="ENI name tag")
    description = models.TextField(blank=True, help_text="ENI description")
    interface_type = models.CharField(max_length=50, help_text="Interface type (e.g., interface, gateway_load_balancer)")
    status = models.CharField(max_length=20, help_text="ENI status")
    mac_address = models.CharField(max_length=17, blank=True, help_text="MAC address")
    private_ip_address = models.GenericIPAddressField(help_text="Primary private IP address")
    public_ip_address = models.GenericIPAddressField(blank=True, null=True, help_text="Public IP address if assigned")
    attached_resource_id = models.CharField(max_length=255, blank=True, help_text="ID of attached resource (instance, load balancer, etc.)")
    attached_resource_type = models.CharField(max_length=50, blank=True, help_text="Type of attached resource")
    owner_account = models.CharField(max_length=12, default='', help_text="Owner account ID")
    tags = models.JSONField(default=dict, blank=True, help_text="AWS tags as key-value pairs")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['eni_id']

    def __str__(self):
        return f"{self.name or self.eni_id} ({self.private_ip_address})"


class ENISecondaryIP(models.Model):
    """Secondary IP addresses for ENIs"""
    eni = models.ForeignKey(ENI, on_delete=models.CASCADE, related_name='secondary_ips')
    ip_address = models.GenericIPAddressField(help_text="Secondary IP address")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['eni', 'ip_address']
        ordering = ['ip_address']

    def __str__(self):
        return f"{self.eni.eni_id} - {self.ip_address}"


class ENISecurityGroup(models.Model):
    """Many-to-many relationship between ENIs and Security Groups"""
    eni = models.ForeignKey(ENI, on_delete=models.CASCADE, related_name='eni_security_groups')
    security_group = models.ForeignKey(SecurityGroup, on_delete=models.CASCADE, related_name='sg_enis')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['eni', 'security_group']

    def __str__(self):
        return f"{self.eni.eni_id} - {self.security_group.name}"
