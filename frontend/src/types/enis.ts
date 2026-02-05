export interface ENISecondaryIP {
  id: number
  ip_address: string
  created_at: string
}

export interface ENISecurityGroup {
  id: number
  security_group: number
  security_group_name: string
  security_group_id: string
  created_at: string
}

export interface EC2InstanceDetails {
  id: number
  instance_id: string
  name: string | null
  instance_type: string
  state: string
}

export interface ENI {
  id: number
  eni_id: string
  subnet: number
  subnet_id: string
  subnet_cidr: string
  vpc_id: string
  vpc_cidr: string
  vpc_owner_account: string
  subnet_owner_account: string
  name: string | null
  description: string | null
  interface_type: string
  status: string
  mac_address: string
  private_ip_address: string
  public_ip_address: string | null
  attached_resource_id: string | null
  attached_resource_type: string | null
  owner_account: string
  availability_zone: string
  region: string
  secondary_ips: ENISecondaryIP[]
  security_groups: ENISecurityGroup[]
  ec2_instance_details: EC2InstanceDetails | null
  tags: Record<string, string>
  created_at: string
  updated_at: string
}

export interface ENISummary {
  total_accounts: number
  total_vpcs: number
  total_subnets: number
  total_security_groups: number
  total_enis: number
  total_private_ips: number
  total_public_ips: number
  regions: string[]
  accounts: string[]
}

export interface ENIFilters {
  region?: string | null
  account?: string | null
  status?: string | null
  vpc?: string | null
  subnet?: string | null
  interface_type?: string | null
  has_public_ip?: 'yes' | 'no' | null
  attached?: 'yes' | 'no' | null
  search?: string
  ordering?: string
  page?: number
}
