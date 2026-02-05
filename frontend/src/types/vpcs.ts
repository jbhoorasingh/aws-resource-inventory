import type { ENI } from './enis'

export interface VPC {
  id: number
  vpc_id: string
  region: string
  cidr_block: string
  owner_account: string
  is_default: boolean
  state: string
  tags: Record<string, string>
  created_at: string
  updated_at: string
}

export interface Subnet {
  id: number
  subnet_id: string
  vpc: number
  vpc_id: string
  vpc_cidr: string
  vpc_owner_account: string
  name: string | null
  cidr_block: string
  availability_zone: string
  owner_account: string
  state: string
  tags: Record<string, string>
  created_at: string
  updated_at: string
}

export interface VPCWithResources extends VPC {
  subnets: SubnetWithResources[]
  resource_counts: {
    subnet_count: number
    eni_count: number
    ec2_instance_count: number
    security_group_count: number
  }
}

export interface SubnetWithResources extends Subnet {
  enis: ENI[]
  resource_counts: {
    eni_count: number
    ec2_instance_count: number
    security_group_count: number
  }
}

export interface VPCFilters {
  region?: string | null
  account?: string | null
  state?: string | null
  search?: string
  ordering?: string
}
