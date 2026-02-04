export interface SecurityGroupRule {
  id: number
  rule_type: 'ingress' | 'egress'
  protocol: string
  from_port: number | null
  to_port: number | null
  source_type: string
  source_value: string
  description: string | null
}

export interface SecurityGroup {
  id: number
  sg_id: string
  vpc: number
  vpc_id: string
  vpc_owner_account: string
  name: string
  description: string | null
  tags: Record<string, string>
  ingress_rules: SecurityGroupRule[]
  egress_rules: SecurityGroupRule[]
  created_at: string
  updated_at: string
}

export interface SecurityGroupFilters {
  region?: string | null
  account?: string | null
  vpc?: string | null
  has_ingress?: 'yes' | 'no' | null
  has_egress?: 'yes' | 'no' | null
  search?: string
  ordering?: string
  page?: number
}
