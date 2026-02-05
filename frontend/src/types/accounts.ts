export interface AWSAccount {
  id: number
  account_id: string
  account_name: string | null
  is_active: boolean
  role_arn: string | null
  external_id: string | null
  last_polled: string | null
  created_at: string
  updated_at: string
  eni_count: number
  auth_method: 'instance_role' | 'credentials'
  can_repoll: boolean
}

export interface AccountWithENICount extends AWSAccount {
  eni_count: number
}
