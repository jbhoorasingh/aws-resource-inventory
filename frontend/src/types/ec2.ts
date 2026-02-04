export interface EC2Instance {
  id: number
  instance_id: string
  vpc: number | null
  vpc_id: string | null
  subnet: number | null
  subnet_id: string | null
  eni: number | null
  name: string | null
  instance_type: string
  state: string
  region: string
  availability_zone: string
  private_ip_address: string | null
  public_ip_address: string | null
  platform: string
  launch_time: string
  owner_account: string
  tags: Record<string, string>
  created_at: string
  updated_at: string
}

export interface EC2Filters {
  region?: string | null
  account?: string | null
  state?: string | null
  instance_type?: string | null
  vpc?: string | null
  subnet?: string | null
  has_public_ip?: 'yes' | 'no' | null
  platform?: string | null
  search?: string
  ordering?: string
  page?: number
}
