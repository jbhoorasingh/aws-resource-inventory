// Common API response types

export interface PaginatedResponse<T> {
  count: number
  next: string | null
  previous: string | null
  results: T[]
}

export interface SelectOption {
  value: string | number | null
  label: string
  sublabel?: string
}

export interface FilterOptions {
  regions: SelectOption[]
  accounts: SelectOption[]
  vpcs?: SelectOption[]
  subnets?: SelectOption[]
  statuses?: SelectOption[]
  states?: SelectOption[]
  interface_types?: SelectOption[]
  instance_types?: SelectOption[]
}
