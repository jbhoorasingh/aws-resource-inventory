import { apiClient } from './client'
import type { SecurityGroup, SecurityGroupFilters } from '@/types/securityGroups'
import type { PaginatedResponse, FilterOptions } from '@/types/api'

export const securityGroupsApi = {
  async list(filters: SecurityGroupFilters = {}): Promise<PaginatedResponse<SecurityGroup>> {
    const queryString = apiClient.buildQueryString({
      ...filters,
      'vpc__region': filters.region,
      'vpc__owner_account': filters.account,
      vpc: filters.vpc,
    })
    return apiClient.getPaginated<SecurityGroup>(`/security-groups/${queryString}`)
  },

  async get(sgId: string): Promise<SecurityGroup> {
    return apiClient.get<SecurityGroup>(`/security-groups/${sgId}/`)
  },

  async getFilterOptions(): Promise<FilterOptions> {
    return apiClient.get<FilterOptions>('/security-groups/filter_options/')
  },
}
