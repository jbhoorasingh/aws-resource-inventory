import { apiClient } from './client'
import type { VPC, VPCWithResources, VPCFilters } from '@/types/vpcs'
import type { PaginatedResponse, FilterOptions } from '@/types/api'

export const vpcsApi = {
  async list(filters: VPCFilters = {}): Promise<PaginatedResponse<VPC>> {
    const queryString = apiClient.buildQueryString({
      ...filters,
      account: filters.account ? filters.account : undefined,
    })
    return apiClient.getPaginated<VPC>(`/vpcs/${queryString}`)
  },

  async get(id: number): Promise<VPC> {
    return apiClient.get<VPC>(`/vpcs/${id}/`)
  },

  async getTree(filters: VPCFilters = {}): Promise<VPCWithResources[]> {
    const queryString = apiClient.buildQueryString({
      region: filters.region,
      owner_account: filters.account,
      state: filters.state,
    })
    const response = await apiClient.getPaginated<VPCWithResources>(`/vpcs/tree/${queryString}`)
    return response.results
  },

  async getFilterOptions(): Promise<FilterOptions> {
    return apiClient.get<FilterOptions>('/vpcs/filter_options/')
  },
}
