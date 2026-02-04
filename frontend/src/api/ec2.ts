import { apiClient } from './client'
import type { EC2Instance, EC2Filters } from '@/types/ec2'
import type { PaginatedResponse, FilterOptions } from '@/types/api'

export const ec2Api = {
  async list(filters: EC2Filters = {}): Promise<PaginatedResponse<EC2Instance>> {
    const queryString = apiClient.buildQueryString({
      ...filters,
      account: filters.account ? filters.account : undefined,
      owner_account: filters.account,
    })
    return apiClient.getPaginated<EC2Instance>(`/ec2-instances/${queryString}`)
  },

  async get(instanceId: string): Promise<EC2Instance> {
    return apiClient.get<EC2Instance>(`/ec2-instances/${instanceId}/`)
  },

  async getFilterOptions(): Promise<FilterOptions> {
    return apiClient.get<FilterOptions>('/ec2-instances/filter_options/')
  },
}
