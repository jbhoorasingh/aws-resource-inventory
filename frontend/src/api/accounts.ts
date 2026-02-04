import { apiClient } from './client'
import type { AWSAccount } from '@/types/accounts'
import type { PaginatedResponse, SelectOption } from '@/types/api'

export interface AccountsFilters {
  is_active?: boolean
  search?: string
  ordering?: string
}

export const accountsApi = {
  async list(filters: AccountsFilters = {}): Promise<PaginatedResponse<AWSAccount>> {
    const queryString = apiClient.buildQueryString(filters)
    return apiClient.getPaginated<AWSAccount>(`/accounts/${queryString}`)
  },

  async get(accountId: string): Promise<AWSAccount> {
    return apiClient.get<AWSAccount>(`/accounts/${accountId}/`)
  },

  async getDropdownOptions(): Promise<SelectOption[]> {
    return apiClient.get<SelectOption[]>('/accounts/dropdown_options/')
  },

  async repoll(accountId: string): Promise<{ task_id: number }> {
    return apiClient.post<{ task_id: number }>(`/accounts/${accountId}/repoll/`)
  },

  async repollAll(): Promise<{ task_id: number; message: string }> {
    return apiClient.post<{ task_id: number; message: string }>('/accounts/repoll_all/')
  },
}
