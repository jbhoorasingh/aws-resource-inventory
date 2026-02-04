import { apiClient } from './client'
import type { DiscoveryTask, TaskSummary, TaskFilters } from '@/types/tasks'
import type { PaginatedResponse } from '@/types/api'

export const tasksApi = {
  async list(filters: TaskFilters = {}): Promise<PaginatedResponse<DiscoveryTask>> {
    const queryString = apiClient.buildQueryString(filters)
    return apiClient.getPaginated<DiscoveryTask>(`/discovery-tasks/${queryString}`)
  },

  async get(id: number): Promise<DiscoveryTask> {
    return apiClient.get<DiscoveryTask>(`/discovery-tasks/${id}/`)
  },

  async getSummary(): Promise<TaskSummary> {
    return apiClient.get<TaskSummary>('/discovery-tasks/summary/')
  },

  async cancel(id: number): Promise<DiscoveryTask> {
    return apiClient.post<DiscoveryTask>(`/discovery-tasks/${id}/cancel/`)
  },

  async trigger(data: {
    account_number: string
    account_name?: string
    access_key_id: string
    secret_access_key: string
    session_token?: string
    regions: string[]
    role_arn?: string
    external_id?: string
  }): Promise<DiscoveryTask> {
    return apiClient.post<DiscoveryTask>('/discovery-tasks/trigger/', data)
  },

  async bulkTrigger(data: {
    access_key_id: string
    secret_access_key: string
    session_token?: string
    regions: string[]
    accounts: {
      account_number: string
      account_name?: string
      role_arn?: string
      external_id?: string
    }[]
  }): Promise<DiscoveryTask> {
    return apiClient.post<DiscoveryTask>('/discovery-tasks/bulk_trigger/', data)
  },
}
