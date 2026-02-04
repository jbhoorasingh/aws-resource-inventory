import { apiClient } from './client'
import type { ENI, ENISummary, ENIFilters } from '@/types/enis'
import type { PaginatedResponse, FilterOptions } from '@/types/api'

// Map frontend filter names to API query params
const filterMapping: Record<string, string> = {
  region: 'subnet__vpc__region',
  account: 'owner_account',
  vpc: 'subnet__vpc',
  subnet: 'subnet',
}

function mapFilters(filters: ENIFilters): Record<string, unknown> {
  const mapped: Record<string, unknown> = {}
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      const apiKey = filterMapping[key] || key
      mapped[apiKey] = value
    }
  })
  return mapped
}

export const enisApi = {
  async list(filters: ENIFilters = {}): Promise<PaginatedResponse<ENI>> {
    const mappedFilters = mapFilters(filters)
    const queryString = apiClient.buildQueryString(mappedFilters)
    return apiClient.getPaginated<ENI>(`/enis/${queryString}`)
  },

  async get(id: number): Promise<ENI> {
    return apiClient.get<ENI>(`/enis/${id}/`)
  },

  async getSummary(): Promise<ENISummary> {
    return apiClient.get<ENISummary>('/enis/summary/')
  },

  async getFilterOptions(): Promise<FilterOptions> {
    return apiClient.get<FilterOptions>('/enis/filter_options/')
  },

  async getByIp(ip: string): Promise<ENI[]> {
    return apiClient.get<ENI[]>(`/enis/by_ip/?ip=${encodeURIComponent(ip)}`)
  },

  async getWithPublicIp(): Promise<PaginatedResponse<ENI>> {
    return apiClient.getPaginated<ENI>('/enis/with_public_ip/')
  },
}
