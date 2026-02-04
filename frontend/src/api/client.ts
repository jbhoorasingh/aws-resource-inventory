import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios'
import type { PaginatedResponse } from '@/types/api'

class ApiClient {
  private instance: AxiosInstance

  constructor() {
    this.instance = axios.create({
      baseURL: '/api',
      headers: {
        'Content-Type': 'application/json',
      },
      // Include cookies for session authentication
      withCredentials: true,
    })

    // Add CSRF token to requests
    this.instance.interceptors.request.use((config) => {
      const csrfToken = this.getCsrfToken()
      if (csrfToken && config.method !== 'get') {
        config.headers['X-CSRFToken'] = csrfToken
      }
      return config
    })
  }

  private getCsrfToken(): string | null {
    // Try to get from cookie
    const cookieValue = document.cookie
      .split('; ')
      .find(row => row.startsWith('csrftoken='))
      ?.split('=')[1]

    if (cookieValue) return cookieValue

    // Fallback: try to get from meta tag or data attribute
    const metaTag = document.querySelector('meta[name="csrf-token"]')
    if (metaTag) return metaTag.getAttribute('content')

    const mountPoint = document.querySelector('[data-csrf-token]')
    if (mountPoint) return mountPoint.getAttribute('data-csrf-token')

    return null
  }

  async get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.get<T>(url, config)
    return response.data
  }

  async getPaginated<T>(url: string, config?: AxiosRequestConfig): Promise<PaginatedResponse<T>> {
    const response = await this.instance.get<PaginatedResponse<T>>(url, config)
    return response.data
  }

  async post<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.post<T>(url, data, config)
    return response.data
  }

  async put<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.put<T>(url, data, config)
    return response.data
  }

  async patch<T>(url: string, data?: unknown, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.patch<T>(url, data, config)
    return response.data
  }

  async delete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
    const response = await this.instance.delete<T>(url, config)
    return response.data
  }

  buildQueryString<T extends object>(params: T): string {
    const searchParams = new URLSearchParams()
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        searchParams.append(key, String(value))
      }
    })
    const queryString = searchParams.toString()
    return queryString ? `?${queryString}` : ''
  }
}

export const apiClient = new ApiClient()
