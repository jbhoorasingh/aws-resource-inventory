import { ref, type Ref } from 'vue'

export interface UseApiOptions {
  immediate?: boolean
}

export interface UseApiReturn<T, P> {
  data: Ref<T | null>
  loading: Ref<boolean>
  error: Ref<Error | null>
  execute: (params: P) => Promise<T | null>
}

export function useApi<T, P = void>(
  fetcher: (params: P) => Promise<T>,
  _options: UseApiOptions = {}
): UseApiReturn<T, P> {
  const data = ref<T | null>(null) as Ref<T | null>
  const loading = ref(false)
  const error = ref<Error | null>(null)

  const execute = async (params: P): Promise<T | null> => {
    loading.value = true
    error.value = null

    try {
      data.value = await fetcher(params)
      return data.value
    } catch (e) {
      error.value = e as Error
      console.error('API Error:', e)
      return null
    } finally {
      loading.value = false
    }
  }

  return {
    data,
    loading,
    error,
    execute,
  }
}

// Helper for paginated API calls
export function usePaginatedApi<T, P extends { page?: number }>(
  fetcher: (params: P) => Promise<{ count: number; results: T[]; next: string | null; previous: string | null }>,
) {
  const items = ref<T[]>([]) as Ref<T[]>
  const totalCount = ref(0)
  const loading = ref(false)
  const error = ref<Error | null>(null)
  const currentPage = ref(1)
  const hasNext = ref(false)
  const hasPrevious = ref(false)

  const execute = async (params: P): Promise<void> => {
    loading.value = true
    error.value = null

    try {
      const response = await fetcher(params)
      items.value = response.results
      totalCount.value = response.count
      hasNext.value = response.next !== null
      hasPrevious.value = response.previous !== null
      currentPage.value = params.page || 1
    } catch (e) {
      error.value = e as Error
      console.error('API Error:', e)
    } finally {
      loading.value = false
    }
  }

  return {
    items,
    totalCount,
    loading,
    error,
    currentPage,
    hasNext,
    hasPrevious,
    execute,
  }
}
