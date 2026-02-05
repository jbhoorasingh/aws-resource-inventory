import { reactive, computed, type UnwrapRef } from 'vue'

export function useFilters<T extends Record<string, unknown>>(
  initialState: T,
  onApply?: (filters: T) => void
) {
  // Current applied filters
  const filters = reactive<T>({ ...initialState }) as UnwrapRef<T>

  // Pending filters (before apply)
  const pendingFilters = reactive<T>({ ...initialState }) as UnwrapRef<T>

  const hasActiveFilters = computed(() => {
    return Object.values(filters as Record<string, unknown>).some(
      v => v !== null && v !== '' && v !== undefined
    )
  })

  const activeFilterCount = computed(() => {
    return Object.values(filters as Record<string, unknown>).filter(
      v => v !== null && v !== '' && v !== undefined
    ).length
  })

  const updateFilter = <K extends keyof T>(key: K, value: T[K]) => {
    (pendingFilters as T)[key] = value
  }

  const applyFilters = () => {
    Object.assign(filters as Record<string, unknown>, pendingFilters as Record<string, unknown>)
    onApply?.(filters as T)
  }

  const clearFilters = () => {
    Object.keys(initialState).forEach(key => {
      (filters as T)[key as keyof T] = initialState[key as keyof T]
      ;(pendingFilters as T)[key as keyof T] = initialState[key as keyof T]
    })
    onApply?.(filters as T)
  }

  const setFiltersFromUrl = () => {
    const params = new URLSearchParams(window.location.search)
    Object.keys(initialState).forEach(key => {
      const value = params.get(key)
      if (value !== null) {
        (filters as T)[key as keyof T] = value as T[keyof T]
        ;(pendingFilters as T)[key as keyof T] = value as T[keyof T]
      }
    })
  }

  const updateUrl = () => {
    const params = new URLSearchParams()
    Object.entries(filters as Record<string, unknown>).forEach(([key, value]) => {
      if (value !== null && value !== '' && value !== undefined) {
        params.set(key, String(value))
      }
    })
    const newUrl = params.toString()
      ? `${window.location.pathname}?${params}`
      : window.location.pathname
    window.history.replaceState({}, '', newUrl)
  }

  return {
    filters,
    pendingFilters,
    hasActiveFilters,
    activeFilterCount,
    updateFilter,
    applyFilters,
    clearFilters,
    setFiltersFromUrl,
    updateUrl,
  }
}
