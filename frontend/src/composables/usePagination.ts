import { ref, computed } from 'vue'

export function usePagination(itemsPerPage = 100) {
  const currentPage = ref(1)
  const totalItems = ref(0)

  const totalPages = computed(() => {
    return Math.ceil(totalItems.value / itemsPerPage)
  })

  const hasNextPage = computed(() => {
    return currentPage.value < totalPages.value
  })

  const hasPreviousPage = computed(() => {
    return currentPage.value > 1
  })

  const startIndex = computed(() => {
    return (currentPage.value - 1) * itemsPerPage + 1
  })

  const endIndex = computed(() => {
    return Math.min(currentPage.value * itemsPerPage, totalItems.value)
  })

  const setPage = (page: number) => {
    if (page >= 1 && page <= totalPages.value) {
      currentPage.value = page
    }
  }

  const nextPage = () => {
    if (hasNextPage.value) {
      currentPage.value++
    }
  }

  const previousPage = () => {
    if (hasPreviousPage.value) {
      currentPage.value--
    }
  }

  const setTotalItems = (total: number) => {
    totalItems.value = total
    // Reset to page 1 if current page exceeds total pages
    if (currentPage.value > Math.ceil(total / itemsPerPage)) {
      currentPage.value = 1
    }
  }

  const reset = () => {
    currentPage.value = 1
    totalItems.value = 0
  }

  return {
    currentPage,
    totalItems,
    totalPages,
    hasNextPage,
    hasPreviousPage,
    startIndex,
    endIndex,
    itemsPerPage,
    setPage,
    nextPage,
    previousPage,
    setTotalItems,
    reset,
  }
}
