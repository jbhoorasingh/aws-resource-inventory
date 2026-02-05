<template>
  <div class="flex items-center justify-between">
    <div class="flex-1 flex justify-between sm:hidden">
      <button
        :disabled="!hasPrevious"
        @click="$emit('page-change', currentPage - 1)"
        class="relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Previous
      </button>
      <button
        :disabled="!hasNext"
        @click="$emit('page-change', currentPage + 1)"
        class="ml-3 relative inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        Next
      </button>
    </div>
    <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
      <div>
        <p class="text-sm text-gray-700">
          Showing
          <span class="font-medium">{{ startIndex }}</span>
          to
          <span class="font-medium">{{ endIndex }}</span>
          of
          <span class="font-medium">{{ totalItems }}</span>
          results
        </p>
      </div>
      <div>
        <nav
          class="relative z-0 inline-flex rounded-md shadow-sm -space-x-px"
          aria-label="Pagination"
        >
          <button
            :disabled="!hasPrevious"
            @click="$emit('page-change', currentPage - 1)"
            class="relative inline-flex items-center px-2 py-2 rounded-l-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span class="sr-only">Previous</span>
            <ChevronLeftIcon class="h-5 w-5" aria-hidden="true" />
          </button>

          <!-- Page numbers -->
          <template v-for="page in visiblePages" :key="page">
            <span
              v-if="page === '...'"
              class="relative inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-sm font-medium text-gray-700"
            >
              ...
            </span>
            <button
              v-else
              @click="$emit('page-change', page as number)"
              :class="[
                page === currentPage
                  ? 'z-10 bg-aws-orange border-aws-orange text-white'
                  : 'bg-white border-gray-300 text-gray-500 hover:bg-gray-50',
                'relative inline-flex items-center px-4 py-2 border text-sm font-medium',
              ]"
            >
              {{ page }}
            </button>
          </template>

          <button
            :disabled="!hasNext"
            @click="$emit('page-change', currentPage + 1)"
            class="relative inline-flex items-center px-2 py-2 rounded-r-md border border-gray-300 bg-white text-sm font-medium text-gray-500 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span class="sr-only">Next</span>
            <ChevronRightIcon class="h-5 w-5" aria-hidden="true" />
          </button>
        </nav>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ChevronLeftIcon, ChevronRightIcon } from '@heroicons/vue/20/solid'

const props = defineProps<{
  currentPage: number
  totalPages: number
  totalItems: number
  itemsPerPage: number
}>()

defineEmits<{
  (e: 'page-change', page: number): void
}>()

const hasPrevious = computed(() => props.currentPage > 1)
const hasNext = computed(() => props.currentPage < props.totalPages)

const startIndex = computed(() => {
  if (props.totalItems === 0) return 0
  return (props.currentPage - 1) * props.itemsPerPage + 1
})

const endIndex = computed(() => {
  return Math.min(props.currentPage * props.itemsPerPage, props.totalItems)
})

const visiblePages = computed(() => {
  const pages: (number | string)[] = []
  const total = props.totalPages
  const current = props.currentPage

  if (total <= 7) {
    // Show all pages if 7 or fewer
    for (let i = 1; i <= total; i++) {
      pages.push(i)
    }
  } else {
    // Always show first page
    pages.push(1)

    if (current > 3) {
      pages.push('...')
    }

    // Show pages around current
    const start = Math.max(2, current - 1)
    const end = Math.min(total - 1, current + 1)

    for (let i = start; i <= end; i++) {
      pages.push(i)
    }

    if (current < total - 2) {
      pages.push('...')
    }

    // Always show last page
    pages.push(total)
  }

  return pages
})
</script>
