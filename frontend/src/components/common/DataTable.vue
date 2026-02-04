<template>
  <div class="bg-white shadow-lg rounded-lg">
    <!-- Header with search -->
    <div
      class="bg-gray-50 border-b border-gray-200 px-6 py-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4"
    >
      <h5 class="text-lg font-semibold text-gray-900 flex items-center">
        <slot name="title">{{ title }}</slot>
        <span
          v-if="showCount && totalCount !== filteredCount"
          class="ml-2 px-2 py-0.5 bg-aws-orange text-white text-xs rounded-full"
        >
          {{ filteredCount }} of {{ totalCount }}
        </span>
        <span
          v-else-if="showCount"
          class="ml-2 px-2 py-0.5 bg-gray-200 text-gray-700 text-xs rounded-full"
        >
          {{ totalCount }}
        </span>
      </h5>

      <div class="flex items-center gap-4 w-full sm:w-auto">
        <div v-if="searchable" class="relative flex-1 sm:w-72">
          <input
            type="text"
            v-model="searchQuery"
            class="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-lg
                   focus:ring-2 focus:ring-aws-orange focus:border-aws-orange text-sm"
            :placeholder="searchPlaceholder"
            @input="onSearchInput"
          />
          <div
            class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none"
          >
            <MagnifyingGlassIcon class="h-5 w-5 text-gray-400" />
          </div>
        </div>
        <slot name="actions"></slot>
      </div>
    </div>

    <!-- Table -->
    <div class="overflow-x-auto">
      <table class="w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th
              v-for="column in columns"
              :key="column.key"
              class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
              :class="[column.headerClass, { 'cursor-pointer hover:bg-gray-100': column.sortable }]"
              :style="column.width ? { width: column.width } : {}"
              @click="column.sortable && toggleSort(column.key)"
            >
              <span class="flex items-center gap-1">
                {{ column.label }}
                <template v-if="column.sortable">
                  <ChevronUpIcon
                    v-if="sortKey === column.key && sortDirection === 'asc'"
                    class="h-4 w-4"
                  />
                  <ChevronDownIcon
                    v-else-if="sortKey === column.key && sortDirection === 'desc'"
                    class="h-4 w-4"
                  />
                  <ChevronUpDownIcon v-else class="h-4 w-4 text-gray-300" />
                </template>
              </span>
            </th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
          <!-- Loading state -->
          <template v-if="loading">
            <tr>
              <td :colspan="columns.length" class="px-6 py-12 text-center">
                <LoadingSpinner />
                <p class="mt-2 text-gray-500">Loading...</p>
              </td>
            </tr>
          </template>

          <!-- Empty state -->
          <template v-else-if="items.length === 0">
            <tr>
              <td :colspan="columns.length" class="px-6 py-12">
                <slot name="empty">
                  <EmptyState :message="emptyMessage" :icon="emptyIcon" />
                </slot>
              </td>
            </tr>
          </template>

          <!-- Data rows -->
          <template v-else>
            <tr
              v-for="item in items"
              :key="getRowKey(item)"
              class="hover:bg-gray-50 transition-colors duration-150"
              :class="{ 'cursor-pointer': clickable }"
              @click="clickable && $emit('row-click', item)"
            >
              <td
                v-for="column in columns"
                :key="column.key"
                class="px-3 py-3 text-sm"
                :class="column.cellClass"
              >
                <slot
                  :name="`cell-${column.key}`"
                  :item="item"
                  :value="getItemValue(item, column.key)"
                >
                  {{ getItemValue(item, column.key) }}
                </slot>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <!-- Pagination -->
    <div
      v-if="paginated && totalPages > 1"
      class="bg-gray-50 border-t border-gray-200 px-6 py-3"
    >
      <Pagination
        :current-page="currentPage"
        :total-pages="totalPages"
        :total-items="totalCount"
        :items-per-page="itemsPerPage"
        @page-change="$emit('page-change', $event)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import {
  MagnifyingGlassIcon,
  ChevronUpIcon,
  ChevronDownIcon,
  ChevronUpDownIcon,
} from '@heroicons/vue/20/solid'
import LoadingSpinner from './LoadingSpinner.vue'
import EmptyState, { type EmptyStateIcon } from './EmptyState.vue'
import Pagination from './Pagination.vue'

export interface Column {
  key: string
  label: string
  sortable?: boolean
  headerClass?: string
  cellClass?: string
  width?: string
}

const props = withDefaults(
  defineProps<{
    title?: string
    columns: Column[]
    items: any[]
    loading?: boolean
    searchable?: boolean
    searchPlaceholder?: string
    emptyMessage?: string
    emptyIcon?: EmptyStateIcon
    paginated?: boolean
    currentPage?: number
    totalPages?: number
    totalCount?: number
    filteredCount?: number
    itemsPerPage?: number
    rowKey?: string
    clickable?: boolean
    showCount?: boolean
  }>(),
  {
    title: '',
    loading: false,
    searchable: true,
    searchPlaceholder: 'Search...',
    emptyMessage: 'No data found',
    emptyIcon: 'inbox',
    paginated: false,
    currentPage: 1,
    totalPages: 1,
    totalCount: 0,
    itemsPerPage: 100,
    rowKey: 'id',
    clickable: false,
    showCount: true,
  }
)

const emit = defineEmits<{
  (e: 'search', query: string): void
  (e: 'sort', key: string, direction: 'asc' | 'desc'): void
  (e: 'page-change', page: number): void
  (e: 'row-click', item: unknown): void
}>()

const searchQuery = ref('')
const sortKey = ref<string | null>(null)
const sortDirection = ref<'asc' | 'desc'>('asc')

const filteredCount = computed(() => props.filteredCount ?? props.items.length)

const getRowKey = (item: unknown): string | number => {
  const record = item as Record<string, unknown>
  return record[props.rowKey] as string | number
}

const getItemValue = (item: unknown, key: string): unknown => {
  const record = item as Record<string, unknown>
  const keys = key.split('.')
  return keys.reduce((obj: unknown, k: string) => {
    if (obj && typeof obj === 'object') {
      return (obj as Record<string, unknown>)[k]
    }
    return undefined
  }, record)
}

const onSearchInput = () => {
  emit('search', searchQuery.value)
}

const toggleSort = (key: string) => {
  if (sortKey.value === key) {
    sortDirection.value = sortDirection.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDirection.value = 'asc'
  }
  emit('sort', key, sortDirection.value)
}
</script>
