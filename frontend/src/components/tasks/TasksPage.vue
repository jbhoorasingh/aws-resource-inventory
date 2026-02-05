<template>
  <div>
    <!-- Page Header -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 fade-in mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900 mb-2 flex items-center">
          <ClipboardDocumentListIcon class="w-8 h-8 text-aws-orange mr-3" />
          Discovery Tasks
        </h2>
        <p class="text-gray-600">Monitor and track AWS resource discovery operations</p>
      </div>
      <a
        href="/accounts/"
        class="bg-aws-orange hover:bg-orange-600 text-white font-medium py-2 px-4 rounded-lg
               transition-colors duration-200 flex items-center"
      >
        <PlusIcon class="w-5 h-5 mr-2" />
        New Discovery
      </a>
    </div>

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6 fade-in">
      <SummaryCard
        label="Total Tasks"
        :value="summary.total_tasks"
        color="gray"
        icon="clipboard"
      />
      <SummaryCard
        label="Pending"
        :value="summary.pending"
        color="yellow"
        icon="clock"
      />
      <SummaryCard
        label="Running"
        :value="summary.running"
        color="blue"
        icon="play"
      />
      <SummaryCard
        label="Completed"
        :value="summary.success"
        color="green"
        icon="check"
      />
      <SummaryCard
        label="Failed"
        :value="summary.failed"
        color="red"
        icon="x"
      />
    </div>

    <!-- Filters -->
    <FilterBar
      :active-filter-count="activeFilterCount"
      @apply="applyFilters"
      @clear="clearFilters"
    >
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Status</label>
        <SearchableSelect
          v-model="pendingFilters.status"
          :options="statusOptions"
          placeholder="All Statuses"
        />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Type</label>
        <SearchableSelect
          v-model="pendingFilters.task_type"
          :options="typeOptions"
          placeholder="All Types"
        />
      </div>
    </FilterBar>

    <!-- Error message -->
    <div
      v-if="error"
      class="mb-4 bg-red-50 border-l-4 border-red-500 p-4 rounded"
    >
      <div class="flex items-center">
        <svg class="w-5 h-5 text-red-500 mr-2" fill="currentColor" viewBox="0 0 20 20">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"/>
        </svg>
        <span class="text-red-700">{{ error }}</span>
      </div>
    </div>

    <!-- Auto-refresh control -->
    <div class="mb-4 flex items-center justify-between">
      <div v-if="isPolling && !autoRefreshDisabled" class="flex items-center text-sm text-blue-600">
        <ArrowPathIcon class="w-4 h-4 mr-2 animate-spin" />
        Auto-refreshing every 5 seconds...
      </div>
      <div v-else class="text-sm text-gray-500">
        {{ autoRefreshDisabled ? 'Auto-refresh disabled' : 'Auto-refresh paused (no active tasks)' }}
      </div>
      <button
        @click="toggleAutoRefresh"
        :class="[
          'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors flex items-center gap-2',
          autoRefreshDisabled
            ? 'bg-green-100 text-green-700 hover:bg-green-200'
            : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
        ]"
      >
        <ArrowPathIcon v-if="!autoRefreshDisabled" class="w-4 h-4" />
        <PauseIcon v-else class="w-4 h-4" />
        {{ autoRefreshDisabled ? 'Enable Auto-refresh' : 'Disable Auto-refresh' }}
      </button>
    </div>

    <!-- Tasks Table -->
    <DataTable
      title="Discovery Tasks"
      :columns="columns"
      :items="tasks"
      :loading="loading"
      :searchable="false"
      :total-count="tasks.length"
      :show-count="true"
      empty-message="No discovery tasks found"
      empty-icon="clipboard"
    >
      <template #cell-task_type="{ item }">
        <StatusBadge
          :variant="item.task_type === 'bulk' ? 'purple' : 'blue'"
          :icon="item.task_type === 'bulk' ? 'server' : 'refresh'"
        >
          {{ item.task_type === 'bulk' ? 'Bulk' : 'Single' }}
        </StatusBadge>
      </template>

      <template #cell-account="{ item }">
        <template v-if="item.account_id">
          <code class="bg-gray-100 px-2 py-0.5 rounded text-xs font-mono">
            {{ item.account_id }}
          </code>
          <div v-if="item.account_name" class="text-xs text-gray-500 mt-1">
            {{ item.account_name }}
          </div>
        </template>
        <span v-else class="text-gray-500 text-sm">
          {{ item.total_accounts }} accounts
        </span>
      </template>

      <template #cell-status="{ item }">
        <TaskStatusBadge :status="item.status" />
      </template>

      <template #cell-progress="{ item }">
        <TaskProgress v-if="item.task_type === 'bulk'" :task="item" />
        <span v-else class="text-gray-400">-</span>
      </template>

      <template #cell-started_at="{ item }">
        <span v-if="item.started_at" class="text-sm text-gray-600">
          {{ formatTimeAgo(item.started_at) }}
        </span>
        <span v-else class="text-gray-400">Not started</span>
      </template>

      <template #cell-duration="{ item }">
        <span v-if="item.duration" class="text-sm text-gray-600">
          {{ formatDuration(item.duration) }}
        </span>
        <span v-else class="text-gray-400">-</span>
      </template>

      <template #cell-actions="{ item }">
        <a
          :href="`/tasks/${item.id}/`"
          class="text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center"
        >
          <EyeIcon class="w-4 h-4 mr-1" />
          View
        </a>
      </template>
    </DataTable>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  ClipboardDocumentListIcon,
  PlusIcon,
  EyeIcon,
  ArrowPathIcon,
  PauseIcon,
} from '@heroicons/vue/24/outline'
import { tasksApi } from '@/api/tasks'
import { useFilters } from '@/composables/useFilters'
import { useConditionalPolling } from '@/composables/usePolling'
import type { DiscoveryTask, TaskSummary } from '@/types/tasks'
import type { SelectOption } from '@/types/api'

import DataTable, { type Column } from '@/components/common/DataTable.vue'
import FilterBar from '@/components/common/FilterBar.vue'
import SearchableSelect from '@/components/common/SearchableSelect.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import SummaryCard from '@/components/common/SummaryCard.vue'
import TaskStatusBadge from './TaskStatusBadge.vue'
import TaskProgress from './TaskProgress.vue'

// State
const tasks = ref<DiscoveryTask[]>([])
const summary = ref<TaskSummary>({
  total_tasks: 0,
  pending: 0,
  running: 0,
  success: 0,
  failed: 0,
  cancelled: 0,
})
const loading = ref(false)
const autoRefreshDisabled = ref(false)

// Filter state
interface TaskFilterState {
  [key: string]: SelectOption | null
  status: SelectOption | null
  task_type: SelectOption | null
}

const initialFilters: TaskFilterState = {
  status: null,
  task_type: null,
}

const { filters, pendingFilters, activeFilterCount, applyFilters, clearFilters } =
  useFilters<TaskFilterState>(initialFilters, fetchTasks)

// Filter options
const statusOptions: SelectOption[] = [
  { value: 'pending', label: 'Pending' },
  { value: 'running', label: 'Running' },
  { value: 'success', label: 'Success' },
  { value: 'failed', label: 'Failed' },
  { value: 'cancelled', label: 'Cancelled' },
]

const typeOptions: SelectOption[] = [
  { value: 'single', label: 'Single Account' },
  { value: 'bulk', label: 'Bulk Discovery' },
]

// Table columns
const columns: Column[] = [
  { key: 'task_type', label: 'Type', width: '100px' },
  { key: 'account', label: 'Account' },
  { key: 'status', label: 'Status', width: '120px' },
  { key: 'progress', label: 'Progress', width: '150px' },
  { key: 'started_at', label: 'Started', width: '120px' },
  { key: 'duration', label: 'Duration', width: '100px' },
  { key: 'actions', label: 'Actions', width: '80px' },
]

// Error state
const error = ref<string | null>(null)

// Fetch data
async function fetchTasks() {
  loading.value = true
  error.value = null
  try {
    const apiFilters: Record<string, string | undefined> = {}
    if (filters.status) {
      apiFilters.status = String(filters.status.value)
    }
    if (filters.task_type) {
      apiFilters.task_type = String(filters.task_type.value)
    }

    console.log('Fetching tasks with filters:', apiFilters)

    const [tasksResponse, summaryResponse] = await Promise.all([
      tasksApi.list(apiFilters),
      tasksApi.getSummary(),
    ])

    console.log('Tasks response:', tasksResponse)
    console.log('Summary response:', summaryResponse)

    tasks.value = tasksResponse.results
    summary.value = summaryResponse
  } catch (e: any) {
    console.error('Failed to fetch tasks:', e)
    error.value = e.response?.data?.detail || e.message || 'Failed to fetch tasks'
  } finally {
    loading.value = false
  }
}

// Polling - refresh every 5 seconds if there are pending/running tasks and auto-refresh is enabled
const shouldPoll = computed(
  () => !autoRefreshDisabled.value && (summary.value.pending > 0 || summary.value.running > 0)
)

const { isPolling } = useConditionalPolling(fetchTasks, shouldPoll, 5000)

// Toggle auto-refresh
function toggleAutoRefresh() {
  autoRefreshDisabled.value = !autoRefreshDisabled.value
}

// Utilities
function formatTimeAgo(date: string): string {
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  return `${minutes}m ${remainingSeconds.toFixed(0)}s`
}

// Initial load
onMounted(() => {
  fetchTasks()
})
</script>
