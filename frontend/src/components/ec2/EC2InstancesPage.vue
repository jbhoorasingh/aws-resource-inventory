<template>
  <div>
    <!-- Page Header -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 fade-in mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900 mb-2 flex items-center">
          <ServerIcon class="w-8 h-8 text-aws-orange mr-3" />
          EC2 Instances
        </h2>
        <p class="text-gray-600">Monitor EC2 instances across all accounts and regions</p>
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6 fade-in">
      <SummaryCard
        label="Total Instances"
        :value="summary.total"
        color="blue"
        icon="server"
      />
      <SummaryCard
        label="Running"
        :value="summary.running"
        color="green"
        icon="play"
      />
      <SummaryCard
        label="Stopped"
        :value="summary.stopped"
        color="red"
        icon="stop"
      />
      <SummaryCard
        label="Regions"
        :value="summary.regions"
        color="purple"
        icon="globe"
      />
    </div>

    <!-- Filters -->
    <FilterBar
      :active-filter-count="activeFilterCount"
      @apply="applyFilters"
      @clear="clearFilters"
    >
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Region</label>
        <SearchableSelect
          v-model="pendingFilters.region"
          :options="filterOptions.regions"
          placeholder="All Regions"
        />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Account</label>
        <SearchableSelect
          v-model="pendingFilters.account"
          :options="filterOptions.accounts"
          placeholder="All Accounts"
        />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">State</label>
        <SearchableSelect
          v-model="pendingFilters.state"
          :options="stateOptions"
          placeholder="All States"
        />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Instance Type</label>
        <SearchableSelect
          v-model="pendingFilters.instance_type"
          :options="filterOptions.instance_types || []"
          placeholder="All Types"
        />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">VPC</label>
        <SearchableSelect
          v-model="pendingFilters.vpc"
          :options="filterOptions.vpcs || []"
          placeholder="All VPCs"
        />
      </div>
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Has Public IP</label>
        <SearchableSelect
          v-model="pendingFilters.has_public_ip"
          :options="boolOptions"
          placeholder="Any"
        />
      </div>
    </FilterBar>

    <!-- Error message -->
    <div
      v-if="error"
      class="mb-4 bg-red-50 border-l-4 border-red-500 p-4 rounded"
    >
      <div class="flex items-center">
        <ExclamationTriangleIcon class="w-5 h-5 text-red-500 mr-2" />
        <span class="text-red-700">{{ error }}</span>
      </div>
    </div>

    <!-- EC2 Instances Table -->
    <DataTable
      title="EC2 Instances"
      :columns="columns"
      :items="instances"
      :loading="loading"
      :searchable="true"
      search-placeholder="Search instances..."
      :total-count="totalCount"
      :show-count="true"
      empty-message="No EC2 instances found. Poll an AWS account to discover instances."
      empty-icon="server"
      @search="handleSearch"
    >
      <template #cell-instance="{ item }">
        <a
          :href="`/ec2-instances/${item.id}/`"
          class="text-blue-600 hover:text-blue-800 hover:underline font-semibold text-sm block"
        >
          {{ truncate(item.name || item.instance_id, 25) }}
        </a>
        <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs font-mono text-gray-600 mt-1 inline-block">
          {{ truncate(item.instance_id, 15) }}
        </code>
        <small v-if="item.platform" class="text-gray-500 text-xs block mt-1">
          {{ item.platform }}
        </small>
      </template>

      <template #cell-type_state="{ item }">
        <StatusBadge variant="purple" class="mb-1 block">
          {{ item.instance_type }}
        </StatusBadge>
        <StatusBadge :variant="getStateVariant(item.state)">
          {{ item.state }}
        </StatusBadge>
      </template>

      <template #cell-ips="{ item }">
        <div class="space-y-1">
          <div v-if="item.private_ip_address">
            <StatusBadge variant="blue" icon="lock">
              {{ item.private_ip_address }}
            </StatusBadge>
          </div>
          <div v-if="item.public_ip_address">
            <StatusBadge variant="green" icon="globe">
              {{ item.public_ip_address }}
            </StatusBadge>
          </div>
          <span v-if="!item.private_ip_address && !item.public_ip_address" class="text-gray-400 text-xs">-</span>
        </div>
      </template>

      <template #cell-network="{ item }">
        <div class="text-xs">
          <div class="mb-1">
            <span class="text-gray-500">VPC:</span>
            <code class="bg-gray-100 px-1.5 py-0.5 rounded font-mono ml-1">{{ item.vpc_id || '-' }}</code>
          </div>
          <div>
            <span class="text-gray-500">Sub:</span>
            <code class="bg-gray-100 px-1.5 py-0.5 rounded font-mono ml-1">{{ item.subnet_id || '-' }}</code>
          </div>
        </div>
      </template>

      <template #cell-region="{ item }">
        <StatusBadge variant="gray" class="mb-1 block">
          {{ item.region }}
        </StatusBadge>
        <small class="text-gray-500 text-xs">{{ truncate(item.availability_zone, 12) }}</small>
      </template>

      <template #cell-tags="{ item }">
        <div v-if="item.tags && Object.keys(item.tags).length > 0" class="flex flex-wrap gap-1">
          <span
            v-for="[key, value] in Object.entries(item.tags).slice(0, 2)"
            :key="key"
            class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 border border-gray-200"
          >
            <strong class="text-xs">{{ truncate(String(key), 8) }}:</strong>&nbsp;
            <span class="text-xs">{{ truncate(String(value), 8) }}</span>
          </span>
          <span
            v-if="Object.keys(item.tags).length > 2"
            class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-200 text-gray-700"
          >
            +{{ Object.keys(item.tags).length - 2 }} more
          </span>
        </div>
        <span v-else class="text-gray-400 text-xs">-</span>
      </template>

      <template #cell-actions="{ item }">
        <a
          :href="`/ec2-instances/${item.id}/`"
          class="text-blue-600 hover:text-blue-800 hover:bg-blue-50 px-2 py-1 rounded transition-colors text-xs flex items-center"
        >
          <EyeIcon class="w-4 h-4 mr-1" />
          View
        </a>
      </template>
    </DataTable>

    <!-- Pagination -->
    <Pagination
      v-if="totalCount > pageSize"
      :current-page="currentPage"
      :total-pages="totalPages"
      :total-items="totalCount"
      :items-per-page="pageSize"
      @page-change="handlePageChange"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  ServerIcon,
  ExclamationTriangleIcon,
  EyeIcon,
} from '@heroicons/vue/24/outline'
import { ec2Api } from '@/api/ec2'
import { useFilters } from '@/composables/useFilters'
import type { EC2Instance } from '@/types/ec2'
import type { SelectOption, FilterOptions } from '@/types/api'
import type { Column } from '@/components/common/DataTable.vue'

import DataTable from '@/components/common/DataTable.vue'
import FilterBar from '@/components/common/FilterBar.vue'
import SearchableSelect from '@/components/common/SearchableSelect.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import SummaryCard from '@/components/common/SummaryCard.vue'
import Pagination from '@/components/common/Pagination.vue'

// State
const instances = ref<EC2Instance[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const totalCount = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)
const searchQuery = ref('')

const summary = ref({
  total: 0,
  running: 0,
  stopped: 0,
  regions: 0,
})

const filterOptions = ref<FilterOptions & { instance_types?: SelectOption[] }>({
  regions: [],
  accounts: [],
  vpcs: [],
  instance_types: [],
})

// Static options
const stateOptions: SelectOption[] = [
  { value: 'running', label: 'Running' },
  { value: 'stopped', label: 'Stopped' },
  { value: 'pending', label: 'Pending' },
  { value: 'stopping', label: 'Stopping' },
  { value: 'terminated', label: 'Terminated' },
]

const boolOptions: SelectOption[] = [
  { value: 'yes', label: 'Yes' },
  { value: 'no', label: 'No' },
]

// Filter state
interface EC2FilterState {
  [key: string]: SelectOption | null
  region: SelectOption | null
  account: SelectOption | null
  state: SelectOption | null
  instance_type: SelectOption | null
  vpc: SelectOption | null
  has_public_ip: SelectOption | null
}

const initialFilters: EC2FilterState = {
  region: null,
  account: null,
  state: null,
  instance_type: null,
  vpc: null,
  has_public_ip: null,
}

const { filters, pendingFilters, activeFilterCount, applyFilters, clearFilters } =
  useFilters<EC2FilterState>(initialFilters, fetchInstances)

// Computed
const totalPages = computed(() => Math.ceil(totalCount.value / pageSize.value))

// Table columns
const columns: Column[] = [
  { key: 'instance', label: 'Instance' },
  { key: 'type_state', label: 'Type / State', width: '140px' },
  { key: 'ips', label: 'IPs', width: '160px' },
  { key: 'network', label: 'Network', width: '180px' },
  { key: 'region', label: 'Region', width: '130px' },
  { key: 'tags', label: 'Tags' },
  { key: 'actions', label: 'Actions', width: '80px' },
]

// Fetch filter options
async function fetchFilterOptions() {
  try {
    const options = await ec2Api.getFilterOptions()
    filterOptions.value = options
  } catch (e: any) {
    console.error('Failed to fetch filter options:', e)
  }
}

// Fetch instances
async function fetchInstances() {
  loading.value = true
  error.value = null
  try {
    const apiFilters: Record<string, string | number | undefined> = {
      page: currentPage.value,
    }

    if (searchQuery.value) {
      apiFilters.search = searchQuery.value
    }
    if (filters.region) {
      apiFilters.region = String(filters.region.value)
    }
    if (filters.account) {
      apiFilters.account = String(filters.account.value)
    }
    if (filters.state) {
      apiFilters.state = String(filters.state.value)
    }
    if (filters.instance_type) {
      apiFilters.instance_type = String(filters.instance_type.value)
    }
    if (filters.vpc) {
      apiFilters.vpc = String(filters.vpc.value)
    }
    if (filters.has_public_ip) {
      apiFilters.has_public_ip = String(filters.has_public_ip.value)
    }

    const response = await ec2Api.list(apiFilters as any)
    instances.value = response.results
    totalCount.value = response.count

    // Calculate summary
    let running = 0
    let stopped = 0
    const regions = new Set<string>()

    response.results.forEach((instance) => {
      if (instance.state === 'running') running++
      if (instance.state === 'stopped') stopped++
      regions.add(instance.region)
    })

    summary.value = {
      total: response.count,
      running,
      stopped,
      regions: regions.size,
    }
  } catch (e: any) {
    console.error('Failed to fetch instances:', e)
    error.value = e.response?.data?.detail || e.message || 'Failed to fetch EC2 instances'
  } finally {
    loading.value = false
  }
}

// Handlers
function handleSearch(query: string) {
  searchQuery.value = query
  currentPage.value = 1
  fetchInstances()
}

function handlePageChange(page: number) {
  currentPage.value = page
  fetchInstances()
}

function getStateVariant(state: string): 'green' | 'red' | 'yellow' | 'gray' {
  switch (state) {
    case 'running':
      return 'green'
    case 'stopped':
      return 'red'
    case 'stopping':
    case 'pending':
    case 'starting':
      return 'yellow'
    default:
      return 'gray'
  }
}

// Utilities
function truncate(str: string | null, maxLength: number): string {
  if (!str) return ''
  return str.length > maxLength ? str.substring(0, maxLength) + '...' : str
}

// Initial load
onMounted(async () => {
  await fetchFilterOptions()
  await fetchInstances()
})
</script>
