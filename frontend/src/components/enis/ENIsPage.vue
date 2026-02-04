<template>
  <div>
    <!-- Page Header -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 fade-in mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900 mb-2 flex items-center">
          <SignalIcon class="w-8 h-8 text-aws-orange mr-3" />
          Elastic Network Interfaces
        </h2>
        <p class="text-gray-600">Monitor all ENIs and their network configurations</p>
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6 fade-in">
      <SummaryCard
        label="Total ENIs"
        :value="summary.total_enis"
        color="blue"
        icon="network"
      />
      <SummaryCard
        label="Private IPs"
        :value="summary.total_private_ips"
        color="green"
        icon="lock"
      />
      <SummaryCard
        label="Public IPs"
        :value="summary.total_public_ips"
        color="purple"
        icon="globe"
      />
      <SummaryCard
        label="Regions"
        :value="summary.regions?.length || 0"
        color="yellow"
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
        <label class="block text-sm font-medium text-gray-700 mb-1">Status</label>
        <SearchableSelect
          v-model="pendingFilters.status"
          :options="statusOptions"
          placeholder="All Statuses"
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
        <label class="block text-sm font-medium text-gray-700 mb-1">Interface Type</label>
        <SearchableSelect
          v-model="pendingFilters.interface_type"
          :options="filterOptions.interface_types || []"
          placeholder="All Types"
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
      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">Attached</label>
        <SearchableSelect
          v-model="pendingFilters.attached"
          :options="attachedOptions"
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

    <!-- ENIs Table -->
    <DataTable
      title="ENI Details"
      :columns="columns"
      :items="enis"
      :loading="loading"
      :searchable="true"
      search-placeholder="Search ENIs..."
      :total-count="totalCount"
      :show-count="true"
      empty-message="No ENIs found. Poll an AWS account to discover network interfaces."
      empty-icon="network"
      @search="handleSearch"
    >
      <template #cell-eni="{ item }">
        <a
          :href="`/enis/${item.eni_id}/`"
          class="text-blue-600 hover:text-blue-800 hover:underline font-semibold text-sm block"
        >
          {{ truncate(item.name || item.eni_id, 20) }}
        </a>
        <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs font-mono text-gray-600 mt-1 inline-block">
          {{ truncate(item.eni_id, 18) }}
        </code>
        <small v-if="item.description" class="text-gray-500 text-xs block mt-1">
          {{ truncate(item.description, 30) }}
        </small>
      </template>

      <template #cell-status="{ item }">
        <StatusBadge :variant="item.status === 'in-use' ? 'green' : 'yellow'">
          {{ item.status }}
        </StatusBadge>
        <StatusBadge variant="gray" class="mt-1">
          {{ item.interface_type }}
        </StatusBadge>
      </template>

      <template #cell-ips="{ item }">
        <div class="space-y-1">
          <div>
            <StatusBadge variant="blue" icon="lock">
              {{ item.private_ip_address }}
            </StatusBadge>
          </div>
          <div v-if="item.public_ip_address">
            <StatusBadge variant="green" icon="globe">
              {{ item.public_ip_address }}
            </StatusBadge>
          </div>
          <div v-if="item.secondary_ips && item.secondary_ips.length > 0">
            <span class="text-xs text-gray-500">+{{ item.secondary_ips.length }} secondary</span>
          </div>
        </div>
      </template>

      <template #cell-network="{ item }">
        <div class="text-xs">
          <div class="mb-1">
            <span class="text-gray-500">VPC:</span>
            <code class="bg-gray-100 px-1.5 py-0.5 rounded font-mono ml-1">{{ item.vpc_id }}</code>
          </div>
          <div class="mb-1">
            <span class="text-gray-500">Sub:</span>
            <code class="bg-gray-100 px-1.5 py-0.5 rounded font-mono ml-1">{{ item.subnet_id }}</code>
          </div>
          <small class="text-gray-500">{{ item.availability_zone }}</small>
        </div>
      </template>

      <template #cell-attachment="{ item }">
        <template v-if="item.attached_resource_id">
          <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs font-mono block">
            {{ truncate(item.attached_resource_id, 15) }}
          </code>
          <small class="text-gray-500 text-xs">{{ item.attached_resource_type }}</small>
        </template>
        <span v-else class="text-gray-400 text-xs">Not attached</span>
      </template>

      <template #cell-security_groups="{ item }">
        <div v-if="item.security_groups && item.security_groups.length > 0" class="flex flex-wrap gap-1">
          <span
            v-for="sg in item.security_groups.slice(0, 2)"
            :key="sg.id"
            class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-800"
            :title="sg.security_group_id"
          >
            {{ truncate(sg.security_group_name, 10) }}
          </span>
          <span
            v-if="item.security_groups.length > 2"
            class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-gray-200 text-gray-700"
          >
            +{{ item.security_groups.length - 2 }}
          </span>
        </div>
        <span v-else class="text-gray-400 text-xs">-</span>
      </template>

      <template #cell-actions="{ item }">
        <a
          :href="`/enis/${item.eni_id}/`"
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
  SignalIcon,
  ExclamationTriangleIcon,
  EyeIcon,
} from '@heroicons/vue/24/outline'
import { enisApi } from '@/api/enis'
import { useFilters } from '@/composables/useFilters'
import type { ENI, ENISummary } from '@/types/enis'
import type { SelectOption, FilterOptions } from '@/types/api'
import type { Column } from '@/components/common/DataTable.vue'

import DataTable from '@/components/common/DataTable.vue'
import FilterBar from '@/components/common/FilterBar.vue'
import SearchableSelect from '@/components/common/SearchableSelect.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import SummaryCard from '@/components/common/SummaryCard.vue'
import Pagination from '@/components/common/Pagination.vue'

// State
const enis = ref<ENI[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const totalCount = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)
const searchQuery = ref('')

const summary = ref<ENISummary>({
  total_accounts: 0,
  total_vpcs: 0,
  total_subnets: 0,
  total_security_groups: 0,
  total_enis: 0,
  total_private_ips: 0,
  total_public_ips: 0,
  regions: [],
  accounts: [],
})

const filterOptions = ref<FilterOptions & { interface_types?: SelectOption[] }>({
  regions: [],
  accounts: [],
  vpcs: [],
  interface_types: [],
})

// Static options
const statusOptions: SelectOption[] = [
  { value: 'in-use', label: 'In Use' },
  { value: 'available', label: 'Available' },
]

const boolOptions: SelectOption[] = [
  { value: 'yes', label: 'Yes' },
  { value: 'no', label: 'No' },
]

const attachedOptions: SelectOption[] = [
  { value: 'yes', label: 'Attached' },
  { value: 'no', label: 'Not Attached' },
]

// Filter state
interface ENIFilterState {
  [key: string]: SelectOption | null
  region: SelectOption | null
  account: SelectOption | null
  status: SelectOption | null
  vpc: SelectOption | null
  interface_type: SelectOption | null
  has_public_ip: SelectOption | null
  attached: SelectOption | null
}

const initialFilters: ENIFilterState = {
  region: null,
  account: null,
  status: null,
  vpc: null,
  interface_type: null,
  has_public_ip: null,
  attached: null,
}

const { filters, pendingFilters, activeFilterCount, applyFilters, clearFilters } =
  useFilters<ENIFilterState>(initialFilters, fetchENIs)

// Computed
const totalPages = computed(() => Math.ceil(totalCount.value / pageSize.value))

// Table columns
const columns: Column[] = [
  { key: 'eni', label: 'ENI' },
  { key: 'status', label: 'Status', width: '120px' },
  { key: 'ips', label: 'IPs', width: '160px' },
  { key: 'network', label: 'Network', width: '180px' },
  { key: 'attachment', label: 'Attachment', width: '150px' },
  { key: 'security_groups', label: 'Security Groups' },
  { key: 'actions', label: 'Actions', width: '80px' },
]

// Fetch filter options and summary
async function fetchFilterOptions() {
  try {
    const [options, summaryData] = await Promise.all([
      enisApi.getFilterOptions(),
      enisApi.getSummary(),
    ])
    filterOptions.value = options
    summary.value = summaryData
  } catch (e: any) {
    console.error('Failed to fetch filter options:', e)
  }
}

// Fetch ENIs
async function fetchENIs() {
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
    if (filters.status) {
      apiFilters.status = String(filters.status.value)
    }
    if (filters.vpc) {
      apiFilters.vpc = String(filters.vpc.value)
    }
    if (filters.interface_type) {
      apiFilters.interface_type = String(filters.interface_type.value)
    }
    if (filters.has_public_ip) {
      apiFilters.has_public_ip = String(filters.has_public_ip.value)
    }
    if (filters.attached) {
      apiFilters.attached = String(filters.attached.value)
    }

    const response = await enisApi.list(apiFilters as any)
    enis.value = response.results
    totalCount.value = response.count
  } catch (e: any) {
    console.error('Failed to fetch ENIs:', e)
    error.value = e.response?.data?.detail || e.message || 'Failed to fetch ENIs'
  } finally {
    loading.value = false
  }
}

// Handlers
function handleSearch(query: string) {
  searchQuery.value = query
  currentPage.value = 1
  fetchENIs()
}

function handlePageChange(page: number) {
  currentPage.value = page
  fetchENIs()
}

// Utilities
function truncate(str: string | null, maxLength: number): string {
  if (!str) return ''
  return str.length > maxLength ? str.substring(0, maxLength) + '...' : str
}

// Initial load
onMounted(async () => {
  await fetchFilterOptions()
  await fetchENIs()
})
</script>
