<template>
  <div>
    <!-- Page Header -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 fade-in mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900 mb-2 flex items-center">
          <ShieldCheckIcon class="w-8 h-8 text-aws-orange mr-3" />
          Security Groups
        </h2>
        <p class="text-gray-600">Manage and review security group rules and policies</p>
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6 fade-in">
      <SummaryCard
        label="Total Groups"
        :value="summary.total_groups"
        color="blue"
        icon="shield"
      />
      <SummaryCard
        label="Ingress Rules"
        :value="summary.total_ingress"
        color="green"
        icon="arrow-down"
      />
      <SummaryCard
        label="Egress Rules"
        :value="summary.total_egress"
        color="purple"
        icon="arrow-up"
      />
      <SummaryCard
        label="Regions"
        :value="summary.total_regions"
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
        <label class="block text-sm font-medium text-gray-700 mb-1">VPC</label>
        <SearchableSelect
          v-model="pendingFilters.vpc"
          :options="filterOptions.vpcs || []"
          placeholder="All VPCs"
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

    <!-- Security Groups Table -->
    <DataTable
      title="Security Groups"
      :columns="columns"
      :items="securityGroups"
      :loading="loading"
      :searchable="true"
      search-placeholder="Search security groups..."
      :total-count="totalCount"
      :show-count="true"
      empty-message="No security groups found. Poll an AWS account to discover security groups."
      empty-icon="shield"
      @search="handleSearch"
    >
      <template #cell-security_group="{ item }">
        <a
          :href="`/security-groups/${item.sg_id}/`"
          class="text-blue-600 hover:text-blue-800 hover:underline font-semibold text-sm block"
        >
          {{ truncate(item.name, 25) }}
        </a>
        <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs font-mono text-gray-600 mt-1 inline-block">
          {{ item.sg_id }}
        </code>
        <small v-if="item.description" class="text-gray-500 text-xs mt-1 block">
          {{ truncate(item.description, 30) }}
        </small>
      </template>

      <template #cell-vpc="{ item }">
        <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs font-mono block mb-1">
          {{ item.vpc_id }}
        </code>
      </template>

      <template #cell-rules="{ item }">
        <div class="flex flex-wrap gap-1">
          <StatusBadge variant="green">
            {{ item.ingress_rules?.length || 0 }} In
          </StatusBadge>
          <StatusBadge variant="purple">
            {{ item.egress_rules?.length || 0 }} Out
          </StatusBadge>
        </div>
      </template>

      <template #cell-owner="{ item }">
        <code class="bg-gray-100 px-1.5 py-0.5 rounded text-xs font-mono">
          {{ item.vpc_owner_account }}
        </code>
      </template>

      <template #cell-region="{ item }">
        <StatusBadge variant="gray">
          {{ getRegionFromVpc(item) }}
        </StatusBadge>
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
          :href="`/security-groups/${item.sg_id}/`"
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
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  EyeIcon,
} from '@heroicons/vue/24/outline'
import { securityGroupsApi } from '@/api/securityGroups'
import { useFilters } from '@/composables/useFilters'
import type { SecurityGroup } from '@/types/securityGroups'
import type { SelectOption, FilterOptions } from '@/types/api'
import type { Column } from '@/components/common/DataTable.vue'

import DataTable from '@/components/common/DataTable.vue'
import FilterBar from '@/components/common/FilterBar.vue'
import SearchableSelect from '@/components/common/SearchableSelect.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import SummaryCard from '@/components/common/SummaryCard.vue'
import Pagination from '@/components/common/Pagination.vue'

// State
const securityGroups = ref<SecurityGroup[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const totalCount = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)
const searchQuery = ref('')

const summary = ref({
  total_groups: 0,
  total_ingress: 0,
  total_egress: 0,
  total_regions: 0,
})

const filterOptions = ref<FilterOptions>({
  regions: [],
  accounts: [],
  vpcs: [],
})

// Region map - we need to get region from somewhere
const vpcRegionMap = ref<Map<string, string>>(new Map())

// Filter state
interface SGFilterState {
  [key: string]: SelectOption | null
  region: SelectOption | null
  account: SelectOption | null
  vpc: SelectOption | null
}

const initialFilters: SGFilterState = {
  region: null,
  account: null,
  vpc: null,
}

const { filters, pendingFilters, activeFilterCount, applyFilters, clearFilters } =
  useFilters<SGFilterState>(initialFilters, fetchSecurityGroups)

// Computed
const totalPages = computed(() => Math.ceil(totalCount.value / pageSize.value))

// Table columns
const columns: Column[] = [
  { key: 'security_group', label: 'Security Group' },
  { key: 'vpc', label: 'VPC', width: '140px' },
  { key: 'rules', label: 'Rules', width: '120px' },
  { key: 'owner', label: 'Owner', width: '140px' },
  { key: 'region', label: 'Region', width: '120px' },
  { key: 'tags', label: 'Tags' },
  { key: 'actions', label: 'Actions', width: '80px' },
]

// Fetch filter options
async function fetchFilterOptions() {
  try {
    const options = await securityGroupsApi.getFilterOptions()
    filterOptions.value = options
  } catch (e: any) {
    console.error('Failed to fetch filter options:', e)
  }
}

// Fetch security groups
async function fetchSecurityGroups() {
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
    if (filters.vpc) {
      apiFilters.vpc = String(filters.vpc.value)
    }

    const response = await securityGroupsApi.list(apiFilters as any)
    securityGroups.value = response.results
    totalCount.value = response.count

    // Calculate summary
    let totalIngress = 0
    let totalEgress = 0
    const regions = new Set<string>()

    response.results.forEach((sg) => {
      totalIngress += sg.ingress_rules?.length || 0
      totalEgress += sg.egress_rules?.length || 0
    })

    // Get unique regions from filter options
    filterOptions.value.regions?.forEach((r: SelectOption) => {
      if (r.value) regions.add(String(r.value))
    })

    summary.value = {
      total_groups: response.count,
      total_ingress: totalIngress,
      total_egress: totalEgress,
      total_regions: regions.size,
    }
  } catch (e: any) {
    console.error('Failed to fetch security groups:', e)
    error.value = e.response?.data?.detail || e.message || 'Failed to fetch security groups'
  } finally {
    loading.value = false
  }
}

// Handlers
function handleSearch(query: string) {
  searchQuery.value = query
  currentPage.value = 1
  fetchSecurityGroups()
}

function handlePageChange(page: number) {
  currentPage.value = page
  fetchSecurityGroups()
}

function getRegionFromVpc(sg: SecurityGroup): string {
  // VPC ID doesn't contain region, we'd need this from the API
  // For now, return a placeholder or get from filter options
  return vpcRegionMap.value.get(sg.vpc_id) || '-'
}

// Utilities
function truncate(str: string | null, maxLength: number): string {
  if (!str) return ''
  return str.length > maxLength ? str.substring(0, maxLength) + '...' : str
}

// Initial load
onMounted(async () => {
  await fetchFilterOptions()
  await fetchSecurityGroups()
})
</script>
