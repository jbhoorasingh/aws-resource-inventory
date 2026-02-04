<template>
  <div>
    <!-- Page Header -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 fade-in mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900 mb-2 flex items-center">
          <CloudIcon class="w-8 h-8 text-aws-orange mr-3" />
          VPCs & Subnets
        </h2>
        <p class="text-gray-600">Hierarchical view of VPCs, Subnets, and all associated resources</p>
      </div>
      <div class="flex gap-2">
        <button
          @click="expandAll"
          class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <PlusCircleIcon class="w-5 h-5" />
          Expand All
        </button>
        <button
          @click="collapseAll"
          class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <MinusCircleIcon class="w-5 h-5" />
          Collapse All
        </button>
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6 fade-in">
      <SummaryCard
        label="VPCs"
        :value="summary.vpcs"
        color="blue"
        icon="cloud"
      />
      <SummaryCard
        label="Subnets"
        :value="summary.subnets"
        color="green"
        icon="layer"
      />
      <SummaryCard
        label="ENIs"
        :value="summary.enis"
        color="purple"
        icon="network"
      />
      <SummaryCard
        label="EC2"
        :value="summary.ec2"
        color="yellow"
        icon="server"
      />
      <SummaryCard
        label="SGs"
        :value="summary.sgs"
        color="red"
        icon="shield"
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

    <!-- VPC Tree -->
    <div class="bg-white shadow-lg rounded-lg">
      <div class="bg-gray-50 border-b border-gray-200 px-6 py-4">
        <h5 class="text-lg font-semibold text-gray-900">VPC Hierarchy</h5>
      </div>
      <div class="p-6">
        <!-- Loading state -->
        <div v-if="loading" class="flex flex-col items-center justify-center py-12">
          <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-aws-orange mb-4"></div>
          <p class="text-gray-600">Loading VPCs...</p>
        </div>

        <!-- VPC List -->
        <div v-else-if="vpcs.length > 0" class="space-y-6">
          <VPCTreeItem
            v-for="vpc in vpcs"
            :key="vpc.id"
            :vpc="vpc"
            :expanded="expandedVpcs.has(vpc.id)"
            @toggle="toggleVpc"
          />
        </div>

        <!-- Empty state -->
        <div v-else class="text-center py-12">
          <CloudIcon class="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h4 class="text-xl font-semibold text-gray-600 mb-3">No VPCs found</h4>
          <p class="text-gray-500 mb-6">Poll an AWS account to discover VPCs and their resources.</p>
          <a
            href="/accounts/"
            class="bg-aws-orange hover:bg-orange-600 text-white px-6 py-3 rounded-lg transition-colors inline-flex items-center gap-2"
          >
            <UserGroupIcon class="w-5 h-5" />
            Go to Accounts
          </a>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  CloudIcon,
  PlusCircleIcon,
  MinusCircleIcon,
  ExclamationTriangleIcon,
  UserGroupIcon,
} from '@heroicons/vue/24/outline'
import { vpcsApi } from '@/api/vpcs'
import { useFilters } from '@/composables/useFilters'
import type { VPCWithResources } from '@/types/vpcs'
import type { SelectOption, FilterOptions } from '@/types/api'

import FilterBar from '@/components/common/FilterBar.vue'
import SearchableSelect from '@/components/common/SearchableSelect.vue'
import SummaryCard from '@/components/common/SummaryCard.vue'
import VPCTreeItem from './VPCTreeItem.vue'

// State
const vpcs = ref<VPCWithResources[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const expandedVpcs = ref<Set<number>>(new Set())

const summary = ref({
  vpcs: 0,
  subnets: 0,
  enis: 0,
  ec2: 0,
  sgs: 0,
})

const filterOptions = ref<FilterOptions>({
  regions: [],
  accounts: [],
  vpcs: [],
})

// Static options
const stateOptions: SelectOption[] = [
  { value: 'available', label: 'Available' },
  { value: 'pending', label: 'Pending' },
]

// Filter state
interface VPCFilterState {
  [key: string]: SelectOption | null
  region: SelectOption | null
  account: SelectOption | null
  state: SelectOption | null
}

const initialFilters: VPCFilterState = {
  region: null,
  account: null,
  state: null,
}

const { filters, pendingFilters, activeFilterCount, applyFilters, clearFilters } =
  useFilters<VPCFilterState>(initialFilters, fetchVPCs)

// Fetch filter options
async function fetchFilterOptions() {
  try {
    const options = await vpcsApi.getFilterOptions()
    filterOptions.value = options
  } catch (e: any) {
    console.error('Failed to fetch filter options:', e)
  }
}

// Fetch VPCs with tree structure
async function fetchVPCs() {
  loading.value = true
  error.value = null
  try {
    const apiFilters: Record<string, string | undefined> = {}

    if (filters.region) {
      apiFilters.region = String(filters.region.value)
    }
    if (filters.account) {
      apiFilters.account = String(filters.account.value)
    }
    if (filters.state) {
      apiFilters.state = String(filters.state.value)
    }

    const data = await vpcsApi.getTree(apiFilters as any)
    vpcs.value = data

    // Calculate summary
    let totalSubnets = 0
    let totalENIs = 0
    let totalEC2 = 0
    let totalSGs = 0

    data.forEach((vpc) => {
      totalSubnets += vpc.resource_counts?.subnet_count || 0
      totalENIs += vpc.resource_counts?.eni_count || 0
      totalEC2 += vpc.resource_counts?.ec2_instance_count || 0
      totalSGs += vpc.resource_counts?.security_group_count || 0
    })

    summary.value = {
      vpcs: data.length,
      subnets: totalSubnets,
      enis: totalENIs,
      ec2: totalEC2,
      sgs: totalSGs,
    }
  } catch (e: any) {
    console.error('Failed to fetch VPCs:', e)
    error.value = e.response?.data?.detail || e.message || 'Failed to fetch VPCs'
  } finally {
    loading.value = false
  }
}

// Tree controls
function toggleVpc(vpcId: number) {
  if (expandedVpcs.value.has(vpcId)) {
    expandedVpcs.value.delete(vpcId)
  } else {
    expandedVpcs.value.add(vpcId)
  }
  expandedVpcs.value = new Set(expandedVpcs.value) // Trigger reactivity
}

function expandAll() {
  expandedVpcs.value = new Set(vpcs.value.map((v) => v.id))
}

function collapseAll() {
  expandedVpcs.value = new Set()
}

// Initial load
onMounted(async () => {
  await fetchFilterOptions()
  await fetchVPCs()
})
</script>
