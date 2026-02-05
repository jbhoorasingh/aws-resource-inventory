<template>
  <div>
    <!-- Page Header -->
    <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 fade-in mb-8">
      <div>
        <h2 class="text-3xl font-bold text-gray-900 mb-2 flex items-center">
          <UserGroupIcon class="w-8 h-8 text-aws-orange mr-3" />
          AWS Accounts
        </h2>
        <p class="text-gray-600">Manage and monitor your AWS accounts across regions</p>
      </div>
      <div v-if="canPoll" class="flex gap-2 flex-wrap">
        <a
          href="/accounts/add/"
          class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <PlusIcon class="w-5 h-5" />
          Add Account
        </a>
        <button
          @click="handleRepollAll"
          :disabled="repollAllLoading"
          class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50"
        >
          <ArrowPathIcon v-if="repollAllLoading" class="w-5 h-5 animate-spin" />
          <ServerIcon v-else class="w-5 h-5" />
          Re-poll All (Instance Role)
        </button>
        <button
          @click="showPollModal = true"
          class="bg-aws-orange hover:bg-orange-600 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <ArrowPathIcon class="w-5 h-5" />
          Poll with Credentials
        </button>
        <button
          @click="showBulkPollModal = true"
          class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <ServerStackIcon class="w-5 h-5" />
          Bulk Poll
        </button>
      </div>
      <div v-else class="text-sm text-gray-500 bg-gray-50 px-4 py-2 rounded-lg border border-gray-200">
        <InformationCircleIcon class="w-4 h-4 inline mr-1" />
        Read-only access
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6 fade-in">
      <SummaryCard
        label="Total Accounts"
        :value="accounts.length"
        color="gray"
        icon="users"
      />
      <SummaryCard
        label="Active"
        :value="activeCount"
        color="green"
        icon="check"
      />
      <SummaryCard
        label="Instance Role"
        :value="instanceRoleCount"
        color="purple"
        icon="server"
      />
      <SummaryCard
        label="Total ENIs"
        :value="totalENIs"
        color="blue"
        icon="network"
      />
    </div>

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

    <!-- Success message -->
    <div
      v-if="successMessage"
      class="mb-4 bg-green-50 border-l-4 border-green-500 p-4 rounded"
    >
      <div class="flex items-center">
        <CheckCircleIcon class="w-5 h-5 text-green-500 mr-2" />
        <span class="text-green-700">{{ successMessage }}</span>
      </div>
    </div>

    <!-- Accounts Table -->
    <DataTable
      title="Account Overview"
      :columns="columns"
      :items="accounts"
      :loading="loading"
      :searchable="true"
      search-placeholder="Search accounts..."
      :total-count="totalCount"
      :show-count="true"
      empty-message="No accounts yet. Get started by polling your AWS accounts to discover and track resources."
      empty-icon="cloud"
      @search="handleSearch"
    >
      <template #cell-account="{ item }">
        <div class="flex flex-col">
          <code class="bg-gray-100 px-2 py-0.5 rounded text-xs font-mono">{{ item.account_id }}</code>
          <span v-if="item.account_name" class="text-gray-900 text-sm mt-1">{{ item.account_name }}</span>
          <span v-else class="text-gray-400 text-xs mt-1">No name</span>
        </div>
      </template>

      <template #cell-status="{ item }">
        <StatusBadge
          :variant="item.is_active ? 'green' : 'gray'"
        >
          {{ item.is_active ? 'Active' : 'Inactive' }}
        </StatusBadge>
      </template>

      <template #cell-auth_method="{ item }">
        <div class="flex items-center gap-1">
          <StatusBadge
            :variant="item.auth_method === 'instance_role' ? 'purple' : 'blue'"
            :icon="item.auth_method === 'instance_role' ? 'server' : 'key'"
          >
            {{ item.auth_method === 'instance_role' ? 'Instance Role' : 'Credentials' }}
          </StatusBadge>
          <span
            v-if="item.can_repoll"
            class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 text-green-700"
            title="Can be re-polled automatically"
          >
            <CheckIcon class="w-3 h-3" />
          </span>
        </div>
      </template>

      <template #cell-eni_count="{ item }">
        <StatusBadge variant="blue">
          {{ item.eni_count }}
        </StatusBadge>
      </template>

      <template #cell-last_polled="{ item }">
        <template v-if="item.last_polled">
          <div class="text-xs">
            <div class="text-gray-900">{{ formatDate(item.last_polled) }}</div>
            <div class="text-gray-500">{{ formatTimeAgo(item.last_polled) }}</div>
          </div>
        </template>
        <span v-else class="text-gray-400 text-xs">Never</span>
      </template>

      <template #cell-created_at="{ item }">
        <span class="text-gray-900 text-xs">{{ formatDate(item.created_at) }}</span>
      </template>

      <template #cell-actions="{ item }">
        <div v-if="canPoll" class="flex items-center gap-1">
          <a
            :href="`/accounts/${item.account_id}/edit/`"
            class="text-gray-600 hover:text-gray-800 hover:bg-gray-100 px-2 py-1 rounded transition-colors text-xs"
            title="Edit account settings"
          >
            <PencilIcon class="w-4 h-4" />
          </a>
          <button
            v-if="item.can_repoll"
            @click="handleRepoll(item)"
            :disabled="repollingAccounts.has(item.account_id)"
            class="text-purple-600 hover:text-purple-800 hover:bg-purple-50 px-2 py-1 rounded transition-colors text-xs flex items-center disabled:opacity-50"
            title="Re-poll using instance role"
          >
            <ArrowPathIcon v-if="repollingAccounts.has(item.account_id)" class="w-4 h-4 animate-spin" />
            <ArrowPathIcon v-else class="w-4 h-4 mr-1" />
            <span v-if="!repollingAccounts.has(item.account_id)">Re-poll</span>
          </button>
          <span
            v-else-if="item.auth_method === 'instance_role'"
            class="text-yellow-600 text-xs"
            title="Instance role account not fully configured. Edit to add role name and regions."
          >
            <ExclamationTriangleIcon class="w-4 h-4 inline" />
            Config needed
          </span>
          <button
            v-else
            @click="handlePollWithCredentials(item)"
            class="text-blue-600 hover:text-blue-800 hover:bg-blue-50 px-2 py-1 rounded transition-colors text-xs flex items-center"
            title="Poll with credentials"
          >
            <KeyIcon class="w-4 h-4 mr-1" />
            Poll
          </button>
        </div>
        <span v-else class="text-gray-400 text-xs">
          <LockClosedIcon class="w-4 h-4" />
        </span>
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

    <!-- Empty state actions -->
    <div v-if="!loading && accounts.length === 0 && canPoll" class="mt-6 flex gap-3 justify-center">
      <button
        @click="showPollModal = true"
        class="bg-aws-orange hover:bg-orange-600 text-white px-6 py-3 rounded-lg transition-colors"
      >
        <PlusIcon class="w-5 h-5 inline mr-2" />
        Add Your First Account
      </button>
      <button
        @click="showBulkPollModal = true"
        class="border border-aws-orange text-aws-orange hover:bg-orange-50 px-6 py-3 rounded-lg transition-colors"
      >
        <ServerStackIcon class="w-5 h-5 inline mr-2" />
        Bulk Import
      </button>
    </div>

    <!-- Poll Modal -->
    <PollModal
      :is-open="showPollModal"
      :prefill-account="prefillAccount"
      @close="closePollModal"
      @success="handlePollSuccess"
    />

    <!-- Bulk Poll Modal -->
    <BulkPollModal
      :is-open="showBulkPollModal"
      @close="showBulkPollModal = false"
      @success="handleBulkPollSuccess"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import {
  UserGroupIcon,
  PlusIcon,
  ArrowPathIcon,
  ServerIcon,
  ServerStackIcon,
  InformationCircleIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  CheckIcon,
  PencilIcon,
  KeyIcon,
  LockClosedIcon,
} from '@heroicons/vue/24/outline'
import { accountsApi } from '@/api/accounts'
import type { AWSAccount } from '@/types/accounts'
import type { Column } from '@/components/common/DataTable.vue'

import DataTable from '@/components/common/DataTable.vue'
import StatusBadge from '@/components/common/StatusBadge.vue'
import SummaryCard from '@/components/common/SummaryCard.vue'
import Pagination from '@/components/common/Pagination.vue'
import PollModal from './PollModal.vue'
import BulkPollModal from './BulkPollModal.vue'

// Props
defineProps<{
  canPoll?: boolean
}>()

// State
const accounts = ref<AWSAccount[]>([])
const loading = ref(false)
const error = ref<string | null>(null)
const totalCount = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)
const searchQuery = ref('')
const successMessage = ref<string | null>(null)
const showPollModal = ref(false)
const showBulkPollModal = ref(false)
const prefillAccount = ref<{ account_id: string; account_name: string } | null>(null)
const repollAllLoading = ref(false)
const repollingAccounts = ref<Set<string>>(new Set())

// Computed
const activeCount = computed(() => accounts.value.filter(a => a.is_active).length)
const instanceRoleCount = computed(() => accounts.value.filter(a => a.auth_method === 'instance_role').length)
const totalENIs = computed(() => accounts.value.reduce((sum, a) => sum + a.eni_count, 0))
const totalPages = computed(() => Math.ceil(totalCount.value / pageSize.value))

// Table columns
const columns: Column[] = [
  { key: 'account', label: 'Account' },
  { key: 'status', label: 'Status', width: '100px' },
  { key: 'auth_method', label: 'Auth', width: '150px' },
  { key: 'eni_count', label: 'ENIs', width: '80px' },
  { key: 'last_polled', label: 'Last Polled', width: '140px' },
  { key: 'created_at', label: 'Created', width: '100px' },
  { key: 'actions', label: 'Actions', width: '150px' },
]

// Fetch accounts
async function fetchAccounts() {
  loading.value = true
  error.value = null
  try {
    const filters: Record<string, string | number> = {
      page: currentPage.value,
    }
    if (searchQuery.value) {
      filters.search = searchQuery.value
    }
    const response = await accountsApi.list(filters as any)
    accounts.value = response.results
    totalCount.value = response.count
  } catch (e: any) {
    console.error('Failed to fetch accounts:', e)
    error.value = e.response?.data?.detail || e.message || 'Failed to fetch accounts'
  } finally {
    loading.value = false
  }
}

// Handlers
function handleSearch(query: string) {
  searchQuery.value = query
  currentPage.value = 1
  fetchAccounts()
}

function handlePageChange(page: number) {
  currentPage.value = page
  fetchAccounts()
}

// Handle repoll all
async function handleRepollAll() {
  if (!confirm('Re-poll ALL accounts configured with EC2 instance role authentication?')) {
    return
  }

  repollAllLoading.value = true
  error.value = null
  successMessage.value = null

  try {
    const result = await accountsApi.repollAll()
    successMessage.value = result.message || 'Started re-polling all accounts'
    // Navigate to tasks page to show progress
    setTimeout(() => {
      window.location.href = `/tasks/${result.task_id}/`
    }, 1500)
  } catch (e: any) {
    error.value = e.response?.data?.detail || e.message || 'Failed to start re-polling'
  } finally {
    repollAllLoading.value = false
  }
}

// Handle repoll single account
async function handleRepoll(account: AWSAccount) {
  repollingAccounts.value.add(account.account_id)
  error.value = null
  successMessage.value = null

  try {
    const result = await accountsApi.repoll(account.account_id)
    successMessage.value = `Started re-polling account ${account.account_id}`
    // Navigate to task details
    setTimeout(() => {
      window.location.href = `/tasks/${result.task_id}/`
    }, 1500)
  } catch (e: any) {
    error.value = e.response?.data?.detail || e.message || 'Failed to start re-polling'
  } finally {
    repollingAccounts.value.delete(account.account_id)
  }
}

// Handle poll with credentials
function handlePollWithCredentials(account: AWSAccount) {
  prefillAccount.value = {
    account_id: account.account_id,
    account_name: account.account_name || '',
  }
  showPollModal.value = true
}

// Close poll modal
function closePollModal() {
  showPollModal.value = false
  prefillAccount.value = null
}

// Handle poll success
function handlePollSuccess(taskId: number) {
  successMessage.value = 'Started polling account'
  setTimeout(() => {
    window.location.href = `/tasks/${taskId}/`
  }, 1500)
}

// Handle bulk poll success
function handleBulkPollSuccess(taskId: number) {
  successMessage.value = 'Started bulk polling accounts'
  setTimeout(() => {
    window.location.href = `/tasks/${taskId}/`
  }, 1500)
}

// Utilities
function formatDate(date: string): string {
  return new Date(date).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

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

// Initial load
onMounted(() => {
  fetchAccounts()
})
</script>
