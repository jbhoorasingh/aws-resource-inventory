<template>
  <TransitionRoot appear :show="isOpen" as="template">
    <Dialog as="div" class="relative z-50" @close="$emit('close')">
      <TransitionChild
        as="template"
        enter="duration-300 ease-out"
        enter-from="opacity-0"
        enter-to="opacity-100"
        leave="duration-200 ease-in"
        leave-from="opacity-100"
        leave-to="opacity-0"
      >
        <div class="fixed inset-0 bg-black bg-opacity-50" />
      </TransitionChild>

      <div class="fixed inset-0 overflow-y-auto">
        <div class="flex min-h-full items-center justify-center p-4">
          <TransitionChild
            as="template"
            enter="duration-300 ease-out"
            enter-from="opacity-0 scale-95"
            enter-to="opacity-100 scale-100"
            leave="duration-200 ease-in"
            leave-from="opacity-100 scale-100"
            leave-to="opacity-0 scale-95"
          >
            <DialogPanel class="w-full max-w-5xl transform overflow-hidden rounded-lg bg-white shadow-xl transition-all">
              <!-- Header -->
              <div class="bg-gradient-to-r from-aws-dark to-aws-light px-6 py-4">
                <div class="flex items-center justify-between">
                  <DialogTitle class="text-lg font-semibold text-white flex items-center">
                    <ServerStackIcon class="w-5 h-5 mr-2" />
                    Bulk Poll Multiple AWS Accounts
                  </DialogTitle>
                  <button @click="$emit('close')" class="text-white hover:text-gray-200">
                    <XMarkIcon class="w-6 h-6" />
                  </button>
                </div>
              </div>

              <!-- Body -->
              <form @submit.prevent="handleSubmit">
                <div class="px-6 py-4">
                  <!-- Info banner -->
                  <div class="bg-blue-50 border-l-4 border-blue-500 p-4 mb-4">
                    <div class="flex">
                      <InformationCircleIcon class="w-5 h-5 text-blue-500 mr-2 flex-shrink-0" />
                      <p class="text-sm text-blue-700">
                        <strong>Bulk Polling with Role Assumption:</strong> Poll multiple accounts using the same identity credentials.
                      </p>
                    </div>
                  </div>

                  <!-- Identity Account Credentials -->
                  <h4 class="text-base font-semibold text-gray-900 mb-2">Identity Account Credentials</h4>
                  <p class="text-sm text-gray-600 mb-4">These credentials will be used to assume roles in all target accounts.</p>

                  <div class="grid grid-cols-3 gap-4 mb-4">
                    <div>
                      <label class="block text-sm font-medium text-gray-700 mb-1">
                        Access Key ID <span class="text-red-500">*</span>
                      </label>
                      <input
                        v-model="form.access_key_id"
                        type="text"
                        required
                        placeholder="AKIA..."
                        class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                      />
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 mb-1">
                        Secret Access Key <span class="text-red-500">*</span>
                      </label>
                      <input
                        v-model="form.secret_access_key"
                        type="password"
                        required
                        placeholder="Your secret key"
                        class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                      />
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 mb-1">
                        Session Token
                      </label>
                      <input
                        v-model="form.session_token"
                        type="password"
                        placeholder="Leave empty if using IAM user"
                        class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                      />
                    </div>
                  </div>

                  <!-- Regions -->
                  <div class="mb-4">
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                      AWS Regions <span class="text-red-500">*</span>
                    </label>
                    <input
                      v-model="form.regions"
                      type="text"
                      required
                      placeholder="us-east-1,us-west-2,eu-west-1"
                      class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                    />
                    <p class="mt-1 text-sm text-gray-500">Comma-separated list of regions (will be used for all accounts)</p>
                  </div>

                  <hr class="my-6 border-gray-200">

                  <!-- Target Accounts Configuration -->
                  <h4 class="text-base font-semibold text-gray-900 mb-2">Target Accounts Configuration</h4>
                  <p class="text-sm text-gray-600 mb-4">
                    Enter one account per line in the format:
                    <code class="bg-gray-100 px-2 py-1 rounded">account_number|account_name|role_arn|external_id</code>
                  </p>

                  <div class="mb-4">
                    <label class="block text-sm font-medium text-gray-700 mb-1">
                      Accounts Configuration <span class="text-red-500">*</span>
                    </label>
                    <textarea
                      v-model="form.accounts_config"
                      rows="10"
                      required
                      placeholder="264449297775|Production Account|arn:aws:iam::264449297775:role/ResourceDiscoveryRole|
123456789012|Dev Account|arn:aws:iam::123456789012:role/ResourceDiscoveryRole|my-external-id
987654444448|Staging Account|arn:aws:iam::987654444448:role/ResourceDiscoveryRole|"
                      class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm font-mono"
                    />
                    <div class="mt-1 text-sm text-gray-500">
                      <strong>Format:</strong> <code class="bg-gray-100 px-2 py-1 rounded">account_number|account_name|role_arn|external_id</code><br>
                      <strong>Note:</strong> External ID is optional (leave empty or omit the last <code class="bg-gray-100 px-1 rounded">|</code> if not needed)
                    </div>
                  </div>

                  <!-- Warning -->
                  <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
                    <div class="flex">
                      <ExclamationTriangleIcon class="w-5 h-5 text-yellow-400 mr-2 flex-shrink-0" />
                      <p class="text-sm text-yellow-700">
                        <strong>Note:</strong> Accounts will be polled sequentially. This may take several minutes for many accounts.
                      </p>
                    </div>
                  </div>

                  <!-- Parsed accounts preview -->
                  <div v-if="parsedAccounts.length > 0" class="mt-4">
                    <h5 class="text-sm font-medium text-gray-700 mb-2">Parsed Accounts ({{ parsedAccounts.length }})</h5>
                    <div class="max-h-32 overflow-y-auto bg-gray-50 rounded p-2">
                      <div v-for="(account, index) in parsedAccounts" :key="index" class="text-xs py-1 border-b border-gray-200 last:border-0">
                        <code class="text-gray-600">{{ account.account_number }}</code>
                        <span v-if="account.account_name" class="text-gray-500 ml-2">{{ account.account_name }}</span>
                      </div>
                    </div>
                  </div>

                  <!-- Error message -->
                  <div v-if="error" class="mt-4 bg-red-50 border-l-4 border-red-500 p-3">
                    <p class="text-sm text-red-700">{{ error }}</p>
                  </div>
                </div>

                <!-- Footer -->
                <div class="bg-gray-50 px-6 py-4 flex justify-end gap-3">
                  <button
                    type="button"
                    @click="$emit('close')"
                    class="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-800 rounded-lg transition-colors text-sm"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    :disabled="submitting || parsedAccounts.length === 0"
                    class="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors text-sm flex items-center disabled:opacity-50"
                  >
                    <ArrowPathIcon v-if="submitting" class="w-4 h-4 mr-2 animate-spin" />
                    <ServerStackIcon v-else class="w-4 h-4 mr-2" />
                    {{ submitting ? 'Starting...' : `Start Bulk Polling (${parsedAccounts.length} accounts)` }}
                  </button>
                </div>
              </form>
            </DialogPanel>
          </TransitionChild>
        </div>
      </div>
    </Dialog>
  </TransitionRoot>
</template>

<script setup lang="ts">
import { ref, reactive, computed, watch } from 'vue'
import {
  Dialog,
  DialogPanel,
  DialogTitle,
  TransitionRoot,
  TransitionChild,
} from '@headlessui/vue'
import {
  XMarkIcon,
  ArrowPathIcon,
  ServerStackIcon,
  InformationCircleIcon,
  ExclamationTriangleIcon,
} from '@heroicons/vue/24/outline'
import { tasksApi } from '@/api/tasks'

const props = defineProps<{
  isOpen: boolean
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'success', taskId: number): void
}>()

const submitting = ref(false)
const error = ref<string | null>(null)

const form = reactive({
  access_key_id: '',
  secret_access_key: '',
  session_token: '',
  regions: 'us-east-1,us-west-2',
  accounts_config: '',
})

// Parse accounts from textarea
const parsedAccounts = computed(() => {
  if (!form.accounts_config.trim()) return []

  const accounts: { account_number: string; account_name: string; role_arn: string; external_id: string }[] = []
  const lines = form.accounts_config.split('\n')

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue

    const parts = trimmed.split('|')
    if (parts.length >= 3) {
      accounts.push({
        account_number: parts[0].trim(),
        account_name: parts[1]?.trim() || '',
        role_arn: parts[2]?.trim() || '',
        external_id: parts[3]?.trim() || '',
      })
    }
  }

  return accounts
})

// Reset form when modal closes
watch(() => props.isOpen, (isOpen) => {
  if (!isOpen) {
    error.value = null
    form.access_key_id = ''
    form.secret_access_key = ''
    form.session_token = ''
    form.accounts_config = ''
  }
})

async function handleSubmit() {
  if (parsedAccounts.value.length === 0) {
    error.value = 'Please enter at least one account configuration'
    return
  }

  submitting.value = true
  error.value = null

  try {
    const regions = form.regions.split(',').map(r => r.trim()).filter(Boolean)

    const task = await tasksApi.bulkTrigger({
      access_key_id: form.access_key_id,
      secret_access_key: form.secret_access_key,
      session_token: form.session_token || undefined,
      regions,
      accounts: parsedAccounts.value.map(a => ({
        account_number: a.account_number,
        account_name: a.account_name || undefined,
        role_arn: a.role_arn || undefined,
        external_id: a.external_id || undefined,
      })),
    })

    emit('success', task.id)
    emit('close')
  } catch (e: any) {
    error.value = e.response?.data?.detail || e.response?.data?.error || e.message || 'Failed to start bulk polling'
  } finally {
    submitting.value = false
  }
}
</script>
