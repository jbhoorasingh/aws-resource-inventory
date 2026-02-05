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
            <DialogPanel class="w-full max-w-4xl transform overflow-hidden rounded-lg bg-white shadow-xl transition-all">
              <!-- Header -->
              <div class="bg-gradient-to-r from-aws-dark to-aws-light px-6 py-4">
                <div class="flex items-center justify-between">
                  <DialogTitle class="text-lg font-semibold text-white flex items-center">
                    <ArrowPathIcon class="w-5 h-5 mr-2" />
                    Poll AWS Account
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
                        You can use direct credentials OR role assumption for cross-account access.
                      </p>
                    </div>
                  </div>

                  <!-- Auth method tabs -->
                  <div class="border-b border-gray-200 mb-4">
                    <nav class="flex -mb-px">
                      <button
                        type="button"
                        @click="authMethod = 'direct'"
                        :class="[
                          'py-2 px-4 border-b-2 font-medium text-sm',
                          authMethod === 'direct'
                            ? 'border-aws-orange text-aws-orange'
                            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                        ]"
                      >
                        <KeyIcon class="w-4 h-4 inline mr-1" />
                        Direct Credentials
                      </button>
                      <button
                        type="button"
                        @click="authMethod = 'role'"
                        :class="[
                          'py-2 px-4 border-b-2 font-medium text-sm',
                          authMethod === 'role'
                            ? 'border-aws-orange text-aws-orange'
                            : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                        ]"
                      >
                        <ShieldCheckIcon class="w-4 h-4 inline mr-1" />
                        Role Assumption
                      </button>
                    </nav>
                  </div>

                  <!-- Account info -->
                  <div class="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <label class="block text-sm font-medium text-gray-700 mb-1">
                        Account Number <span class="text-red-500">*</span>
                      </label>
                      <input
                        v-model="form.account_number"
                        type="text"
                        required
                        placeholder="123456789012"
                        class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                      />
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-gray-700 mb-1">
                        Account Name (Optional)
                      </label>
                      <input
                        v-model="form.account_name"
                        type="text"
                        placeholder="Production Account"
                        class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                      />
                    </div>
                  </div>

                  <!-- Credentials -->
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
                        placeholder="Optional"
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
                    <p class="mt-1 text-sm text-gray-500">Comma-separated list of regions to scan</p>
                  </div>

                  <!-- Role assumption fields -->
                  <div v-if="authMethod === 'role'" class="border-t border-gray-200 pt-4 mt-4">
                    <h4 class="text-sm font-semibold text-gray-900 mb-3 flex items-center">
                      <ShieldCheckIcon class="w-4 h-4 mr-2 text-aws-orange" />
                      Role Assumption Configuration
                    </h4>
                    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-3 mb-4">
                      <p class="text-sm text-yellow-700">
                        Use these fields to assume a role in the target account.
                      </p>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                      <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Role ARN</label>
                        <input
                          v-model="form.role_arn"
                          type="text"
                          placeholder="arn:aws:iam::123456789012:role/DiscoveryRole"
                          class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                        />
                      </div>
                      <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">External ID (Optional)</label>
                        <input
                          v-model="form.external_id"
                          type="text"
                          placeholder="my-external-id"
                          class="block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-aws-orange focus:border-aws-orange text-sm"
                        />
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
                    :disabled="submitting"
                    class="px-4 py-2 bg-aws-orange hover:bg-orange-600 text-white rounded-lg transition-colors text-sm flex items-center disabled:opacity-50"
                  >
                    <ArrowPathIcon v-if="submitting" class="w-4 h-4 mr-2 animate-spin" />
                    <ArrowPathIcon v-else class="w-4 h-4 mr-2" />
                    {{ submitting ? 'Starting...' : 'Start Polling' }}
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
import { ref, reactive, watch } from 'vue'
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
  KeyIcon,
  ShieldCheckIcon,
  InformationCircleIcon,
} from '@heroicons/vue/24/outline'
import { tasksApi } from '@/api/tasks'

const props = defineProps<{
  isOpen: boolean
  prefillAccount?: { account_id: string; account_name: string } | null
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'success', taskId: number): void
}>()

const authMethod = ref<'direct' | 'role'>('direct')
const submitting = ref(false)
const error = ref<string | null>(null)

const form = reactive({
  account_number: '',
  account_name: '',
  access_key_id: '',
  secret_access_key: '',
  session_token: '',
  regions: 'us-east-1,us-west-2',
  role_arn: '',
  external_id: '',
})

// Prefill account info when modal opens
watch(() => props.prefillAccount, (account) => {
  if (account) {
    form.account_number = account.account_id
    form.account_name = account.account_name || ''
  }
}, { immediate: true })

// Reset form when modal closes
watch(() => props.isOpen, (isOpen) => {
  if (!isOpen) {
    error.value = null
    if (!props.prefillAccount) {
      form.account_number = ''
      form.account_name = ''
    }
    form.access_key_id = ''
    form.secret_access_key = ''
    form.session_token = ''
    form.role_arn = ''
    form.external_id = ''
  }
})

async function handleSubmit() {
  submitting.value = true
  error.value = null

  try {
    const regions = form.regions.split(',').map(r => r.trim()).filter(Boolean)

    const task = await tasksApi.trigger({
      account_number: form.account_number,
      account_name: form.account_name,
      access_key_id: form.access_key_id,
      secret_access_key: form.secret_access_key,
      session_token: form.session_token,
      regions,
      role_arn: authMethod.value === 'role' ? form.role_arn : undefined,
      external_id: authMethod.value === 'role' ? form.external_id : undefined,
    })

    emit('success', task.id)
    emit('close')
  } catch (e: any) {
    error.value = e.response?.data?.detail || e.response?.data?.error || e.message || 'Failed to start polling'
  } finally {
    submitting.value = false
  }
}
</script>
