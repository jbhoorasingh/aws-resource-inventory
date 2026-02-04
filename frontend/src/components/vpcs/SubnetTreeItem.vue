<template>
  <div class="border border-gray-200 rounded-lg my-2 overflow-hidden">
    <!-- Subnet Header -->
    <div
      class="bg-green-50 px-4 py-2 cursor-pointer hover:bg-green-100 transition-colors"
      @click="expanded = !expanded"
    >
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-3">
          <button class="text-green-600 hover:text-green-800 focus:outline-none" type="button">
            <ChevronDownIcon v-if="expanded" class="w-4 h-4" />
            <ChevronRightIcon v-else class="w-4 h-4" />
          </button>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <Squares2X2Icon class="w-4 h-4 text-green-600" />
              <span class="font-semibold text-gray-900 text-sm">{{ subnet.subnet_id }}</span>
              <code class="bg-green-100 px-2 py-0.5 rounded text-xs">{{ subnet.cidr_block }}</code>
              <StatusBadge variant="gray" class="text-xs">{{ subnet.availability_zone }}</StatusBadge>
              <StatusBadge variant="green" class="text-xs">{{ subnet.state }}</StatusBadge>
            </div>
            <div v-if="subnet.name" class="text-xs text-gray-500 mt-0.5">
              {{ subnet.name }}
            </div>
          </div>
        </div>
        <div class="flex gap-2 text-xs">
          <span class="px-2 py-1 bg-white rounded border border-gray-200">
            <SignalIcon class="w-3 h-3 inline text-indigo-600" />
            {{ subnet.resource_counts?.eni_count || subnet.enis?.length || 0 }}
          </span>
          <span class="px-2 py-1 bg-white rounded border border-gray-200">
            <ServerIcon class="w-3 h-3 inline text-purple-600" />
            {{ subnet.resource_counts?.ec2_instance_count || 0 }}
          </span>
        </div>
      </div>
    </div>

    <!-- Subnet Content (ENIs) -->
    <div v-if="expanded && subnet.enis?.length > 0" class="border-t border-gray-200 bg-gray-50 p-3">
      <div class="text-xs font-medium text-gray-700 mb-2">ENIs in this subnet:</div>
      <div class="space-y-2">
        <div
          v-for="eni in subnet.enis"
          :key="eni.id"
          class="bg-white border border-gray-200 rounded p-2"
        >
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2 flex-wrap">
              <a
                :href="`/enis/${eni.eni_id}/`"
                class="text-blue-600 hover:text-blue-800 font-medium text-xs"
              >
                {{ eni.eni_id }}
              </a>
              <StatusBadge :variant="eni.status === 'in-use' ? 'green' : 'yellow'" class="text-xs">
                {{ eni.status }}
              </StatusBadge>
              <StatusBadge variant="gray" class="text-xs">
                {{ eni.interface_type }}
              </StatusBadge>
            </div>
            <div class="flex gap-2">
              <StatusBadge variant="blue" icon="lock" class="text-xs">
                {{ eni.private_ip_address }}
              </StatusBadge>
              <StatusBadge v-if="eni.public_ip_address" variant="green" icon="globe" class="text-xs">
                {{ eni.public_ip_address }}
              </StatusBadge>
            </div>
          </div>
          <div v-if="eni.attached_resource_id" class="text-xs text-gray-500 mt-1">
            Attached: <code class="bg-gray-100 px-1 rounded">{{ eni.attached_resource_id }}</code>
            ({{ eni.attached_resource_type }})
          </div>
          <div v-if="eni.security_groups?.length > 0" class="mt-1 flex gap-1 flex-wrap">
            <span
              v-for="sg in eni.security_groups.slice(0, 3)"
              :key="sg.id"
              class="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-indigo-100 text-indigo-800"
              :title="sg.security_group_id"
            >
              {{ truncate(sg.security_group_name, 15) }}
            </span>
            <span
              v-if="eni.security_groups.length > 3"
              class="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-200 text-gray-700"
            >
              +{{ eni.security_groups.length - 3 }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- Empty ENIs message -->
    <div v-else-if="expanded" class="border-t border-gray-200 bg-gray-50 p-3">
      <p class="text-gray-500 text-xs">No ENIs in this subnet</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import {
  ChevronDownIcon,
  ChevronRightIcon,
  Squares2X2Icon,
  SignalIcon,
  ServerIcon,
} from '@heroicons/vue/24/outline'
import type { SubnetWithResources } from '@/types/vpcs'
import StatusBadge from '@/components/common/StatusBadge.vue'

defineProps<{
  subnet: SubnetWithResources
}>()

const expanded = ref(false)

function truncate(str: string | null, maxLength: number): string {
  if (!str) return ''
  return str.length > maxLength ? str.substring(0, maxLength) + '...' : str
}
</script>
