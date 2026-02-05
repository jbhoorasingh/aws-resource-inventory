<template>
  <div class="border border-gray-300 rounded-lg overflow-hidden">
    <!-- VPC Header -->
    <div
      class="bg-blue-50 px-4 py-3 cursor-pointer hover:bg-blue-100 transition-colors"
      @click="$emit('toggle', vpc.id)"
    >
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-4">
          <button class="text-blue-600 hover:text-blue-800 focus:outline-none" type="button">
            <ChevronDownIcon v-if="expanded" class="w-5 h-5" />
            <ChevronRightIcon v-else class="w-5 h-5" />
          </button>
          <div>
            <div class="flex items-center gap-2 flex-wrap">
              <CloudIcon class="w-5 h-5 text-blue-600" />
              <span class="font-bold text-gray-900">{{ vpc.vpc_id }}</span>
              <code class="bg-blue-100 px-2 py-0.5 rounded text-xs">{{ vpc.cidr_block }}</code>
              <StatusBadge variant="gray">{{ vpc.region }}</StatusBadge>
              <StatusBadge variant="green">{{ vpc.state }}</StatusBadge>
              <StatusBadge v-if="vpc.is_default" variant="yellow" icon="star">
                Default
              </StatusBadge>
            </div>
            <div class="text-xs text-gray-500 mt-1">
              Account: <code class="bg-gray-100 px-1 py-0.5 rounded">{{ vpc.owner_account }}</code>
              &bull; Subnets: {{ vpc.subnets?.length || 0 }}
            </div>
          </div>
        </div>
        <div class="flex gap-2 text-xs">
          <span class="px-2 py-1 bg-white rounded border border-gray-200">
            <Squares2X2Icon class="w-4 h-4 inline text-green-600" />
            {{ vpc.resource_counts?.subnet_count || 0 }}
          </span>
          <span class="px-2 py-1 bg-white rounded border border-gray-200">
            <SignalIcon class="w-4 h-4 inline text-indigo-600" />
            {{ vpc.resource_counts?.eni_count || 0 }}
          </span>
          <span class="px-2 py-1 bg-white rounded border border-gray-200">
            <ServerIcon class="w-4 h-4 inline text-purple-600" />
            {{ vpc.resource_counts?.ec2_instance_count || 0 }}
          </span>
        </div>
      </div>
    </div>

    <!-- VPC Content (Subnets) -->
    <div v-if="expanded && vpc.subnets?.length > 0" class="border-t border-gray-200">
      <div class="ml-8 py-2">
        <SubnetTreeItem
          v-for="subnet in vpc.subnets"
          :key="subnet.id"
          :subnet="subnet"
        />
      </div>
    </div>

    <!-- Empty subnets message -->
    <div v-else-if="expanded" class="border-t border-gray-200 p-4 ml-8">
      <p class="text-gray-500 text-sm">No subnets in this VPC</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import {
  ChevronDownIcon,
  ChevronRightIcon,
  CloudIcon,
  Squares2X2Icon,
  SignalIcon,
  ServerIcon,
} from '@heroicons/vue/24/outline'
import type { VPCWithResources } from '@/types/vpcs'
import StatusBadge from '@/components/common/StatusBadge.vue'
import SubnetTreeItem from './SubnetTreeItem.vue'

defineProps<{
  vpc: VPCWithResources
  expanded: boolean
}>()

defineEmits<{
  (e: 'toggle', vpcId: number): void
}>()
</script>
