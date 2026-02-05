<template>
  <div class="w-full">
    <div class="flex justify-between text-xs text-gray-600 mb-1">
      <span>{{ task.completed_accounts + task.failed_accounts }} / {{ task.total_accounts }}</span>
      <span>{{ task.progress_percentage.toFixed(0) }}%</span>
    </div>
    <div class="w-full bg-gray-200 rounded-full h-2">
      <div
        class="h-2 rounded-full transition-all duration-300"
        :class="progressClass"
        :style="{ width: `${task.progress_percentage}%` }"
      ></div>
    </div>
    <div v-if="task.failed_accounts > 0" class="text-xs text-red-600 mt-1">
      {{ task.failed_accounts }} failed
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { DiscoveryTask } from '@/types/tasks'

const props = defineProps<{
  task: DiscoveryTask
}>()

const progressClass = computed(() => {
  if (props.task.status === 'failed') return 'bg-red-500'
  if (props.task.failed_accounts > 0) return 'bg-yellow-500'
  return 'bg-aws-orange'
})
</script>
