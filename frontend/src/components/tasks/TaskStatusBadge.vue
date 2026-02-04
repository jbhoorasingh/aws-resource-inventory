<template>
  <StatusBadge :variant="variant" :icon="icon">
    {{ label }}
  </StatusBadge>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import StatusBadge, { type BadgeVariant, type BadgeIcon } from '@/components/common/StatusBadge.vue'
import type { TaskStatus } from '@/types/tasks'

const props = defineProps<{
  status: TaskStatus
}>()

const variant = computed<BadgeVariant>(() => {
  const variants: Record<TaskStatus, BadgeVariant> = {
    pending: 'yellow',
    running: 'blue',
    success: 'green',
    failed: 'red',
    cancelled: 'gray',
  }
  return variants[props.status]
})

const icon = computed<BadgeIcon>(() => {
  const icons: Record<TaskStatus, BadgeIcon> = {
    pending: 'clock',
    running: 'refresh',
    success: 'check',
    failed: 'x',
    cancelled: 'stop',
  }
  return icons[props.status]
})

const label = computed(() => {
  const labels: Record<TaskStatus, string> = {
    pending: 'Pending',
    running: 'Running',
    success: 'Success',
    failed: 'Failed',
    cancelled: 'Cancelled',
  }
  return labels[props.status]
})
</script>
