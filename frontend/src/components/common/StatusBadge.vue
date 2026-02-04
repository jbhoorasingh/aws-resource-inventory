<template>
  <span
    class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
    :class="variantClass"
  >
    <component
      v-if="icon"
      :is="iconComponent"
      class="mr-1 h-3.5 w-3.5"
      aria-hidden="true"
    />
    <slot></slot>
  </span>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'
import {
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  ArrowPathIcon,
  ExclamationCircleIcon,
  MinusCircleIcon,
  ServerIcon,
  StopIcon,
  LockClosedIcon,
  GlobeAltIcon,
  StarIcon,
  KeyIcon,
} from '@heroicons/vue/20/solid'

export type BadgeVariant =
  | 'green'
  | 'red'
  | 'yellow'
  | 'blue'
  | 'gray'
  | 'purple'
  | 'orange'

export type BadgeIcon =
  | 'check'
  | 'x'
  | 'clock'
  | 'refresh'
  | 'exclamation'
  | 'minus'
  | 'server'
  | 'stop'
  | 'lock'
  | 'globe'
  | 'star'
  | 'key'

const props = withDefaults(
  defineProps<{
    variant?: BadgeVariant
    icon?: BadgeIcon
  }>(),
  {
    variant: 'gray',
  }
)

const variantClass = computed(() => {
  const variants: Record<BadgeVariant, string> = {
    green: 'bg-green-100 text-green-800',
    red: 'bg-red-100 text-red-800',
    yellow: 'bg-yellow-100 text-yellow-800',
    blue: 'bg-blue-100 text-blue-800',
    gray: 'bg-gray-100 text-gray-800',
    purple: 'bg-purple-100 text-purple-800',
    orange: 'bg-orange-100 text-orange-800',
  }
  return variants[props.variant]
})

const iconComponent = computed<Component | null>(() => {
  if (!props.icon) return null

  const icons: Record<BadgeIcon, Component> = {
    check: CheckCircleIcon,
    x: XCircleIcon,
    clock: ClockIcon,
    refresh: ArrowPathIcon,
    exclamation: ExclamationCircleIcon,
    minus: MinusCircleIcon,
    server: ServerIcon,
    stop: StopIcon,
    lock: LockClosedIcon,
    globe: GlobeAltIcon,
    star: StarIcon,
    key: KeyIcon,
  }
  return icons[props.icon]
})
</script>
