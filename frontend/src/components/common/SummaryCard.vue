<template>
  <div class="bg-white rounded-lg shadow-md p-4 border-l-4" :class="borderClass">
    <div class="flex items-center justify-between">
      <div>
        <p class="text-sm font-medium text-gray-500">{{ label }}</p>
        <p class="text-2xl font-bold" :class="textClass">
          {{ formattedValue }}
        </p>
      </div>
      <div
        v-if="icon"
        class="p-3 rounded-full"
        :class="bgClass"
      >
        <component
          :is="iconComponent"
          class="h-6 w-6"
          :class="iconClass"
          aria-hidden="true"
        />
      </div>
    </div>
    <p v-if="subtitle" class="mt-1 text-xs text-gray-500">{{ subtitle }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'
import {
  ServerIcon,
  CloudIcon,
  ShieldCheckIcon,
  GlobeAltIcon,
  CheckCircleIcon,
  XCircleIcon,
  ClockIcon,
  PlayIcon,
  StopIcon,
  UserGroupIcon,
  SignalIcon,
  LockClosedIcon,
  ClipboardDocumentListIcon,
  Squares2X2Icon,
  ArrowDownIcon,
  ArrowUpIcon,
} from '@heroicons/vue/24/outline'

export type CardColor = 'gray' | 'green' | 'red' | 'yellow' | 'blue' | 'purple' | 'orange'
export type CardIcon =
  | 'server'
  | 'cloud'
  | 'shield'
  | 'globe'
  | 'check'
  | 'x'
  | 'clock'
  | 'play'
  | 'stop'
  | 'users'
  | 'network'
  | 'lock'
  | 'clipboard'
  | 'layer'
  | 'arrow-down'
  | 'arrow-up'

const props = withDefaults(
  defineProps<{
    label: string
    value: number | string
    color?: CardColor
    icon?: CardIcon
    subtitle?: string
  }>(),
  {
    color: 'gray',
  }
)

const formattedValue = computed(() => {
  if (typeof props.value === 'number') {
    return props.value.toLocaleString()
  }
  return props.value
})

const borderClass = computed(() => {
  const colors: Record<CardColor, string> = {
    gray: 'border-gray-500',
    green: 'border-green-500',
    red: 'border-red-500',
    yellow: 'border-yellow-500',
    blue: 'border-blue-500',
    purple: 'border-purple-500',
    orange: 'border-aws-orange',
  }
  return colors[props.color]
})

const textClass = computed(() => {
  const colors: Record<CardColor, string> = {
    gray: 'text-gray-900',
    green: 'text-green-600',
    red: 'text-red-600',
    yellow: 'text-yellow-600',
    blue: 'text-blue-600',
    purple: 'text-purple-600',
    orange: 'text-aws-orange',
  }
  return colors[props.color]
})

const bgClass = computed(() => {
  const colors: Record<CardColor, string> = {
    gray: 'bg-gray-100',
    green: 'bg-green-100',
    red: 'bg-red-100',
    yellow: 'bg-yellow-100',
    blue: 'bg-blue-100',
    purple: 'bg-purple-100',
    orange: 'bg-orange-100',
  }
  return colors[props.color]
})

const iconClass = computed(() => {
  const colors: Record<CardColor, string> = {
    gray: 'text-gray-600',
    green: 'text-green-600',
    red: 'text-red-600',
    yellow: 'text-yellow-600',
    blue: 'text-blue-600',
    purple: 'text-purple-600',
    orange: 'text-aws-orange',
  }
  return colors[props.color]
})

const iconComponent = computed<Component | null>(() => {
  if (!props.icon) return null

  const icons: Record<CardIcon, Component> = {
    server: ServerIcon,
    cloud: CloudIcon,
    shield: ShieldCheckIcon,
    globe: GlobeAltIcon,
    check: CheckCircleIcon,
    x: XCircleIcon,
    clock: ClockIcon,
    play: PlayIcon,
    stop: StopIcon,
    users: UserGroupIcon,
    network: SignalIcon,
    lock: LockClosedIcon,
    clipboard: ClipboardDocumentListIcon,
    layer: Squares2X2Icon,
    'arrow-down': ArrowDownIcon,
    'arrow-up': ArrowUpIcon,
  }
  return icons[props.icon]
})
</script>
