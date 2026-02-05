<template>
  <div class="text-center py-12">
    <component
      v-if="iconComponent"
      :is="iconComponent"
      class="mx-auto h-12 w-12 text-gray-400"
      aria-hidden="true"
    />
    <h3 class="mt-2 text-sm font-medium text-gray-900">{{ title }}</h3>
    <p class="mt-1 text-sm text-gray-500">{{ message }}</p>
    <div v-if="$slots.action" class="mt-6">
      <slot name="action"></slot>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'
import {
  InboxIcon,
  FolderOpenIcon,
  MagnifyingGlassIcon,
  ServerIcon,
  CloudIcon,
  ShieldCheckIcon,
  ClipboardDocumentListIcon,
  SignalIcon,
} from '@heroicons/vue/24/outline'

export type EmptyStateIcon =
  | 'inbox'
  | 'folder'
  | 'search'
  | 'server'
  | 'cloud'
  | 'shield'
  | 'clipboard'
  | 'network'

const props = withDefaults(
  defineProps<{
    title?: string
    message?: string
    icon?: EmptyStateIcon
  }>(),
  {
    title: 'No data',
    message: 'No items found matching your criteria.',
    icon: 'inbox',
  }
)

const iconComponent = computed<Component>(() => {
  const icons: Record<EmptyStateIcon, Component> = {
    inbox: InboxIcon,
    folder: FolderOpenIcon,
    search: MagnifyingGlassIcon,
    server: ServerIcon,
    cloud: CloudIcon,
    shield: ShieldCheckIcon,
    clipboard: ClipboardDocumentListIcon,
    network: SignalIcon,
  }
  return icons[props.icon]
})
</script>
