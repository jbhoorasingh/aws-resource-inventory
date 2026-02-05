<template>
  <div class="bg-white shadow-lg rounded-lg mb-6">
    <div class="bg-gray-50 border-b border-gray-200 px-6 py-4">
      <div class="flex items-center justify-between">
        <h5 class="text-lg font-semibold text-gray-900 flex items-center">
          <FunnelIcon class="w-5 h-5 mr-2 text-aws-orange" />
          Filters
          <span
            v-if="activeFilterCount > 0"
            class="ml-2 px-2 py-0.5 bg-aws-orange text-white text-xs rounded-full"
          >
            {{ activeFilterCount }} active
          </span>
        </h5>
        <button
          v-if="collapsible"
          @click="isCollapsed = !isCollapsed"
          class="text-gray-500 hover:text-gray-700"
        >
          <ChevronDownIcon
            class="h-5 w-5 transition-transform duration-200"
            :class="{ 'rotate-180': !isCollapsed }"
          />
        </button>
      </div>
    </div>

    <Transition
      enter-active-class="transition duration-200 ease-out"
      enter-from-class="opacity-0 -translate-y-2"
      enter-to-class="opacity-100 translate-y-0"
      leave-active-class="transition duration-150 ease-in"
      leave-from-class="opacity-100 translate-y-0"
      leave-to-class="opacity-0 -translate-y-2"
    >
      <div v-show="!isCollapsed" class="p-6">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <slot></slot>

          <!-- Action buttons -->
          <div class="flex items-end gap-2">
            <button
              @click="$emit('apply')"
              class="bg-aws-orange hover:bg-orange-600 text-white px-4 py-2 rounded-lg
                     transition-all duration-200 flex items-center gap-2 text-sm font-medium"
            >
              <MagnifyingGlassIcon class="h-4 w-4" />
              Apply
            </button>
            <button
              @click="$emit('clear')"
              class="bg-gray-200 hover:bg-gray-300 text-gray-800 px-4 py-2 rounded-lg
                     transition-all duration-200 flex items-center gap-2 text-sm font-medium"
            >
              <XMarkIcon class="h-4 w-4" />
              Clear
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import {
  FunnelIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  ChevronDownIcon,
} from '@heroicons/vue/20/solid'

withDefaults(
  defineProps<{
    activeFilterCount?: number
    collapsible?: boolean
  }>(),
  {
    activeFilterCount: 0,
    collapsible: false,
  }
)

defineEmits<{
  (e: 'apply'): void
  (e: 'clear'): void
}>()

const isCollapsed = ref(false)
</script>
