<template>
  <div class="flex items-center justify-center" :class="containerClass">
    <div
      class="animate-spin rounded-full border-b-2 border-aws-orange"
      :class="sizeClass"
    ></div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    size?: 'small' | 'medium' | 'large'
    inline?: boolean
  }>(),
  {
    size: 'medium',
    inline: false,
  }
)

const sizeClass = computed(() => {
  switch (props.size) {
    case 'small':
      return 'h-4 w-4'
    case 'large':
      return 'h-12 w-12'
    default:
      return 'h-8 w-8'
  }
})

const containerClass = computed(() => {
  return props.inline ? 'inline-flex' : ''
})
</script>
